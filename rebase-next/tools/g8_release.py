#!/usr/bin/env python3
"""Extracted-release checks using only the selected payload and host prerequisites.

All scenario helpers run in isolated Python subprocesses with the extracted
tools directory explicitly selected. This module itself uses only the standard
library, so a coordinator can compose run_release without importing a checkout
client, oracle or fixture into the extracted workflows.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid


MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
BOOTSTRAP = """import json, pathlib, runpy, sys
root = pathlib.Path(sys.argv[1]).resolve()
action = sys.argv[2]
sys.path.insert(0, str(root / 'tools'))
if action == 'check-bundle':
    import package
    print(json.dumps(package.check_bundle(root)))
elif action == 'checksum-controls':
    import g8_release
    print(json.dumps(g8_release.checksum_controls(root, pathlib.Path(sys.argv[3]))))
else:
    sys.argv = [str(root / 'tools' / action), *sys.argv[3:]]
    runpy.run_path(sys.argv[0], run_name='__main__')
"""


class Incomplete(RuntimeError):
    """An extracted obligation or its bounded evidence did not complete."""


def read_json(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise Incomplete("required release JSON is missing or exceeds its byte budget")
    return json.loads(path.read_bytes())


def write_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
        output.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def isolated_command(bundle, action, *args):
    """Only fixed, trusted extracted entry points can be launched."""
    if action not in ("check-bundle", "checksum-controls", "g8.py", "g7_http.py", "g8_release.py"):
        raise ValueError("unknown extracted release entry point")
    bundle = Path(bundle).resolve(strict=True)
    return [sys.executable, "-I", "-B", "-c", BOOTSTRAP, str(bundle), action, *map(str, args)]


def runtime_environment(native_library_path=None):
    """Ignore ambient Python imports and select the native library path explicitly."""
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "LD_LIBRARY_PATH"):
        environment.pop(name, None)
    if native_library_path is not None:
        path = Path(native_library_path).resolve(strict=True)
        if not path.is_dir() or not any(path.glob("libfdb_c.so*")):
            raise ValueError("native library path must contain compatible libfdb_c")
        environment["LD_LIBRARY_PATH"] = str(path)
    return environment


def outside_git(path):
    path = Path(path).resolve()
    return not any((parent / ".git").exists() for parent in (path, *path.parents))


def process_group_members(group):
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
            if fields[0] != "Z" and int(fields[2]) == group:
                members.append(int(entry.name))
        except (OSError, ValueError, IndexError):
            continue
    return members


def stop_group(process):
    # Every child below is started in its own session. Borrowed FDB infrastructure
    # is not in that group and is never signalled by this extracted runner.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process_group_members(process.pid):
        time.sleep(.05)
    if process_group_members(process.pid):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def run_command(arguments, bundle, directory, label, environment, *, timeout=120):
    """Bound logs, deadlines and the complete owned subprocess group."""
    output_path, error_path = directory / f"{label}.stdout", directory / f"{label}.stderr"
    started = time.monotonic()
    process = None
    try:
        with os.fdopen(os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            with os.fdopen(os.open(error_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as error:
                process = subprocess.Popen(arguments, cwd=bundle, env=environment, stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=error, start_new_session=True)
                while process.poll() is None:
                    if time.monotonic() - started > timeout:
                        raise Incomplete(f"{label} exceeded its declared {timeout}-second deadline")
                    if output_path.stat().st_size + error_path.stat().st_size > MAX_LOG_BYTES:
                        raise Incomplete(f"{label} exhausted its required log byte budget")
                    time.sleep(.05)
        if output_path.stat().st_size + error_path.stat().st_size > MAX_LOG_BYTES:
            raise Incomplete(f"{label} exhausted its required log byte budget")
        if process_group_members(process.pid):
            raise Incomplete(f"{label} left an owned worker or server running")
        return {"returncode": process.returncode, "elapsed_seconds": round(time.monotonic() - started, 3),
                "stdout": output_path.read_bytes(), "stderr": error_path.read_bytes(),
                "logs": [output_path.name, error_path.name], "owned_group_drained": True}
    finally:
        if process is not None and (process.poll() is None or process_group_members(process.pid)):
            stop_group(process)


def require_success(observation, label):
    if observation["returncode"] == 2:
        raise Incomplete(f"{label} reported incomplete; inspect its private command logs")
    if observation["returncode"] != 0:
        raise RuntimeError(f"{label} failed; inspect its private command logs")


def rejection(observation, label, diagnostic=None):
    if observation["returncode"] == 0 or diagnostic and diagnostic.encode().lower() not in observation["stderr"].lower():
        raise RuntimeError(f"{label} did not give the expected clear rejection; inspect private command logs")
    return {"status": "passed", "returncode": observation["returncode"],
            "diagnostic_sha256": hashlib.sha256(observation["stderr"]).hexdigest(),
            "logs": observation["logs"], "owned_group_drained": observation["owned_group_drained"]}


def artifact_usage(directory):
    count, size = 0, 0
    for path in directory.rglob("*"):
        count += 1
        if count > 65536:
            raise Incomplete("release artifact inventory exceeds its declared 65,536-entry observation budget")
        if path.is_file():
            size += path.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise Incomplete("release evidence exhausted its declared 128 MiB artifact budget")
    return {"status": "passed", "bytes": size, "budget_bytes": MAX_ARTIFACT_BYTES}


def publish_result(directory, result):
    """Account for the complete final report before accepting its publication."""
    result["artifacts"] = {"status": "incomplete", "budget_bytes": MAX_ARTIFACT_BYTES}
    summary = "\n".join([
        "# Extracted current release", "", f"Status: {result['status']}.",
        f"Source {result['source_commit']}; features {','.join(result['features']) or 'default redb'}.",
        "", *[f"- {name}: equipment smoke, secured recovery, configuration and template passed."
                  for name in result["supported_backends"]],
        "", "Only the recorded short profiles and fault boundaries are accepted here.", ""]).encode()
    usage = artifact_usage(directory)
    existing = sum(path.stat().st_size for path in
                   (directory / "result.json", directory / "summary.md") if path.is_file())
    base = usage["bytes"] - existing
    total = base + len(summary)
    # The serialized total includes its own decimal digits. A few bounded
    # passes reach the exact byte count without publishing an optimistic total.
    for _ in range(8):
        result["artifacts"] = {"status": "passed", "bytes": total, "budget_bytes": MAX_ARTIFACT_BYTES}
        encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        required = base + len(summary) + len(encoded)
        if len(encoded) > MAX_JSON_BYTES or required > MAX_ARTIFACT_BYTES:
            result["artifacts"] = {"status": "incomplete", "required_bytes": required,
                                   "budget_bytes": MAX_ARTIFACT_BYTES}
            raise Incomplete("final result and summary exhaust the declared release evidence byte budget")
        if required == total:
            break
        total = required
    else:
        result["artifacts"]["status"] = "incomplete"
        raise Incomplete("final release evidence byte accounting did not converge")
    write_json(directory / "result.json", result)
    with os.fdopen(os.open(directory / "summary.md", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as output:
        output.write(summary)
    try:
        final = artifact_usage(directory)
    except Incomplete:
        result["artifacts"]["status"] = "incomplete"
        raise
    if final != result["artifacts"]:
        result["artifacts"]["status"] = "incomplete"
        raise Incomplete("final release artifact inventory changed during publication")
    return final


def checksum_controls(bundle, directory):
    """Use real extracted bytes to test changed/missing payload rejection."""
    import package  # Explicit extracted tools path is selected by BOOTSTRAP.
    directory.mkdir(mode=0o700)
    (directory / "bin").mkdir()
    (directory / "tools").mkdir()
    for name in ("bin/rebase-next", "BUNDLE.json", "tools/client.py"):
        shutil.copyfile(bundle / name, directory / name)
    entries = {name: package.digest(directory / name) for name in
               ("bin/rebase-next", "BUNDLE.json", "tools/client.py")}
    (directory / "SHA256SUMS").write_text("".join(f"{checksum}  {name}\n" for name, checksum in entries.items()))
    package.verify_checksums(directory)
    target = directory / "tools/client.py"
    with target.open("ab") as output:
        output.write(b"\n# injected checksum control\n")
    try:
        package.verify_checksums(directory)
    except RuntimeError as error:
        if "checksum differs" not in str(error):
            raise
    else:
        raise RuntimeError("changed extracted payload was accepted")
    target.unlink()
    try:
        package.verify_checksums(directory)
    except RuntimeError as error:
        if "missing or nonregular" not in str(error):
            raise
    else:
        raise RuntimeError("missing extracted payload was accepted")
    return {"status": "passed", "changed_payload_rejected": True, "missing_payload_rejected": True,
            "baseline_real_bytes_verified": True}


def template_selector(bundle, backend):
    names = {"redb": "rebase-next.service", "surrealkv": "rebase-next-surreal.service",
             "foundationdb": "rebase-next-foundationdb.service"}
    path = bundle / "deploy" / names[backend]
    lines = [line.split("=", 1)[1] for line in path.read_text().splitlines() if line.startswith("ExecStart=")]
    if len(lines) != 1:
        raise ValueError("template must have one ordinary ExecStart")
    arguments = shlex.split(lines[0])
    if arguments[0] != "/usr/local/bin/rebase-next" or "serve" not in arguments or "--config" not in arguments:
        raise ValueError("template does not select the ordinary server command")
    selected = "redb" if "--backend" not in arguments else arguments[arguments.index("--backend") + 1]
    model = "calculation" if "--model" not in arguments else arguments[arguments.index("--model") + 1]
    if selected != backend or model not in ("calculation", "equipment"):
        raise ValueError("template backend/model does not match its declared representative workflow")
    if backend == "foundationdb" and ("--cluster-file" not in arguments
            or "Environment=LD_LIBRARY_PATH=" not in path.read_text()):
        raise ValueError("FoundationDB template must identify cluster and native library prerequisites")
    return model


def probe_template(bundle, directory, backend, cluster_file=None):
    """Actual template identity/config with one secured mutation and exact replay."""
    import client
    from harness import Backend, backup_image, command, require, write_private
    model = template_selector(bundle, backend)
    directory.mkdir(mode=0o700)
    prefix = [str(bundle / "bin/rebase-next"), "--backend", backend]
    if cluster_file:
        prefix += ["--cluster-file", str(cluster_file)]
    wrapper = directory / "selected-backend"
    write_private(wrapper, ("#!/bin/sh\nexec " + shlex.join(prefix) + ' "$@"\n').encode())
    wrapper.chmod(0o700)
    owned = None
    try:
        owned = Backend(wrapper, directory / "backend", model=model)
        config = read_json(bundle / "deploy/server.example.json")
        config["listen"] = "127.0.0.1:0"
        config["identity"]["public_keys"] = {"main": owned.config["identity"]["public_keys"]["harness"]}
        owned.config = config
        owned.config_path.write_bytes(client._bytes(config))
        request = read_json(owned.directory / "token-request.json")
        request["key_id"] = "main"
        (owned.directory / "token-request.json").write_bytes(client._bytes(request))
        owned.token = command(owned.binary, "auth", "issue", owned.config_path,
                              owned.directory / "token-request.json", owned.private).decode().strip()
        owned.token_path.write_text(owned.token + "\n")
        owned.start()
        catalog = owned.call("model.describe", {})
        session = owned.call("session.describe", {})
        require(catalog["model"] == session["model"], "template authenticated DB identity differs")
        identity = str(uuid.uuid4())
        fields, code = ({"at": "0"}, 7) if model == "calculation" else ({"unit": 7}, 101)
        plan = owned.plan({"model": catalog["model"], "commands": [
            {"op": "create", "id": identity, "contract": code, "fields": fields}], "returning": []}, "template")
        response = client.execute(owned.url, owned.token, plan)
        require(response["status"] == "committed", "template secured mutation did not commit")
        record = owned.call("records.get", {"model": catalog["model"], "id": identity})
        require(record["input"] == fields, "template authored input differs")
        replay = client.execute(owned.url, owned.token, plan)
        require(replay["replayed"] and replay["result"] == response["result"], "template replay differs")
        owned.stop()
        image = backup_image(owned, "template")
        require(image["complete"] and len(image["tables"]) == 13, "template complete inventory is missing")
        checked = owned.cli("check", owned.store)
        return {"status": "passed", "model_selector": model, "model": catalog["model"],
                "template_config": "deploy/server.example.json with owned public key and loopback ephemeral port",
                "max_inflight": config["max_inflight"], "request_timeout_seconds": config["request_timeout_seconds"],
                "authenticated_db_operations": True, "literal_input": True, "original_id_replay": True,
                "complete_table_count": 13, "integrity_status": checked["status"]}
    finally:
        if owned is not None:
            owned.stop()


def configuration_controls(bundle, directory, backend, http_directory, environment, cluster_file=None):
    """Quiescent complete images fence invalid config and create-only restore."""
    prefix = [str(bundle / "bin/rebase-next"), "--backend", backend]
    if cluster_file:
        prefix += ["--cluster-file", str(cluster_file)]
    prefix += ["--model", "calculation"]
    store = http_directory / "backend/app.redb"
    before, after = directory / f"{backend}-config-before.backup.json", directory / f"{backend}-config-after.backup.json"
    result = run_command([*prefix, "backup", str(store), str(before)], bundle, directory,
                         backend + "-config-before", environment)
    require_success(result, "configuration baseline")
    config = read_json(http_directory / "backend/server.json")
    unknown = directory / f"{backend}-unknown-config.json"
    write_json(unknown, {**config, "unknown_limit": 1})
    rejected = rejection(run_command([*prefix, "serve", str(store), "--config", str(unknown)], bundle,
                         directory, backend + "-unknown-config", environment), "unknown server configuration", "unknown field")
    invalid = directory / f"{backend}-invalid-config.json"
    write_json(invalid, {**config, "max_inflight": 0})
    bounds = rejection(run_command([*prefix, "serve", str(store), "--config", str(invalid)], bundle,
                       directory, backend + "-invalid-config", environment), "invalid server limits", "network concurrency/deadline limits")
    restore = rejection(run_command([*prefix, "restore", str(http_directory / "backend/after-process-restart.backup.json"),
                        str(store)], bundle, directory, backend + "-existing-destination", environment), "populated restore destination")
    observed = run_command([*prefix, "backup", str(store), str(after)], bundle, directory,
                           backend + "-config-after", environment)
    require_success(observed, "configuration final image")
    left, right = read_json(before)["payload"], read_json(after)["payload"]
    if not left["complete"] or len(left["tables"]) != 13 or left != right:
        raise RuntimeError("invalid configuration or populated restore changed complete application state")
    return {"status": "passed", "unknown_fields": rejected, "invalid_limits": bounds,
            "populated_restore_destination": restore, "complete_thirteen_table_equality": True}


def run_release(bundle_dir, directory, *, cluster_file=None, native_library_path=None,
                database_pid=None, database_paths=()):
    """Verify one current extracted variant; selected backend prerequisites are explicit."""
    bundle, directory = Path(bundle_dir).resolve(strict=True), Path(directory).resolve()
    if not outside_git(bundle) or not outside_git(directory) or directory.is_relative_to(bundle):
        raise ValueError("extracted bundle and new private output must be outside Git, with output outside the payload")
    manifest = read_json(bundle / "BUNDLE.json")
    backends, features = manifest["supported_backends"], manifest["build"]["features"]
    if "foundationdb" in features and native_library_path is None:
        raise ValueError("FoundationDB-feature artifact needs an explicit native library path for every backend")
    if "foundationdb" in backends and (cluster_file is None or type(database_pid) is not int or len(database_paths) != 2):
        raise ValueError("FoundationDB extracted smoke needs its explicit cluster, owned PID, data and log paths")
    cluster_file = None if cluster_file is None else Path(cluster_file).resolve(strict=True)
    environment = runtime_environment(native_library_path)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {"status": "running", "source_commit": manifest["source_commit"],
              "binary_sha256": manifest["binary_sha256"], "features": features, "formats": manifest["formats"],
              "supported_backends": backends, "matrix": {}, "controls": {},
              "isolation": {"outside_git": True, "python_isolated": True, "ambient_python_imports": False,
                            "helpers": "extracted tools only", "private_output_outside_payload": True},
              "scope": "Extracted short equipment smoke and targeted recovery/configuration",
              "budgets": {"command_seconds": 120, "command_log_bytes": MAX_LOG_BYTES,
                          "json_bytes": MAX_JSON_BYTES, "artifacts_bytes": MAX_ARTIFACT_BYTES},
              "remaining_fault_gaps": ["native commit acknowledgement isolation", "replicated failover", "disk/power loss"]}
    started = time.monotonic()
    try:
        identity = run_command(isolated_command(bundle, "check-bundle"), bundle, directory, "identity", environment)
        require_success(identity, "extracted identity")
        result["identity"] = json.loads(identity["stdout"])
        if "foundationdb" in features:
            missing = run_command([str(bundle / "bin/rebase-next"), "version"], bundle, directory,
                                  "missing-library", runtime_environment())
            result["controls"]["missing_library"] = rejection(missing, "missing native library", "libfdb_c")
        for backend in ("surrealkv", "foundationdb"):
            if backend not in backends:
                missing = run_command([str(bundle / "bin/rebase-next"), "--backend", backend, "version"],
                                      bundle, directory, "missing-" + backend, environment)
                result["controls"]["missing_" + backend] = rejection(missing, "missing compiled backend", "support is missing")
        for label, args, diagnostic in (
                ("unknown-model", ["--model", "unprovided-model", "version"], "unknown compiled model"),
                ("unknown-backend", ["--backend", "tikv", "version"], "requires redb"),
                ("wrong-cluster-selector", ["--backend", "redb", "--cluster-file", "unprovided.cluster", "version"], "only valid")):
            result["controls"][label] = rejection(run_command([str(bundle / "bin/rebase-next"), *args], bundle,
                                                  directory, label, environment), label, diagnostic)
        checksums = run_command(isolated_command(bundle, "checksum-controls", directory / "checksum-controls"),
                               bundle, directory, "checksum-controls", environment)
        require_success(checksums, "extracted checksum controls")
        result["controls"]["checksums"] = json.loads(checksums["stdout"])
        for backend in backends:
            common = ["--binary", str(bundle / "bin/rebase-next"), "--backend", backend]
            if backend == "foundationdb":
                common += ["--cluster-file", str(cluster_file)]
            smoke_out = directory / (backend + "-smoke")
            smoke_args = ["smoke", *common, "--out", str(smoke_out)]
            if backend == "foundationdb":
                smoke_args += ["--database-pid", str(database_pid), "--database-data", str(database_paths[0]),
                               "--database-log", str(database_paths[1])]
            smoke = run_command(isolated_command(bundle, "g8.py", *smoke_args), bundle, directory,
                                backend + "-smoke", environment)
            require_success(smoke, backend + " extracted equipment smoke")
            observed = read_json(smoke_out / "result.json")
            if observed["status"] != "passed":
                raise RuntimeError("extracted smoke did not pass every required obligation")
            result["matrix"][backend] = {"smoke": {"status": "passed", "profile": observed["profile"]["label"],
                "duration_seconds": observed["profile"]["duration_seconds"], "result": str(smoke_out / "result.json"),
                "resources": observed["resources"]["status"], "complete_table_count": observed["complete_state"]["table_count"]}}
            http_out = directory / (backend + "-http")
            http = run_command(isolated_command(bundle, "g7_http.py", *common, "--out", str(http_out),
                               "--rounds", "1", "--clients", "2"), bundle, directory, backend + "-http", environment)
            require_success(http, backend + " extracted recovery workflow")
            recovered = read_json(http_out / "result.json")
            if recovered["status"] != "passed":
                raise RuntimeError("extracted recovery workflow did not pass")
            result["matrix"][backend]["recovery"] = {"status": "passed", "result": str(http_out / "result.json"),
                "process_restart": recovered["process_restart"], "lifecycle": recovered["lifecycle"],
                "original_id_reconciliation": recovered["request_response_faults"],
                "automatic_retries": recovered["automatic_retries"]}
            result["matrix"][backend]["configuration"] = configuration_controls(
                bundle, directory, backend, http_out, environment, cluster_file if backend == "foundationdb" else None)
            template_args = ["--probe-template", "--bundle", str(bundle), "--out", str(directory / (backend + "-template")),
                             "--backend", backend]
            if backend == "foundationdb":
                template_args += ["--cluster-file", str(cluster_file)]
            template = run_command(isolated_command(bundle, "g8_release.py", *template_args), bundle, directory,
                                   backend + "-template", environment)
            require_success(template, backend + " extracted deployment template")
            result["matrix"][backend]["template"] = json.loads(template["stdout"])
            result["artifacts"] = artifact_usage(directory)
            write_json(directory / "result.json", result)
        final_identity = run_command(isolated_command(bundle, "check-bundle"), bundle, directory,
                                     "identity-after-workflows", environment)
        require_success(final_identity, "final extracted source checksums")
        result.update(status="passed", elapsed_seconds=round(time.monotonic() - started, 3),
                      final_payload_unchanged=True, owned_workers_drained=True)
        publish_result(directory, result)
        return result
    except BaseException as error:
        result.update(status="incomplete" if isinstance(error, Incomplete) else "failed",
                      error=type(error).__name__, message=str(error), elapsed_seconds=round(time.monotonic() - started, 3))
        write_json(directory / "result.json", result)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--cluster-file", type=Path)
    parser.add_argument("--native-library-path", type=Path)
    parser.add_argument("--database-pid", type=int)
    parser.add_argument("--database-data", type=Path)
    parser.add_argument("--database-log", type=Path)
    parser.add_argument("--probe-template", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--backend", choices=("redb", "surrealkv", "foundationdb"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.probe_template:
            if not args.backend:
                parser.error("template probe requires --backend")
            result = probe_template(args.bundle.resolve(strict=True), args.out, args.backend, args.cluster_file)
        else:
            paths = (args.database_data, args.database_log) if args.database_data and args.database_log else ()
            result = run_release(args.bundle, args.out, cluster_file=args.cluster_file,
                native_library_path=args.native_library_path, database_pid=args.database_pid, database_paths=paths)
        print(json.dumps({"status": result["status"], "result": str(args.out / "result.json")} if not args.probe_template else result))
        return 0
    except BaseException as error:
        status = "incomplete" if isinstance(error, Incomplete) else "failed"
        print(json.dumps({"status": status, "error": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 2 if status == "incomplete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
