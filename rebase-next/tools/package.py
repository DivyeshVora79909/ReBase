#!/usr/bin/env python3
"""Build committed ReBase Next sources outside Git and package a native Linux bundle."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
MODELS = ("calculation", "equipment", "invoicing", "measurement", "effect-demo", "quantity")
FEATURES = ("foundationdb", "surrealkv")
TEMPLATES = {"redb": "deploy/rebase-next.service",
             "surrealkv": "deploy/rebase-next-surreal.service",
             "foundationdb": "deploy/rebase-next-foundationdb.service"}
MAX_METADATA_BYTES = 8 * 1024 * 1024


def command(*args, cwd=ROOT):
    return subprocess.run([str(arg) for arg in args], cwd=cwd, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120).stdout


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def selected_features(value):
    """Explicit Cargo features, in a stable order; no unknown build flags."""
    if not isinstance(value, str):
        raise ValueError("features must be a comma-separated string")
    if not value:
        return []
    names = value.split(",")
    if len(set(names)) != len(names) or any(name not in FEATURES for name in names):
        raise ValueError("features must name foundationdb and/or surrealkv once each")
    return sorted(names)


def backend_names(features):
    if not isinstance(features, list) or features != selected_features(",".join(features)):
        raise ValueError("features must be an explicit canonical list")
    return ["redb", *features]


def model_identity(identity, catalog, version):
    """Check a compiled version against its independently exported public catalog."""
    if (not isinstance(identity, dict) or not isinstance(catalog, dict)
            or identity.get("version") != version
            or not isinstance(identity.get("model"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", identity["model"])
            or identity["model"] != catalog.get("model")
            or not isinstance(identity.get("store_format"), str)
            or not re.fullmatch(r"rebase-store-[1-9][0-9]*", identity["store_format"])
            or not isinstance(catalog.get("api"), str)
            or not re.fullmatch(r"rebase-local-api-[1-9][0-9]*", catalog["api"])
            or not isinstance(catalog.get("codec"), str)
            or not re.fullmatch(r"native-slice-kv-[1-9][0-9]*", catalog["codec"])
            or not isinstance(catalog.get("contracts"), list) or not catalog["contracts"]
            or not isinstance(catalog.get("capabilities"), dict)
            or not isinstance(catalog["capabilities"].get("limits"), dict)):
        raise RuntimeError("compiled package/catalog identity differs or is incomplete")
    return {**identity, "api": catalog["api"], "codec": catalog["codec"],
            "limits": catalog["capabilities"]["limits"]}


def payload_path(directory, name):
    """Only bundle-relative regular files can supply evidence or executable inputs."""
    if (not isinstance(name, str) or not name or "\\" in name or "\n" in name
            or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
            or str(PurePosixPath(name)) != name):
        raise RuntimeError("invalid bundle-relative filename")
    path = directory / name
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise RuntimeError(f"missing or nonregular bundle file: {name}")
    return path


def bounded_json(path):
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise RuntimeError("bundle metadata exceeds the bounded reader")
    return json.loads(path.read_bytes())


def extract_trusted_sources(source, destination):
    """Extract only ordinary, in-tree files and directories from git archive."""
    members = source.getmembers()
    for member in members:
        name = member.name
        if (not name or "\\" in name or "\n" in name or PurePosixPath(name).is_absolute()
                or ".." in PurePosixPath(name).parts or str(PurePosixPath(name)) != name
                or not (member.isfile() or member.isdir())):
            raise RuntimeError("release sources must contain only bounded regular files and directories")
    source.extractall(destination, members=members, filter="data")


def verify_checksums(directory):
    """Verify the complete listed payload without reading file bodies into RAM."""
    directory = Path(directory).resolve(strict=True)
    checksums = payload_path(directory, "SHA256SUMS")
    if checksums.stat().st_size > MAX_METADATA_BYTES:
        raise RuntimeError("checksum inventory exceeds the bounded reader")
    entries = {}
    for line in checksums.read_text().splitlines():
        checksum, separator, name = line.partition("  ")
        if (not separator or not re.fullmatch(r"[0-9a-f]{64}", checksum)
                or name in entries or name == "SHA256SUMS"):
            raise RuntimeError("invalid or duplicate checksum entry")
        if digest(payload_path(directory, name)) != checksum:
            raise RuntimeError(f"bundle checksum differs: {name}")
        entries[name] = checksum
    if not entries or "BUNDLE.json" not in entries or "bin/rebase-next" not in entries:
        raise RuntimeError("bundle checksum inventory is incomplete")
    return entries


def check_bundle(directory, *, check_binary=True):
    """Composable extracted-release identity check; workflow acceptance is separate.

    With check_binary=True the actual extracted executable supplies each version
    and catalog. No source checkout, Cargo or store is used. Host native libraries
    remain explicit runtime prerequisites for a FoundationDB-feature artifact.
    """
    directory = Path(directory).resolve(strict=True)
    entries = verify_checksums(directory)
    manifest = bounded_json(payload_path(directory, "BUNDLE.json"))
    if manifest.get("format") != "rebase-deployment-bundle-2":
        raise RuntimeError("unsupported deployment bundle format")
    features = manifest.get("build", {}).get("features")
    if manifest.get("supported_backends") != backend_names(features):
        raise RuntimeError("feature/backend inventory differs")
    if (manifest.get("models", {}).keys() != set(MODELS)
            or not isinstance(manifest.get("source_files"), dict)
            or not manifest["source_files"]
            or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("source_commit", ""))
            or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("source_tree", ""))):
        raise RuntimeError("source/model inventory is incomplete")
    for name, checksum in manifest["source_files"].items():
        if entries.get(name) != checksum:
            raise RuntimeError(f"source/checksum inventory differs: {name}")
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "src/bin/rebase-next.rs",
                 "tools/client.py", "tools/harness.py", "tools/g8.py", "deploy/server.example.json"):
        if name not in manifest["source_files"]:
            raise RuntimeError(f"required committed bundle input is missing: {name}")
    if entries.get("bin/rebase-next") != manifest.get("binary_sha256"):
        raise RuntimeError("binary/checksum identity differs")
    build = manifest["build"]
    if (build.get("profile") != "release" or build.get("jobs") != 2
            or build.get("locked") is not True or build.get("incremental") is not False
            or build.get("outside_git") is not True):
        raise RuntimeError("bundle build contract differs")
    for backend in manifest["supported_backends"]:
        if manifest.get("deployment_templates", {}).get(backend) != TEMPLATES[backend]:
            raise RuntimeError("compatible deployment template is missing")
        payload_path(directory, TEMPLATES[backend])
    binary = payload_path(directory, "bin/rebase-next")
    formats = manifest.get("formats", {})
    for name in MODELS:
        expected = manifest["models"][name]
        catalog_name = f"catalogs/{name}.public.json"
        if (expected.get("catalog") != catalog_name
                or expected.get("catalog_sha256") != entries.get(catalog_name)):
            raise RuntimeError(f"catalog inventory differs: {name}")
        catalog = bounded_json(payload_path(directory, catalog_name))
        saved = model_identity(expected, catalog, manifest["package_version"])
        if any(saved[key] != expected.get(key) for key in ("api", "codec", "limits")):
            raise RuntimeError(f"saved catalog metadata differs: {name}")
        if (saved["store_format"] != formats.get("store")
                or saved["codec"] != formats.get("native_codec")
                or saved["api"] != formats.get("api")):
            raise RuntimeError("shared model format inventory differs")
        if check_binary:
            version = json.loads(command(binary, "--model", name, "version", cwd=directory))
            actual = json.loads(command(binary, "--model", name, "model", "public", cwd=directory))
            actual_identity = model_identity(version, actual, manifest["package_version"])
            if actual_identity != {key: expected[key] for key in actual_identity} or actual != catalog:
                raise RuntimeError(f"extracted executable/catalog differs: {name}")
            developer = json.loads(command(binary, "--model", name, "model", "developer", cwd=directory))
            if developer.get("behavior_contract") != expected.get("behavior_contract"):
                raise RuntimeError(f"extracted behavior identity differs: {name}")
    effects = bounded_json(payload_path(directory, "catalogs/effect-demo.public.json"))["capabilities"].get("effects", {})
    if effects.get("codec") != formats.get("effect_codec"):
        raise RuntimeError("effect codec inventory differs")
    libraries = manifest.get("platform", {}).get("shared_libraries", [])
    needs_fdb = any(library.startswith("libfdb_c.so") for library in libraries)
    if needs_fdb != ("foundationdb" in features):
        raise RuntimeError("FoundationDB feature/native-library inventory differs")
    fdb = manifest.get("native_prerequisites", {}).get("foundationdb", {})
    if (fdb.get("required") is not ("foundationdb" in features)
            or fdb.get("bundled") is not False
            or fdb.get("library") != "libfdb_c"):
        raise RuntimeError("FoundationDB runtime prerequisite inventory differs")
    return {"status": "passed", "checksummed_files": len(entries), "model_count": len(MODELS),
            "binary_catalogs_checked": check_binary, "features": features,
            "supported_backends": manifest["supported_backends"],
            "source_commit": manifest["source_commit"], "binary_sha256": manifest["binary_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="New directory for archive, checksums and build evidence")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/verification-build",
                        help="Reusable Cargo compilation cache; only archived sources are built")
    parser.add_argument("--features", default="", help="Explicit optional Cargo features: foundationdb,surrealkv")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("this bundle profile targets native Linux x86_64")
    if os.environ.get("CARGO_BUILD_TARGET"):
        parser.error("unset CARGO_BUILD_TARGET for this native build")
    try:
        features = selected_features(args.features)
    except ValueError as error:
        parser.error(str(error))
    if "foundationdb" in features:
        sdk = os.environ.get("FDB_CLIENT_LIB_PATH")
        if not sdk or not any(Path(sdk).glob("libfdb_c.so*")):
            parser.error("FoundationDB feature requires FDB_CLIENT_LIB_PATH containing compatible libfdb_c; see docs/storage-backends.md")
    repository = Path(command("git", "rev-parse", "--show-toplevel").decode().strip())
    commit = command("git", "rev-parse", "HEAD").decode().strip()
    prefix = command("git", "rev-parse", "--show-prefix").decode().strip().rstrip("/")
    source_tree = command("git", "rev-parse", f"{commit}:{prefix}").decode().strip()
    epoch = int(command("git", "show", "-s", "--format=%ct", commit))
    archive = command("git", "archive", "--format=tar", source_tree, cwd=repository)
    target = args.target_dir.resolve()
    destination = args.out.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    rustc = command("rustc", "-Vv").decode().strip()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="rebase-next-build-") as temporary:
        copied = Path(temporary) / "source"
        copied.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            extract_trusted_sources(source, copied)
        inside_git = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=copied,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if inside_git.returncode == 0:
            raise RuntimeError("isolated build directory is inside Git")
        source_hashes = {str(path.relative_to(copied)): digest(path)
                         for path in sorted(copied.rglob("*")) if path.is_file()}
        build = ["cargo", "build", "--locked", "--release", "--manifest-path", str(copied / "Cargo.toml"),
                 "--target-dir", str(target), "--jobs", "2", "--bin", "rebase-next"]
        if features:
            build += ["--features", ",".join(features)]
        print(f"Building committed source {commit} outside Git; log: {destination / 'build.log'}", flush=True)
        with (destination / "build.log").open("wb") as log:
            subprocess.run(build, cwd=copied, env=dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2"),
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        elapsed = round(time.monotonic() - started, 3)
        (copied / "bin").mkdir()
        binary = copied / "bin/rebase-next"
        shutil.copyfile(target / "release/rebase-next", binary)
        binary.chmod(0o755)
        version = tomllib.loads((copied / "Cargo.toml").read_text())["package"]["version"]
        models = {}
        (copied / "catalogs").mkdir()
        for name in MODELS:
            identity = json.loads(command(binary, "--model", name, "version", cwd=copied))
            catalog = json.loads(command(binary, "--model", name, "model", "public", cwd=copied))
            developer = json.loads(command(binary, "--model", name, "model", "developer", cwd=copied))
            models[name] = model_identity(identity, catalog, version)
            if (developer.get("model") != identity["model"] or developer.get("api") != catalog["api"]
                    or developer.get("codec") != catalog["codec"]):
                raise RuntimeError("public/developer catalog identity differs")
            catalog_name = f"catalogs/{name}.public.json"
            write_json(copied / catalog_name, catalog)
            models[name].update(behavior_contract=developer["behavior_contract"], catalog=catalog_name,
                                catalog_sha256=digest(copied / catalog_name))
        formats = {"store": models["calculation"]["store_format"],
                   "native_codec": models["calculation"]["codec"], "api": models["calculation"]["api"],
                   "effect_codec": json.loads((copied / "catalogs/effect-demo.public.json").read_bytes())["capabilities"]["effects"]["codec"]}
        symbols = command("readelf", "--version-info", binary).decode()
        glibc = max(tuple(map(int, value.split("."))) for value in re.findall(r"GLIBC_([0-9.]+)", symbols))
        dynamic = command("readelf", "--dynamic", binary).decode()
        manifest = {
            "format": "rebase-deployment-bundle-2", "package_version": version,
            "source_commit": commit, "source_tree": source_tree, "source_timestamp": epoch,
            "source_files": source_hashes, "binary_sha256": digest(binary), "models": models, "formats": formats,
            "supported_backends": backend_names(features),
            "deployment_templates": {backend: TEMPLATES[backend] for backend in backend_names(features)},
            "native_prerequisites": {"foundationdb": {
                "required": "foundationdb" in features,
                "library": "libfdb_c", "accepted_client_server": "7.3.77", "rust_binding": "0.11.0", "api": "7.3",
                "build": "FDB_CLIENT_LIB_PATH must contain a compatible native client library",
                "runtime": "The dynamic loader needs libfdb_c even when selecting redb; set an explicit library path. A running compatible cluster and explicit cluster file are required for FoundationDB operations.",
                "bundled": False}},
            "build": {"rustc": rustc, "cargo": command("cargo", "--version").decode().strip(),
                      "profile": "release", "features": features, "jobs": 2, "locked": True,
                      "incremental": False, "outside_git": True},
            "platform": {"system": platform.system(), "machine": platform.machine(),
                         "kernel": platform.release(), "libc": list(platform.libc_ver()),
                         "minimum_glibc": ".".join(map(str, glibc)),
                         "shared_libraries": re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic)},
            "tools_require": ["Python 3.11+", "OpenSSL for issuer keys and acceptance workflows"],
            "scope": "One selected backend, tenant and compiled model per store. Embedded adapters own one process; FoundationDB needs its native client and cluster. Extracted workflow acceptance is separate; G6, TiKV and frontend remain deferred.",
        }
        write_json(copied / "BUNDLE.json", manifest)
        files = sorted(path for path in copied.rglob("*") if path.is_file())
        with (copied / "SHA256SUMS").open("w") as checksums:
            for path in files:
                name = str(path.relative_to(copied))
                if "\n" in name or "\\" in name:
                    raise RuntimeError("unsupported checksum filename")
                checksums.write(f"{digest(path)}  {name}\n")
        verified = check_bundle(copied)
        stem = f"rebase-next-{version}-linux-x86_64-{'-'.join(backend_names(features))}"
        bundle = destination / f"{stem}.tar.gz"

        def normalized(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            info.pax_headers = {}
            return info

        with bundle.open("xb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as packed:
                    packed.add(copied, arcname=stem, filter=normalized)
        checksum = digest(bundle)
        bundle.with_suffix(bundle.suffix + ".sha256").write_text(f"{checksum}  {bundle.name}\n")
        write_json(destination / "BUNDLE.json", manifest)
        report = {"status": "packaged; extracted workflow acceptance is separate", "source_commit": commit,
                  "source_tree": source_tree, "bundle": bundle.name, "bundle_sha256": checksum,
                  "bundle_bytes": bundle.stat().st_size, "binary_sha256": manifest["binary_sha256"],
                  "source_files": len(source_hashes), "checksummed_files": len(files),
                  "features": features, "supported_backends": backend_names(features), "formats": formats,
                  "payload_identity": verified,
                  "build": {"command": build, "outside_git": True, "elapsed_seconds": elapsed,
                            "log": "build.log", "source_directory_removed_after_packaging": True}}
        write_json(destination / "result.json", report)
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
