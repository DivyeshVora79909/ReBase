#!/usr/bin/env python3
"""Explain, check, explore and replay bounded non-accounting engine scenarios."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

import verify_cases
from verify_runtime import digest, write_json

ROOT = Path(__file__).resolve().parents[1]
CASES = ("equipment", "measurement", "quantity", "service")


def source_identity():
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True)
    paths = sorted({p for pattern in ("src/**/*.rs", "tests/**/*.rs", "tools/verify*.py", "model/**/*.json")
                    for p in ROOT.glob(pattern)})
    paths += [ROOT / name for name in ("Cargo.toml", "Cargo.lock")]
    return {"revision": result.stdout.strip() if result.returncode == 0 else None,
            "files": {str(p.relative_to(ROOT)): digest(p) for p in paths}}


def prepare_native(binary, destination):
    """One Cargo owner prepares existing harnesses; never a compile per case."""
    if shutil.which("cargo") is None:
        return None
    destination.mkdir(parents=True, exist_ok=True)
    args = ["cargo", "test", "--locked", "--all-targets", "--no-run", "--message-format=json"]
    print("Preparing native test artifacts once…", flush=True)
    with (destination / "build.jsonl").open("w") as output, (destination / "build.log").open("w") as errors:
        result = subprocess.run(args, cwd=ROOT, stdout=output, stderr=errors)
    if result.returncode:
        raise RuntimeError(f"Native preparation failed; see {destination / 'build.log'}")
    inputs = {name: value for name, value in source_identity()["files"].items()
              if name.endswith((".rs", ".json")) or name in ("Cargo.toml", "Cargo.lock")}
    entries = []
    for line in (destination / "build.jsonl").read_text().splitlines():
        item = json.loads(line)
        if item.get("reason") != "compiler-artifact" or not item.get("executable"):
            continue
        target, profile = item["target"], item["profile"]
        if not profile.get("test") or not set(target["kind"]) & {"lib", "test"}:
            continue
        name = "lib" if "lib" in target["kind"] else target["name"]
        path = Path(item["executable"]).resolve()
        entries.append({"target": name, "path": str(path), "sha256": digest(path),
                        "source_fingerprints": inputs})
    manifest = destination / "manifest.json"
    write_json(manifest, {"format": "rebase-native-manifest-1", "binary_sha256": digest(binary),
                          "tests": entries, "command": args})
    return manifest


def markdown(report):
    lines = ["# Workshop verification", "", f"Status: **{report['status']}**. Mode: {report['mode']}.", "",
             "Chapters have separate stores. Counters are work totals, not an execution trace.", "",
             "UUIDs and exact decimal/rational values are strings; unit/contract codes are integers.", ""]
    for case in report.get("cases", []):
        lines += ["## " + case["name"], "", "Model: " + case["model"] + ". " + case["scope"], ""]
        for step in case["steps"]:
            lines += ["### " + step["name"], "", step["intent"], "", step["dependency"], "",
                      "Expected: " + json.dumps(step["expected"], sort_keys=True), "",
                      "Observed: " + json.dumps(step.get("observed"), sort_keys=True), ""]
            for key in ("literals", "work", "range_read"):
                if step.get(key):
                    lines += [key + ": " + json.dumps(step[key], sort_keys=True), ""]
            lines += ["Ordinary action (" + step["method"] + "):", "", "~~~json",
                      json.dumps(step.get("plan", step.get("plans")), indent=2, sort_keys=True),
                      "~~~", "", "Internal observations: " + json.dumps(step.get("internal"), sort_keys=True), ""]
    if "native" in report:
        lines += ["## Capability coverage", "", "| Obligation | Status |", "| --- | --- |"]
        lines += [f"| {key} | {value['status']} |" for key, value in report["native"]["capabilities"].items()]
        lines += ["", "Native logs, source fingerprints and per-harness counts are in result.json.", ""]
    for key in ("exploration", "replay", "process"):
        if key in report:
            lines += ["## " + key.capitalize(), "", "Status: " + report[key]["status"], ""]
    if report.get("error"):
        lines += ["## Failure", "", str(report["error"]), ""]
    return "\n".join(lines + ["G6 accounting, G7 distributed storage, G8 release expansion and frontend remain deferred.", ""])


def walk(binary, destination, selected=None):
    results = []
    for name in ([selected] if selected else CASES):
        print(f"Verifying {name}…", flush=True)
        results.append(getattr(verify_cases, name)(binary, destination / name))
        write_json(destination / "partial.json", results)
    return results


def check(binary, destination, native_manifest=None, cases=None):
    """Compose ordinary workflow, native and fake-provider checks."""
    from verify_checks import run_checks
    from effects_worker import run as worker
    from effects_ingress import run as ingress
    if cases is None:
        cases = walk(binary, destination)
    if native_manifest is None:
        native_manifest = prepare_native(binary, destination / "native-build")
    if native_manifest:
        binding = json.loads(Path(native_manifest).read_text()).get("binary_sha256")
        if binding != digest(binary):
            raise ValueError("Native manifest does not bind this runtime binary")
    native = run_checks(binary, destination / "native", native_manifest)
    process = {"status": "passed", "worker": worker(binary, destination / "worker"),
               "ingress": ingress(binary, destination / "ingress")}
    process["status"] = "passed" if all(process[k]["status"] == "passed" for k in ("worker", "ingress")) else "failed"
    for key in ("V-C13", "V-C14"):
        row = native["capabilities"][key]
        if row["status"] == "incomplete" and not row["missing_harnesses"] and not native["manifest_problems"] and all(
                native["harnesses"][name]["status"] == "passed" and not native["harnesses"][name].get("ignored")
                for name in row["required_harnesses"]):
            row["status"] = "passed-current" if process["status"] == "passed" else "failed"
            row["process_evidence"] = ["worker", "ingress"]
            if process["status"] == "passed":
                row["additional_evidence_required"] = []
    states = {row["status"] for row in native["capabilities"].values()}
    status = "failed" if "failed" in states or process["status"] == "failed" else (
        "passed" if states == {"passed-current"} else "incomplete")
    native["status"] = status
    write_json(destination / "native" / "native-checks.json", native)
    write_json(destination / "process.json", process)
    return {"status": status, "cases": cases, "native": native, "process": process}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new owned directory")
    parser.add_argument("--mode", choices=("walk", "check", "explore", "replay"), default="walk")
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--seed", type=int, default=20261023)
    parser.add_argument("--steps", type=int, default=32)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--native-manifest", type=Path)
    args = parser.parse_args(argv)
    binary, destination = args.binary.resolve(), args.out.resolve()
    if not binary.is_file():
        parser.error("--binary does not exist")
    if args.mode == "replay" and args.artifact is None:
        parser.error("replay requires --artifact")
    if args.mode == "check" and args.case:
        parser.error("check covers the whole map; use walk --case for one chapter")
    if args.mode == "explore" and (args.case not in (None, "quantity") or not 1 <= args.steps <= 256):
        parser.error("explore supports quantity with 1..256 steps")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)
    report = {"format": "rebase-verification-1", "mode": args.mode, "status": "incomplete", "cases": [],
              "started_at": datetime.now(timezone.utc).isoformat(), "source": source_identity(),
              "binary": {"path": str(binary), "sha256": digest(binary)}}
    started = time.monotonic()
    try:
        if args.mode == "walk":
            report["cases"] = walk(binary, destination, args.case)
            report["native_scope"] = "not executed in walk; use check for current internal controls"
            report["status"] = "passed"
        elif args.mode == "check":
            report.update(check(binary, destination, args.native_manifest))
        else:
            from verify_explore import explore, replay
            key = "exploration" if args.mode == "explore" else "replay"
            value = (explore(binary, destination / key, args.seed, args.case, args.steps)
                     if key == "exploration" else replay(binary, destination / key, args.artifact))
            report.update({key: value, "status": value["status"]})
    except Exception as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        if not report["cases"] and (destination / "partial.json").exists():
            report["cases"] = json.loads((destination / "partial.json").read_text())
    finally:
        report["duration_seconds"] = round(time.monotonic() - started, 3)
        write_json(destination / "result.json", report)
        (destination / "summary.md").write_text(markdown(report))
        print(f"{report['status']}: {destination / 'summary.md'}", flush=True)
    return {"passed": 0, "failed": 1, "incomplete": 2}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
