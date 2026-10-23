"""Run already compiled Rust test harnesses and map their results to V-C01..15.

The manifest is produced by the build owner. This module never invokes Cargo.
Expected manifest shape::

    {"tests": [{"target": "lib" | "<integration target>",
                "path": "...", "sha256": "...",
                "source_fingerprints": {"src/file.rs": "sha256", ...}}]}

One executable per target is sufficient. A Rust harness is run once, and the
same result can support more than one capability row. Missing or stale evidence
is explicitly incomplete.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# These are the focused, already-existing seams named in research/43. A row is
# current only when every named harness ran successfully with at least one case.
REQUIREMENTS = {
    "V-C01": ("exact_values", "model_contract", "quantity", "lib"),
    "V-C02": ("equipment", "measurement", "quantity"),
    "V-C03": ("native_tree", "lib"),
    "V-C04": ("lib",),
    "V-C05": ("equipment", "lib"),
    "V-C06": ("lib", "routes"),
    "V-C07": ("quantity", "workshop_exhaustive", "lib"),
    "V-C08": ("equipment", "measurement", "lib"),
    "V-C09": ("measurement",),
    "V-C10": ("measurement", "lib"),
    "V-C11": ("access_control", "equipment_http", "network_api"),
    "V-C12": ("local_api", "semantics"),
    "V-C13": ("local_api", "network_api", "storage_lifecycle"),
    "V-C14": ("lib", "storage_lifecycle"),
    "V-C15": ("lib", "storage_lifecycle", "native_tree"),
}


def _required_source_files() -> set[str]:
    paths = {str(path.relative_to(ROOT)) for pattern in ("src/**/*.rs", "tests/**/*.rs", "model/**/*.json")
             for path in ROOT.glob(pattern)}
    paths.update(("Cargo.toml", "Cargo.lock"))
    return paths


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _manifest_entries(manifest: Path | None) -> tuple[dict[str, dict], list[str]]:
    if manifest is None:
        return {}, ["native manifest was not supplied"]
    try:
        data = json.loads(manifest.read_text())
    except (OSError, json.JSONDecodeError) as error:
        return {}, [f"cannot read native manifest: {error}"]
    entries = data.get("tests") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return {}, ['native manifest must contain a "tests" array']
    found: dict[str, dict] = {}
    problems: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("target"), str):
            problems.append("ignored malformed native test artifact entry")
            continue
        target = entry["target"]
        if target in found:
            problems.append(f"duplicate artifact for target {target}")
            continue
        path = Path(entry.get("path", ""))
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_file():
            problems.append(f"{target}: executable missing at {path}")
            continue
        actual = _digest(path)
        expected = entry.get("sha256")
        if not expected or actual != expected:
            problems.append(f"{target}: executable fingerprint mismatch")
            continue
        fingerprints = entry.get("source_fingerprints", {})
        if not isinstance(fingerprints, dict) or not fingerprints:
            problems.append(f"{target}: source fingerprints missing")
            continue
        missing_sources = sorted(_required_source_files() - set(fingerprints))
        if missing_sources:
            problems.append(f"{target}: source fingerprints omit {', '.join(missing_sources)}")
            continue
        stale = []
        for name, fingerprint in fingerprints.items():
            source = Path(name)
            if not source.is_absolute():
                source = ROOT / source
            if not source.is_file() or _digest(source) != fingerprint:
                stale.append(name)
        if stale:
            problems.append(f"{target}: stale source fingerprints: {', '.join(stale)}")
            continue
        found[target] = {"path": path, "sha256": actual,
                         "source_fingerprints": fingerprints}
    return found, problems


def _parse_summary(output: str) -> tuple[int, int, int] | None:
    matches = re.findall(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
        output,
    )
    if not matches:
        return None
    passed, failed, ignored = matches[-1]
    return int(passed), int(failed), int(ignored)


def _parse_cases(output: str) -> list[dict[str, str]]:
    """Capture the exact Rust harness test names and terminal outcomes."""
    cases, pending = [], None
    for line in output.splitlines():
        started = re.match(r"^test (.+?) \.\.\. (.*)$", line)
        if started:
            pending, line = started.groups()
        # --nocapture can print between the name and its terminal result.
        terminal = re.fullmatch(r"(ok|FAILED|ignored)(?: \([^\r\n]*\))?", line)
        if pending is not None and terminal:
            cases.append({"name": pending, "status": terminal[1].lower()})
            pending = None
    return cases


def run_checks(binary: Path, destination: Path,
               native_manifest: Path | None = None) -> dict:
    """Run cached test executables once each; return current V-C evidence."""
    del binary  # The Rust controls target the compiled test binaries, not CLI.
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    entries, manifest_problems = _manifest_entries(native_manifest)
    targets = sorted({target for needs in REQUIREMENTS.values() for target in needs})
    runs: dict[str, dict] = {}
    for target in targets:
        artifact = entries.get(target)
        if artifact is None:
            continue
        started = time.monotonic()
        try:
            completed = subprocess.run(
                [str(artifact["path"]), "--test-threads=1", "--nocapture"],
                cwd=ROOT, capture_output=True, text=True, timeout=900,
            )
            output = completed.stdout + completed.stderr
            parsed = _parse_summary(output)
            cases = _parse_cases(output)
            runs[target] = {
                "status": ("failed" if completed.returncode != 0 or parsed is None or parsed[1] else
                           "incomplete" if parsed[0] == 0 or parsed[2] else "passed"),
                "exit_code": completed.returncode,
                "passed": parsed[0] if parsed else 0,
                "failed": parsed[1] if parsed else 0,
                "ignored": parsed[2] if parsed else 0,
                "test_cases": cases,
                "duration_seconds": round(time.monotonic() - started, 3),
                "executable": str(artifact["path"]),
                "sha256": artifact["sha256"],
                "log": output,
            }
        except (OSError, subprocess.TimeoutExpired) as error:
            runs[target] = {"status": "failed", "error": str(error),
                            "duration_seconds": round(time.monotonic() - started, 3)}

    capabilities = {}
    for capability, needs in REQUIREMENTS.items():
        absent = [target for target in needs if target not in runs]
        failed = [target for target in needs if runs.get(target, {}).get("status") == "failed"]
        incomplete_runs = [target for target in needs if runs.get(target, {}).get("status") == "incomplete"]
        if failed:
            status = "failed"
        elif absent or incomplete_runs or manifest_problems:
            status = "incomplete"
        elif capability in ("V-C13", "V-C14"):
            # The parent report adds independently observed process/provider
            # recovery results; native test binaries alone cannot close these.
            status = "incomplete"
        else:
            status = "passed-current"
        capabilities[capability] = {
            "status": status,
            "required_harnesses": list(needs),
            "executed_harnesses": [target for target in needs if target in runs],
            "missing_harnesses": absent,
            "failed_harnesses": failed,
            "additional_evidence_required": (["process_and_provider_recovery"]
                                             if capability in ("V-C13", "V-C14") else []),
            "evidence": {target: {k: v for k, v in runs[target].items() if k != "log"}
                         for target in needs if target in runs},
            "executed_cases": [
                {"harness": target, **case}
                for target in needs if target in runs
                for case in runs[target].get("test_cases", [])
            ],
        }
    report = {
        "format": "rebase-native-checks-1",
        "status": ("failed" if any(result.get("status") == "failed" for result in runs.values()) else
                   "passed" if capabilities and all(item["status"] == "passed-current" for item in capabilities.values()) else "incomplete"),
        "manifest": str(native_manifest) if native_manifest else None,
        "manifest_problems": manifest_problems,
        "capabilities": capabilities,
        "harnesses": {target: {k: v for k, v in details.items() if k != "log"}
                      for target, details in runs.items()},
    }
    (destination / "native-checks.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for target, result in runs.items():
        safe_target = target.replace(":", "-")
        (destination / f"native-{safe_target}.log").write_text(result.get("log", result.get("error", "")))
    return report
