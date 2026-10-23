#!/usr/bin/env python3
"""Exercise real-HTTP failure retention, shrinking and logical replay.

The backend remains correct. A test-only Scenario subclass injects a known
wrong observation when the authored fixture Source is set to 6, making this a
verification-tool fault probe rather than an engine defect report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import verify_explore
from verify_runtime import Mismatch, Scenario as BaseScenario, equal, write_json


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(binary, destination):
    binary = Path(binary).resolve()
    destination = Path(destination).resolve()
    if not binary.is_file():
        raise ValueError("--binary must name an existing executable")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    original_fixture = verify_explore._fixture

    class FaultScenario(BaseScenario):
        def public(self):
            records, expectation = super().public()
            source_id = getattr(self, "shrink_probe_source", None)
            if source_id and self.facts[source_id]["fields"]["value"] == "6":
                expected = expectation["derived"][source_id]["quantity"]
                # Deliberate comparator-observation defect, injected after the
                # actual HTTP state was checked against the independent oracle.
                equal("injected.quantity", expected, "wrong")
            return records, expectation

    def fixture(case):
        ids, draft = original_fixture(case)
        case.shrink_probe_source = ids["source"]
        return ids, draft

    verify_explore.Scenario = FaultScenario
    verify_explore._fixture = fixture
    try:
        try:
            verify_explore.explore(binary, destination / "explore", seed=5, steps=16)
        except Mismatch as error:
            if error.kind != "injected.quantity":
                raise
        else:
            raise AssertionError("Injected comparator fault was not detected")

        original_path = destination / "explore" / "failure.original.json"
        minimized_path = destination / "explore" / "failure.minimized.json"
        original = json.loads(original_path.read_text())
        minimized = json.loads(minimized_path.read_text())
        equal("shrink.failure_kind", "injected.quantity", original["mismatch"]["kind"])
        equal("shrink.status", "minimized", minimized["minimization"]["status"])
        equal("shrink.reproduced", True, minimized["minimization"]["same_failure_kind_reproduced"])
        if len(minimized["actions"]) >= len(original["actions"]):
            raise AssertionError("Failure trace did not shrink")
        if len(minimized["actions"]) != 1 or minimized["actions"][0].get("value") != "6":
            raise AssertionError("Expected the minimal authored Source=6 action")

        try:
            verify_explore.replay(binary, destination / "replay", minimized_path)
        except Mismatch as error:
            if error.kind != "injected.quantity":
                raise
            replay_result = {"format": "workshop-shrink-replay-probe-1", "status": "reproduced",
                             "failure_kind": error.kind,
                             "meaning": "Test-only comparator defect reproduced against a fresh logical fixture."}
        else:
            raise AssertionError("Logical replay did not reproduce the injected comparator fault")
        write_json(destination / "replay" / "replay.json", replay_result)

        report = {"format": "workshop-shrink-probe-1", "status": "passed",
                  "binary": {"path": str(binary), "sha256": sha256(binary)},
                  "source": minimized.get("source"),
                  "injected_defect": "Test-only wrong observation when fixture Source=6; engine and persisted state remain correct.",
                  "failure_kind": original["mismatch"]["kind"],
                  "original_action_count": len(original["actions"]),
                  "minimized_action_count": len(minimized["actions"]),
                  "logical_replay_reproduced": True,
                  "artifacts": {"original": str(original_path), "minimized": str(minimized_path),
                                "replay": str(destination / "replay" / "replay.json")}}
        write_json(destination / "result.json", report)
        return report
    finally:
        verify_explore.Scenario = BaseScenario
        verify_explore._fixture = original_fixture


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    args = parser.parse_args(argv)
    report = run(args.binary, args.out)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
