"""Focused unit controls for native evidence mapping."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import verify_checks


class VerifyChecksTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.rs"
        self.source.write_text("source fingerprint fixture")
        self.fingerprints_patch = patch.object(
            verify_checks, "_required_source_files", return_value={str(self.source)}
        )
        self.fingerprints_patch.start()
        self.addCleanup(self.fingerprints_patch.stop)

    def manifest(self, targets=None, source_hash=None):
        targets = targets or sorted({name for cases in verify_checks.REQUIREMENTS.values() for name in cases})
        entries = []
        self.binary_paths = {}
        for index, target in enumerate(targets):
            binary = self.root / f"harness-{index}"
            binary.write_bytes(f"fixture executable {target}".encode())
            self.binary_paths[target] = str(binary)
            entries.append({
                "target": target,
                "path": str(binary),
                "sha256": verify_checks._digest(binary),
                "source_fingerprints": {
                    str(self.source): source_hash or verify_checks._digest(self.source)
                },
            })
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"tests": entries}))
        return path

    def destination(self, name):
        path = self.root / name
        path.mkdir()
        return path

    def success(self):
        return SimpleNamespace(
            returncode=0,
            stdout="running 1 test\ntest sample::selected_case ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
            stderr="",
        )

    def test_missing_manifest_is_incomplete(self):
        result = verify_checks.run_checks(Path("unused"), self.destination("missing"), None)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("manifest was not supplied", result["manifest_problems"][0])
        self.assertEqual(result["capabilities"]["V-C01"]["status"], "incomplete")

    def test_stale_source_hash_rejects_artifact_without_execution(self):
        manifest = self.manifest(["exact_values"], source_hash="0" * 64)
        with patch.object(verify_checks.subprocess, "run") as run:
            result = verify_checks.run_checks(
                Path("unused"), self.destination("stale"), manifest
            )
        run.assert_not_called()
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("stale source fingerprints", result["manifest_problems"][0])
        self.assertEqual(result["harnesses"], {})

    def test_zero_passed_and_ignored_tests_remain_incomplete(self):
        manifest = self.manifest(["exact_values"])
        outputs = [
            SimpleNamespace(returncode=0, stdout="test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", stderr=""),
        ]
        with patch.object(verify_checks.subprocess, "run", side_effect=outputs):
            empty = verify_checks.run_checks(
                Path("unused"), self.destination("zero"), manifest
            )
            ignored = verify_checks.run_checks(
                Path("unused"), self.destination("ignored"), manifest
            )
        self.assertEqual(empty["capabilities"]["V-C01"]["status"], "incomplete")
        self.assertEqual(ignored["capabilities"]["V-C01"]["status"], "incomplete")
        self.assertNotEqual(empty["status"], "passed")
        self.assertNotEqual(ignored["status"], "passed")

    def test_harness_case_names_and_outcomes_are_retained(self):
        output = (
            "running 4 tests\n"
            "test module::literal_name ... ok\n"
            "test module::failed_name ... FAILED\n"
            "test module::ignored_name ... ignored\n"
            "test module::noisy_name ... WORKSHOP_EXHAUSTIVE transitions=258\n"
            "some captured output\n"
            "ok\n"
            "test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        )
        self.assertEqual(verify_checks._parse_cases(output), [
            {"name": "module::literal_name", "status": "ok"},
            {"name": "module::failed_name", "status": "failed"},
            {"name": "module::ignored_name", "status": "ignored"},
            {"name": "module::noisy_name", "status": "ok"},
        ])

    def test_failures_fail_rows_and_successful_native_only_cannot_close_v13_v14(self):
        manifest = self.manifest()
        with patch.object(verify_checks.subprocess, "run", return_value=self.success()):
            native_only = verify_checks.run_checks(
                Path("unused"), self.destination("native-only"), manifest
            )
        for capability in ("V-C13", "V-C14"):
            self.assertEqual(native_only["capabilities"][capability]["status"], "incomplete")
            self.assertEqual(
                native_only["capabilities"][capability]["additional_evidence_required"],
                ["process_and_provider_recovery"],
            )

        failed = SimpleNamespace(
            returncode=101,
            stdout="test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
            stderr="",
        )
        def run_harness(command, **_kwargs):
            return failed if command[0] == self.binary_paths["storage_lifecycle"] else self.success()

        with patch.object(verify_checks.subprocess, "run", side_effect=run_harness):
            result = verify_checks.run_checks(
                Path("unused"), self.destination("failed"), manifest
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["capabilities"]["V-C13"]["status"], "failed")
        self.assertEqual(result["capabilities"]["V-C14"]["status"], "failed")
        self.assertIn(
            {"harness": "local_api", "name": "sample::selected_case", "status": "ok"},
            result["capabilities"]["V-C13"]["executed_cases"],
        )


if __name__ == "__main__":
    unittest.main()
