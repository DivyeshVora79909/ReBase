#!/usr/bin/env python3
"""Extracted command isolation, bounded evidence and cleanup controls.

The child processes here are small standard-library controls. They do not mock
distributed acceptance or claim any database/release workflow has executed.
"""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import g8_release


class ExtractedControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle, self.output = self.root / "bundle", self.root / "output"
        self.bundle.mkdir()
        (self.bundle / "tools").mkdir()
        self.output.mkdir()

    def test_isolated_python_uses_only_explicit_extracted_tools_and_cwd(self):
        (self.bundle / "tools/marker.py").write_text("OWNER='extracted'\n")
        (self.bundle / "tools/g8.py").write_text(
            "import json, os, marker\nprint(json.dumps({'owner':marker.OWNER, 'cwd':os.getcwd()}))\n")
        ambient = self.root / "ambient"
        ambient.mkdir()
        (ambient / "marker.py").write_text("OWNER='ambient checkout'\n")
        with patch.dict(os.environ, {"PYTHONPATH": str(ambient), "PYTHONHOME": "unprovided-home"}):
            environment = g8_release.runtime_environment()
            observation = g8_release.run_command(g8_release.isolated_command(self.bundle, "g8.py"),
                self.bundle, self.output, "isolation", environment)
        self.assertEqual(observation["returncode"], 0)
        self.assertEqual(json.loads(observation["stdout"]), {"owner": "extracted", "cwd": str(self.bundle)})
        self.assertTrue(observation["owned_group_drained"])
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("PYTHONHOME", environment)

    def test_runtime_library_selection_is_explicit(self):
        with patch.dict(os.environ, {"LD_LIBRARY_PATH": "/ambient/library"}):
            self.assertNotIn("LD_LIBRARY_PATH", g8_release.runtime_environment())
        native = self.root / "native"
        native.mkdir()
        with self.assertRaisesRegex(ValueError, "must contain compatible"):
            g8_release.runtime_environment(native)
        (native / "libfdb_c.so").write_bytes(b"fixture for path selection only")
        self.assertEqual(g8_release.runtime_environment(native)["LD_LIBRARY_PATH"], str(native))
        with self.assertRaises(ValueError):
            g8_release.isolated_command(self.bundle, "unprovided.py")

    def test_timeout_and_required_log_exhaustion_are_incomplete(self):
        with self.assertRaisesRegex(g8_release.Incomplete, "deadline"):
            g8_release.run_command([sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                self.bundle, self.output, "deadline", g8_release.runtime_environment(), timeout=.1)
        with patch("g8_release.MAX_LOG_BYTES", 64):
            with self.assertRaisesRegex(g8_release.Incomplete, "log byte budget"):
                g8_release.run_command([sys.executable, "-I", "-c", "print('x'*128)"],
                    self.bundle, self.output, "bytes", g8_release.runtime_environment())

    def test_abandoned_owned_child_is_detected_and_stopped(self):
        code = ("import pathlib, subprocess, sys; "
                "p=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)']); "
                f"pathlib.Path({str(self.output / 'child.pid')!r}).write_text(str(p.pid))")
        with self.assertRaisesRegex(g8_release.Incomplete, "left an owned worker"):
            g8_release.run_command([sys.executable, "-I", "-c", code], self.bundle, self.output,
                                  "child", g8_release.runtime_environment())
        child = int((self.output / "child.pid").read_text())
        try:
            state = Path(f"/proc/{child}/stat").read_text().rsplit(") ", 1)[1].split()[0]
        except FileNotFoundError:
            state = None
        self.assertIn(state, (None, "Z"))

    def test_incomplete_exit_is_preserved_and_rejections_require_diagnostics(self):
        observation = {"returncode": 2, "stderr": b"missing support", "logs": [], "owned_group_drained": True}
        with self.assertRaises(g8_release.Incomplete):
            g8_release.require_success(observation, "required case")
        self.assertEqual(g8_release.rejection(observation, "negative case", "missing support")["status"], "passed")
        with self.assertRaises(RuntimeError):
            g8_release.rejection(observation, "wrong boundary", "different error")
        with self.assertRaises(RuntimeError):
            g8_release.rejection({**observation, "returncode": 0}, "accepted invalid input")

    def test_outside_git_and_native_prerequisite_preflight(self):
        self.assertTrue(g8_release.outside_git(self.bundle))
        (self.root / ".git").write_text("gitdir: another-worktree")
        self.assertFalse(g8_release.outside_git(self.bundle))
        with self.assertRaisesRegex(ValueError, "outside Git"):
            g8_release.run_release(self.bundle, self.root / "new-output")
        (self.root / ".git").unlink()
        (self.bundle / "BUNDLE.json").write_text(json.dumps({
            "supported_backends": ["redb", "foundationdb"], "build": {"features": ["foundationdb"]}}))
        with self.assertRaisesRegex(ValueError, "explicit native library path"):
            g8_release.run_release(self.bundle, self.root / "new-output")

    def test_required_json_and_artifact_observations_are_bounded(self):
        with self.assertRaises(g8_release.Incomplete):
            g8_release.read_json(self.output / "absent.json")
        (self.output / "big.json").write_text('{"large":"xxxx"}')
        with patch("g8_release.MAX_JSON_BYTES", 4):
            with self.assertRaises(g8_release.Incomplete):
                g8_release.read_json(self.output / "big.json")
        with patch("g8_release.MAX_ARTIFACT_BYTES", 4):
            with self.assertRaisesRegex(g8_release.Incomplete, "artifact budget"):
                g8_release.artifact_usage(self.output)

    def test_final_publication_counts_result_fields_and_summary(self):
        (self.output / "kept.jsonl").write_bytes(b"a retained private observation\n")
        g8_release.write_json(self.output / "result.json", {"status": "running"})
        result = {"status": "passed", "source_commit": "a" * 40,
                  "features": [], "supported_backends": ["redb"], "matrix": {"redb": {"status": "passed"}}}
        usage = g8_release.publish_result(self.output, result)
        actual_bytes = sum(path.stat().st_size for path in self.output.rglob("*") if path.is_file())
        saved = json.loads((self.output / "result.json").read_bytes())
        self.assertEqual(usage["bytes"], actual_bytes)
        self.assertEqual(saved["artifacts"]["bytes"], actual_bytes)
        self.assertTrue((self.output / "summary.md").is_file())
        self.assertEqual(saved["status"], "passed")

    def test_initial_budget_pass_cannot_hide_final_publication_exhaustion(self):
        (self.output / "kept.jsonl").write_bytes(b"x" * 100)
        result = {"status": "passed", "source_commit": "a" * 40,
                  "features": [], "supported_backends": ["redb"]}
        with patch("g8_release.MAX_ARTIFACT_BYTES", 128):
            self.assertEqual(g8_release.artifact_usage(self.output)["status"], "passed")
            with self.assertRaisesRegex(g8_release.Incomplete, "final result and summary"):
                g8_release.publish_result(self.output, result)
        self.assertFalse((self.output / "result.json").exists())
        self.assertFalse((self.output / "summary.md").exists())
        self.assertEqual(result["artifacts"]["status"], "incomplete")

    def test_real_bytes_checksum_controls_preserve_original_payload(self):
        (self.bundle / "bin").mkdir()
        (self.bundle / "bin/rebase-next").write_bytes(b"payload bytes only; no executable acceptance")
        (self.bundle / "BUNDLE.json").write_text("{}\n")
        (self.bundle / "tools/client.py").write_text("# original extracted input\n")
        original = (self.bundle / "tools/client.py").read_bytes()
        checked = g8_release.checksum_controls(self.bundle, self.root / "checksum-case")
        self.assertEqual(checked["status"], "passed")
        self.assertTrue(checked["changed_payload_rejected"])
        self.assertTrue(checked["missing_payload_rejected"])
        self.assertEqual((self.bundle / "tools/client.py").read_bytes(), original)

    def test_template_backend_cluster_and_model_are_explicit(self):
        deploy = self.bundle / "deploy"
        deploy.mkdir()
        source = Path(__file__).resolve().parents[1] / "deploy"
        for name in ("rebase-next.service", "rebase-next-surreal.service", "rebase-next-foundationdb.service"):
            shutil.copyfile(source / name, deploy / name)
        self.assertEqual(g8_release.template_selector(self.bundle, "redb"), "calculation")
        self.assertEqual(g8_release.template_selector(self.bundle, "surrealkv"), "equipment")
        self.assertEqual(g8_release.template_selector(self.bundle, "foundationdb"), "equipment")
        path = deploy / "rebase-next-surreal.service"
        path.write_text(path.read_text().replace("--backend surrealkv", "--backend redb"))
        with self.assertRaisesRegex(ValueError, "does not match"):
            g8_release.template_selector(self.bundle, "surrealkv")


if __name__ == "__main__":
    unittest.main()
