"""CLI integration boundaries: evidence paths and non-success exit status."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import g8


class CliControls(unittest.TestCase):
    def test_pressure_check_uses_the_complete_evidence_root(self):
        root = Path("target/example")
        with patch("sys.argv", ["g8.py", "check", "--result", str(root / "pressure/pressure-result.json")]), \
             patch("g8_check.check_pressure_directory", return_value={"status": "incomplete"}) as checker, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(g8.main(), 2)
        checker.assert_called_once_with(root)

    def test_incomplete_outage_is_not_a_successful_cli_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = Mock()
            state = {"backend": backend, "directory": Path(temporary)}
            arguments = ["g8.py", "outage", "--binary", "runtime", "--backend", "foundationdb",
                         "--cluster-file", "owned.cluster", "--database-pid", "1",
                         "--database-data", "owned-data", "--database-log", "owned-log",
                         "--out", temporary]
            with patch("sys.argv", arguments), patch("g8.prepare", return_value=state), \
                 patch("g8.database_observer"), \
                 patch("g8_faults.run_outage", return_value={"status": "incomplete"}), \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(g8.main(), 2)
            backend.stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
