from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import population_values as values


class PopulationValueTests(unittest.TestCase):
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "amount": {"type": "string", "pattern": "^(0|[1-9][0-9]{0,8})$"},
            "maybe": {"type": ["string", "null"]},
            "nested": {"type": "object", "properties": {"tag": {"enum": ["a", "b"]}}, "required": ["tag"]},
            "items": {"type": "array", "items": {"type": "integer", "minimum": 2, "maximum": 3}, "minItems": 1, "maxItems": 2},
            "variant": {"oneOf": [
                {"type": "object", "properties": {"left": {"const": True}}, "required": ["left"]},
                {"type": "object", "properties": {"right": {"const": True}}, "required": ["right"]},
            ]},
        },
        "required": ["amount", "nested", "items", "variant"],
        "x-rebase-range": {"strategy": "caller-owned"},
    }

    def _script(self, source: str, directory: Path) -> Path:
        path = directory / "fixture.mjs"
        path.write_text(source, encoding="utf-8")
        return path

    def _request(self) -> bytes:
        return json.dumps({"schema": {"type": "object"}, "count": 1, "seed": 1}).encode()

    def test_seeded_supported_nested_and_polymorphic_generation(self) -> None:
        if shutil.which("node") is None or not values._GENERATOR.is_file():
            self.skipTest("optional Node value provider is not installed")
        first = values.generate_values(self.schema, 25, 94821)
        second = values.generate_values(self.schema, 25, 94821)
        self.assertEqual(first, second)
        self.assertTrue(all(isinstance(row, dict) for row in first))
        self.assertTrue(all(row["nested"]["tag"] in {"a", "b"} for row in first))
        self.assertTrue(all(all(item in {2, 3} for item in row["items"]) for row in first))
        self.assertTrue(all(("left" in row["variant"]) != ("right" in row["variant"]) for row in first))

    def test_explicit_bounds_and_assertion_keyword_preflight(self) -> None:
        with self.assertRaisesRegex(values.PopulationValueError, "count"):
            values._encode_request(self.schema, 129, 1)
        with self.assertRaisesRegex(values.PopulationValueError, "seed"):
            values._encode_request(self.schema, 1, 1 << 32)
        with self.assertRaisesRegex(values.PopulationValueError, "unsupported JSON Schema keyword 'unevaluatedProperties'"):
            values._encode_request({"type": "object", "unevaluatedProperties": False}, 1, 1)
        with self.assertRaisesRegex(values.PopulationValueError, "unsupported generated format 'i64'"):
            values._encode_request({"type": "object", "properties": {"at": {"type": "string", "format": "i64"}}}, 1, 1)
        for malformed_format in ([], {}):
            with self.subTest(format=malformed_format):
                with self.assertRaisesRegex(values.PopulationValueError, "invalid schema at #/format: expected text"):
                    values._encode_request({"type": "string", "format": malformed_format}, 1, 1)
        with self.assertRaisesRegex(values.PopulationValueError, "unsupported JSON Schema keyword 'unevaluatedProperties'"):
            values._encode_request({"type": "object", "additionalProperties": {"unevaluatedProperties": False}}, 1, 1)
        with self.assertRaisesRegex(values.PopulationValueError, "external JSON Schema reference"):
            values._encode_request({"type": "object", "$ref": "https://example.invalid/schema.json"}, 1, 1)
        with self.assertRaisesRegex(values.PopulationValueError, "exceeds 262144 bytes"):
            values._encode_request({"type": "object", "description": "x" * values.MAX_INPUT_BYTES}, 1, 1)

    def test_missing_node_is_clear(self) -> None:
        with mock.patch.object(values.shutil, "which", return_value=None):
            with self.assertRaisesRegex(values.PopulationValueError, "Node.js is unavailable"):
                values.generate_values({"type": "object"}, 1, 1)

    def test_malformed_output_and_missing_package_are_clear(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            malformed = self._script("process.stdout.write('not-json')", directory)
            with self.assertRaisesRegex(values.PopulationValueError, "malformed JSON"):
                values._invoke(self._request(), executable=shutil.which("node") or "node", generator=malformed, timeout=2)

            missing = self._script("import 'json-schema-faker';", directory)
            with self.assertRaisesRegex(values.PopulationValueError, "json-schema-faker 0.6.3 is unavailable"):
                values._invoke(self._request(), executable=shutil.which("node") or "node", generator=missing, timeout=2)

    def test_oversized_stdout_is_capped_before_python_reads_it(self) -> None:
        if os.name != "posix":
            self.skipTest("file-size limits are POSIX-specific")
        with tempfile.TemporaryDirectory() as temp:
            script = self._script(
                "import os\nwhile True:\n    os.write(1, b'x' * 65536)\n",
                Path(temp),
            )
            with self.assertRaisesRegex(values.PopulationValueError, "output exceeds 2097152 bytes"):
                values._invoke(self._request(), executable=sys.executable, generator=script, timeout=2)

    def test_timeout_kills_and_reaps_subprocess(self) -> None:
        if os.name != "posix":
            self.skipTest("process-group cleanup is POSIX-specific")
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            pid_path = directory / "pid"
            script = self._script(
                f"import fs from 'node:fs'; fs.writeFileSync({json.dumps(str(pid_path))}, String(process.pid)); setInterval(() => {{}}, 1000);",
                directory,
            )
            with self.assertRaisesRegex(values.PopulationValueError, "timed out"):
                values._invoke(self._request(), executable=shutil.which("node") or "node", generator=script, timeout=0.2)
            pid = int(pid_path.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_child_limits_are_set_before_exec(self) -> None:
        if os.name != "posix":
            self.skipTest("resource limits are POSIX-specific")
        with tempfile.TemporaryDirectory() as temp:
            script = self._script(
                "import json, resource\nprint(json.dumps([{'fsize': resource.getrlimit(resource.RLIMIT_FSIZE), 'core': resource.getrlimit(resource.RLIMIT_CORE), 'cpu': resource.getrlimit(resource.RLIMIT_CPU)}]))\n",
                Path(temp),
            )
            rows = values._invoke(self._request(), executable=sys.executable, generator=script, timeout=2)
            self.assertEqual(rows[0]["fsize"], [values.MAX_OUTPUT_BYTES + 1, values.MAX_OUTPUT_BYTES + 1])
            self.assertEqual(rows[0]["core"], [0, 0])
            self.assertEqual(rows[0]["cpu"], [16, 17])


if __name__ == "__main__":
    unittest.main()
