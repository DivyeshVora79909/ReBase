"""Bounded optional JSON Schema value generation through json-schema-faker.

The provider only generates base authored fields. It does not implement ReBase
annotations or native model rules; callers must apply explicit strategies and
validate the completed values before proposing mutations. The subprocess uses
trusted local schemas and bounded input, output, CPU and wall time; these controls
are not a full memory sandbox for hostile schemas or a compromised Node runtime.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


MAX_INPUT_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_COUNT = 128
MAX_SEED = (1 << 32) - 1
TIMEOUT_SECONDS = 15
_MAX_STDERR_BYTES = 64 * 1024
_GENERATOR = Path(__file__).with_name("schema-values") / "generate.mjs"


class PopulationValueError(ValueError):
    """The optional value provider could not safely produce a bounded batch."""


# This is deliberately a generation allowlist, not a JSON Schema validator.
# Unsupported assertion keywords fail before reaching json-schema-faker, which
# otherwise may ignore a keyword and generate values under a weaker schema.
_ASSERTIONS = frozenset(
    {
        "$schema", "$id", "$ref", "$defs", "definitions", "$comment",
        "type", "enum", "const", "minimum", "maximum", "exclusiveMinimum",
        "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "pattern",
        "format", "minItems", "maxItems", "uniqueItems", "items",
        "additionalItems", "properties", "patternProperties", "additionalProperties",
        "required", "minProperties", "maxProperties", "allOf", "anyOf", "oneOf",
    }
)
_ANNOTATIONS = frozenset({"title", "description", "default", "examples", "readOnly", "writeOnly", "deprecated"})
_SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions"})
_SCHEMA_LISTS = frozenset({"allOf", "anyOf", "oneOf"})
_CHILD_SCHEMAS = frozenset({"items", "additionalItems", "additionalProperties"})


def _preflight(schema: Any) -> None:
    if not isinstance(schema, dict):
        raise PopulationValueError("value provider requires an object JSON Schema")

    def visit(node: Any, path: str) -> None:
        if isinstance(node, bool):
            return
        if not isinstance(node, dict):
            raise PopulationValueError(f"invalid schema at {path}: expected an object")
        for key, value in node.items():
            if not isinstance(key, str):
                raise PopulationValueError(f"invalid schema at {path}: keyword is not text")
            if key in _SCHEMA_MAPS:
                if not isinstance(value, dict):
                    raise PopulationValueError(f"invalid schema at {path}/{key}: expected an object")
                for child_key, child in value.items():
                    visit(child, f"{path}/{key}/{child_key}")
            elif key in _SCHEMA_LISTS:
                if not isinstance(value, list):
                    raise PopulationValueError(f"invalid schema at {path}/{key}: expected an array")
                for index, child in enumerate(value):
                    visit(child, f"{path}/{key}/{index}")
            elif key in _CHILD_SCHEMAS:
                if isinstance(value, list):
                    for index, child in enumerate(value):
                        visit(child, f"{path}/{key}/{index}")
                else:
                    visit(value, f"{path}/{key}")
            elif key not in _ASSERTIONS and key not in _ANNOTATIONS and not key.startswith("x-"):
                raise PopulationValueError(
                    f"unsupported JSON Schema keyword {key!r} at {path}; "
                    "supply an explicit field strategy or a schema using supported keywords"
                )
            elif key == "format" and not isinstance(value, str):
                raise PopulationValueError(f"invalid schema at {path}/format: expected text")
            elif key == "format" and value not in {
                "date", "date-time", "time", "email", "hostname", "ipv4", "ipv6", "uri", "uri-reference", "uuid"
            }:
                raise PopulationValueError(f"unsupported generated format {value!r} at {path}")
            elif key in {"$ref"} and not isinstance(value, str):
                raise PopulationValueError(f"invalid schema at {path}/{key}: expected text")
            elif key == "$ref" and not (value == "#" or value.startswith("#/")):
                raise PopulationValueError(
                    f"external JSON Schema reference {value!r} at {path} is unsupported; "
                    "use a self-contained schema with fragment-only references"
                )

    visit(schema, "#")


def _encode_request(schema: Any, count: int, seed: int) -> bytes:
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_COUNT:
        raise PopulationValueError(f"count must be an integer in 1..{MAX_COUNT}")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= MAX_SEED:
        raise PopulationValueError(f"seed must be an integer in 0..{MAX_SEED}")
    _preflight(schema)
    try:
        encoded = json.dumps(
            {"schema": schema, "count": count, "seed": seed},
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PopulationValueError(f"schema is not JSON serializable: {exc}") from exc
    if len(encoded) > MAX_INPUT_BYTES:
        raise PopulationValueError(f"provider input exceeds {MAX_INPUT_BYTES} bytes")
    return encoded


_RESOURCE_LAUNCHER = r"""
import os, resource, sys
file_limit = int(sys.argv[1])
cpu_soft, cpu_hard = int(sys.argv[2]), int(sys.argv[3])
resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))
command = sys.argv[4:]
os.execvpe(command[0], command, os.environ)
""".strip()


def _invoke(
    request: bytes,
    *,
    executable: str,
    generator: Path,
    timeout: float,
    executable_args: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    if os.name != "posix":
        raise PopulationValueError("bounded Node provider currently requires POSIX file-size limits")
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    _RESOURCE_LAUNCHER,
                    str(MAX_OUTPUT_BYTES + 1),
                    "16",
                    "17",
                    executable,
                    *executable_args,
                    str(generator),
                ],
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd=str(generator.parent),
                start_new_session=True,
            )
        except OSError as exc:
            raise PopulationValueError(f"could not start Node value provider: {exc}") from exc
        try:
            process.communicate(input=request, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise PopulationValueError(f"Node value provider timed out after {timeout:g}s") from exc
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        stdout_file.seek(0, os.SEEK_END)
        output_size = stdout_file.tell()
        if output_size > MAX_OUTPUT_BYTES:
            raise PopulationValueError(f"Node value provider output exceeds {MAX_OUTPUT_BYTES} bytes")
        if process.returncode != 0:
            stderr_file.seek(0)
            detail = stderr_file.read(_MAX_STDERR_BYTES).decode("utf-8", "replace").strip()
            if "ERR_MODULE_NOT_FOUND" in detail or "Cannot find package" in detail:
                raise PopulationValueError(
                    "json-schema-faker 0.6.3 is unavailable; run npm ci --ignore-scripts "
                    "in tools/schema-values"
                )
            raise PopulationValueError(
                f"Node value provider failed (exit {process.returncode})"
                + (f": {detail[:1000]}" if detail else "")
            )
        stdout_file.seek(0)
        raw = stdout_file.read(MAX_OUTPUT_BYTES + 1)
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PopulationValueError(f"Node value provider returned malformed JSON: {exc}") from exc
    if not isinstance(result, list) or len(result) == 0 or any(not isinstance(row, dict) for row in result):
        raise PopulationValueError("Node value provider output must be a nonempty array of objects")
    return result


def generate_values(schema: Any, count: int, seed: int) -> list[dict[str, Any]]:
    """Generate one deterministic, bounded batch of object values.

    `x-*` keys are annotations for JSON Schema generation. In particular,
    `x-rebase-binding` and `x-rebase-range` are not enforced here; callers must
    satisfy their native meaning with explicit strategies/rules.
    """
    request = _encode_request(schema, count, seed)
    executable = shutil.which("node")
    if executable is None:
        raise PopulationValueError("Node.js is unavailable; install Node to use the optional value provider")
    if not _GENERATOR.is_file():
        raise PopulationValueError(f"value provider script is missing: {_GENERATOR}")
    values = _invoke(
        request,
        executable=executable,
        generator=_GENERATOR,
        timeout=TIMEOUT_SECONDS,
        executable_args=("--max-old-space-size=64",),
    )
    if len(values) != count:
        raise PopulationValueError(f"Node value provider returned {len(values)} values for requested count {count}")
    return values
