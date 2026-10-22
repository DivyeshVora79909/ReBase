#!/usr/bin/env python3
"""Independent numeric oracle. No native arithmetic is used for expectations.

Build examples/exact_values.rs, then pass its executable with --binary. Python's
Fraction and integer rounding operate on unbounded, independently reduced values.
The report is generated evidence, not a list of hardcoded expected native output.
"""

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess

MIN, MAX = -(2**127), 2**127 - 1
MODES = ("toward_zero", "floor", "ceiling", "half_even",
         "half_away_from_zero", "exact")
ROOT = Path(__file__).resolve().parents[2]


def wire(value):
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def expected_apply(value, mode):
    if mode == "exact":
        if value.denominator != 1:
            return {"error": "inexact"}
        rounded = value.numerator
    elif mode == "toward_zero":
        rounded = math.trunc(value)
    elif mode == "floor":
        rounded = math.floor(value)
    elif mode == "ceiling":
        rounded = math.ceil(value)
    elif mode == "half_even":
        rounded = round(value)
    elif mode == "half_away_from_zero":
        rounded = math.floor(abs(value) + Fraction(1, 2))
        if value < 0:
            rounded = -rounded
    else:
        raise AssertionError(mode)
    return {"ok": {"amount": str(rounded)}} if MIN <= rounded <= MAX else {"error": "overflow"}


def cases():
    result = []

    def add(request, expected):
        result.append((request, expected))

    def apply(amount, numerator, denominator):
        rate = Fraction(numerator, denominator)
        for mode in MODES:
            add({"op": "apply", "amount": str(amount), "rational": wire(rate), "rounding": mode},
                expected_apply(amount * rate, mode))

    # The independent library, not the engine's gcd code, chooses wire values.
    for numerator in (MIN, MIN + 1, -101, -2, -1, 0, 1, 2, 101, MAX - 1, MAX):
        for denominator in (1, 2, 3, 10, 100, MAX - 1, MAX):
            add({"op": "construct", "numerator": str(numerator), "denominator": str(denominator)},
                {"ok": {"rational": wire(Fraction(numerator, denominator))}})

    for amount in (MIN, MIN + 1, -10005, -7, -5, -1, 0, 1, 5, 7, 10005, MAX - 1, MAX):
        for numerator in (MIN, -MAX, -10, -1, 0, 1, 10, MAX - 1, MAX):
            for denominator in (1, 2, 3, 10, MAX - 2, MAX):
                apply(amount, numerator, denominator)

    rng = random.Random(20261022)
    for index in range(512):
        amount = rng.randint(MIN, MAX)
        numerator = rng.randint(MIN, MAX) if index % 2 else rng.randint(-10000, 10000)
        denominator = rng.randint(1, MAX) if index % 3 else rng.randint(1, 10000)
        apply(amount, numerator, denominator)

    for denominator in (MIN, -2, -1, 0):
        add({"op": "construct", "numerator": "1", "denominator": str(denominator)},
            {"error": "invalid_input"})
    for amount in ("+1", "01", "-0", "1e0", "1.0", " 1", "1 ", str(MAX + 1), str(MIN - 1), 1, None):
        add({"op": "apply", "amount": amount, "rational": wire(Fraction(1)), "rounding": "exact"},
            {"error": "invalid_input"})
    for rational in (
        {"numerator": "2", "denominator": "4"},
        {"numerator": "0", "denominator": "2"},
        {"numerator": "-0", "denominator": "1"},
        {"numerator": "1", "denominator": "0"},
        {"numerator": "1", "denominator": "-1"},
        {"numerator": "+1", "denominator": "1"},
        {"numerator": "1", "denominator": "01"},
        {"numerator": str(MAX + 1), "denominator": "1"},
        {"numerator": str(MIN - 1), "denominator": "1"},
        {"numerator": "1", "denominator": str(MAX + 1)},
        {"numerator": "1"},
        {"numerator": "1", "denominator": "1", "extra": True},
        {"numerator": 1, "denominator": "1"},
        ["1", "2"],
        ["0", "1"],
        ["1"],
        ["1", "2", "3"],
        None,
    ):
        add({"op": "validate", "rational": rational}, {"error": "invalid_input"})
    add({"op": "apply", "amount": "1", "rational": wire(Fraction(1)), "rounding": "nearest"},
        {"error": "invalid_input"})
    add({"op": "validate", "rational": wire(Fraction(1)), "extra": 1}, {"error": "invalid_input"})
    return result


def verify(observed, expected):
    if observed != expected:
        raise AssertionError(f"numeric mismatch: expected {expected!r}, observed {observed!r}")


def controls():
    # Literal facts check the independent library's interpretation of each mode.
    verify(expected_apply(Fraction(5, 2), "half_even"), {"ok": {"amount": "2"}})
    verify(expected_apply(Fraction(-5, 2), "floor"), {"ok": {"amount": "-3"}})
    verify(expected_apply(Fraction(-5, 2), "half_away_from_zero"), {"ok": {"amount": "-3"}})
    verify(expected_apply(Fraction(MAX * 2), "exact"), {"error": "overflow"})
    verify(expected_apply(Fraction(1, 2), "exact"), {"error": "inexact"})
    # Ensure wrong values, wrong failure classes and malformed shapes are rejected.
    for observed, expected in (
        ({"ok": {"amount": "3"}}, {"ok": {"amount": "2"}}),
        ({"error": "overflow"}, {"error": "inexact"}),
        ({"ok": {"rational": {"numerator": "1"}}}, {"ok": {"rational": wire(Fraction(1))}}),
    ):
        try:
            verify(observed, expected)
        except AssertionError:
            continue
        raise AssertionError("negative control incorrectly accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    controls()
    vectors = cases()
    requests = "".join(json.dumps(request, separators=(",", ":")) + "\n" for request, _ in vectors)
    run = subprocess.run([str(args.binary.resolve())], input=requests, text=True,
                         capture_output=True, timeout=60, check=True)
    lines = run.stdout.splitlines()
    if len(lines) != len(vectors):
        raise AssertionError(f"expected {len(vectors)} responses, got {len(lines)}")
    for index, (line, (request, expected)) in enumerate(zip(lines, vectors)):
        try:
            verify(json.loads(line), expected)
        except (AssertionError, ValueError) as error:
            raise AssertionError(f"case {index}, request {request!r}: {error}") from error
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        "Cargo.toml", "Cargo.lock", "src/values.rs", "examples/exact_values.rs",
        "research/experiments/exact_values.py")}
    report = {
        "format": "rebase-exact-values-oracle-1", "seed": 20261022,
        "cases": len(vectors), "rounding_modes": list(MODES),
        "successes": sum("ok" in expected for _, expected in vectors),
        "rejections": sum("error" in expected for _, expected in vectors),
        "negative_controls": 3, "literal_controls": 5,
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "requests_sha256": hashlib.sha256(requests.encode()).hexdigest(),
        "responses_sha256": hashlib.sha256(run.stdout.encode()).hexdigest(),
        "source_sha256": hashes,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
