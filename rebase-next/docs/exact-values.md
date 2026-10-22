# Exact values for native model authors

`values::{Rational, Rounding}` provides exact multiplication and an explicit
rounding boundary. Amounts are signed `i128` minor units. A rate is a reduced
fraction with a positive denominator. No floating-point conversion occurs.

```rust
use rebase_semantic_proof::values::{Rational, Rounding};

// USD 100.05 at 10%; the model chooses minor units and this rounding point.
let tax = Rational::new(10, 100)?.apply(10_005, Rounding::HalfEven)?;
assert_eq!(tax, 1_000);

// A conversion ratio can use the same primitive.
let converted = Rational::new(107, 100)?.apply(12_345, Rounding::HalfEven)?;
assert_eq!(converted, 13_209);
```

The ordinary constructor reduces `10/100` to `1/10`. Serde input is stricter:
the wire value must already be reduced. This prevents canonical binding from
silently changing a request's authored value. JSON uses strings:

```json
{"numerator":"1","denominator":"10"}
```

Use `Rational::schema()` inside the model's schema and `Rounding::schema()` for
an authored rounding choice. The same native types validate the value; do not
copy the schema into a separate tool-only file. Schema validation covers the
closed object, strings and lexical patterns; native binding also verifies
`i128` bounds, positive denominator and reduction. Zero is always `0/1`.
Neither local validation nor this numeric primitive proves global tree rules.

| Mode / wire name | Meaning | `+2.5` | `−2.5` |
| --- | --- | --- | --- |
| `TowardZero` / `toward_zero` | Drop the fractional part | 2 | −2 |
| `Floor` / `floor` | Round toward negative infinity | 2 | −3 |
| `Ceiling` / `ceiling` | Round toward positive infinity | 3 | −2 |
| `HalfEven` / `half_even` | Nearest; ties choose the even integer | 2 | −2 |
| `HalfAwayFromZero` / `half_away_from_zero` | Nearest; ties increase magnitude | 3 | −3 |
| `Exact` / `exact` | Reject a fractional minor unit | `inexact` | `inexact` |

`apply` computes the product exactly and checks the **rounded final result**
against `i128`. An out-of-range result returns `overflow`; a bad constructor
denominator returns `invalid_input`. No saturating or wrapping arithmetic is
used. Bounded inputs need at most 255 magnitude bits for their product; mature
`num-bigint` arithmetic handles it. Those crates were already transitive
dependencies and are now explicit dependencies of this module.

The snippets assume a native calculation returning `native_slice::Result`.
These functions are pure and hold no database, caches or mutable global state.
Use them in a binding's trusted calculation, then let the shared transaction
engine maintain the declared roots and enforce aggregate invariants. There is
no new production JSON-RPC method, CLI command or business-model registry.
Per-value work depends on the bounded integer width, not on the record count.
Big-integer allocation and fraction reduction add cost compared with a native
integer multiply; this checkpoint establishes correctness, not a throughput
benchmark. It does not change tree or causal-closure complexity.

Rounding and accounting policy remain explicit model decisions. Three lines of
0.5 rounded individually with half-even sum to 0, while their combined 1.5
rounds to 2. A correction should generally use the difference between the new
and old rounded calculations. Currency scales, legal tax rules, chronological
bases, claims and refunds need their own model contracts.

## Reproduce the independent arithmetic check

From `rebase-next/`, with the pinned Rust toolchain:

```sh
cargo build --locked --example exact_values
python3 -B research/experiments/exact_values.py \
  --binary target/debug/examples/exact_values \
  --out target/exact-values-oracle.json
cargo test --locked --test exact_values
```

If `CARGO_TARGET_DIR` is set, use that directory's example executable instead.
The JSON-lines example is an oracle adapter, not a second arithmetic API.
Python's `Fraction` derives expectations independently. The test-only compiled
binding exercises integration without adding a third shipped business model.
See [the G3a gate](../research/25-exact-values-gate.md) for scope and continuation.
