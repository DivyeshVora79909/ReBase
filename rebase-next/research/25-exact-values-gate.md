# G3a: exact values at an explicit rounding boundary

**Accepted 2026-10-22.** [Evidence](evidence/2026-10-22-g3a-values.json)
records final execution and fingerprints; [usage](../docs/exact-values.md)
describes the small public API. Historical G2 evidence is unchanged.

## Goal

Implement a small reusable numeric foundation for native accounting models:
bounded signed minor-unit amounts, rational rates and an explicit rounding
choice. Fractional prices, tax rates and exchange ratios must not silently use
floating point or reject a valid result because an intermediate product exceeds
`i128`. This is the first implemented part of G3, not full accounting parity.

Keep the accepted shared mutation engine, model behaviors, store format and
limits unchanged. A rate is ordinary native model input, not a new expression
language, database primitive or second schema registry. Reuse mature exact
arithmetic libraries already present in the dependency graph. Do not add a
decimal scale policy, arbitrary user big integers or a general constraint solver.

## Contract

- `Rational::new(numerator, denominator)` accepts bounded `i128` components,
  requires a positive denominator and reduces the fraction. Zero becomes `0/1`.
- JSON carries canonical decimal **strings**, a positive denominator and a
  reduced fraction. Noncanonical input is rejected, rather than silently
  changing an authored request. Private components preserve the invariant.
- `Rational::apply(amount, rounding)` computes an exact product and rounds once
  to an `i128` minor-unit amount. The six modes are toward zero, floor, ceiling,
  half even, half away from zero, and exact. The last rejects fractional results.
- Final overflow and inexactness have distinct errors. An intermediate product
  can need up to 255 magnitude bits; its bounded exact representation is safe
  even when the correctly rounded result only just fits in `i128`.
- Native Serde and reusable schema helpers share the same enum/field shape.
  JSON Schema describes local shape; native binding enforces exact bounds and
  fraction canonicality. A schema alone does not prove aggregate validity.

The model author decides currency scale, where rounding occurs, tax order,
correction policy and economic invariants. Rounding each line and rounding a
sum can differ. A correction to a rounded calculation is generally the new
calculation minus the old one, rather than rounding the correction alone.

## Acceptance

1. Literal signed, tie, canonicalization and full-width boundary controls.
2. A deterministic independent Python `Fraction` oracle against the native
   JSON adapter, including wide products, invalid wire values and all modes.
3. A test-only compiled model using the shared redb mutation/API path: exact
   wire values, derived amounts, aggregate updates, receipt replay, reopening
   and complete rollback for arithmetic/input/late aggregate failures.
4. Existing debug/optimized Rust checks, independent native/local corpora,
   formatting and warning-denying Clippy. Repeating the unchanged G2 population
   benchmark is unnecessary unless integration changes shared behavior.

Record actual execution and source fingerprints separately from historical
G2 evidence. Checkpoint commits stay on `main`, inside `rebase-next/`.

## Executed result

- Six focused value tests and a real authenticated HTTP/redb test bring the
  complete suite to **63 debug and optimized Rust tests**. Formatting and
  warning-denying Clippy pass. All **116 independent native/local cases**,
  six client controls and three population-oracle controls also pass.
- The Python `Fraction` oracle agrees for **7,396 requests** in each profile:
  4,693 successful results and 2,703 rejections. It covers all six modes,
  signed ties, wide products, final-rounded overflow, canonical wire values,
  deterministic random inputs and literal/negative oracle controls.
- The test-only binding derives `13510798882111490` from the exact wire value
  `9007199254740993 × 3/2` with half-even rounding. Its three-entry sum is
  `13510798882111489`. Eight numeric/input failures and a later aggregate
  `MAX + 1` failure preserve complete application-table observations, revision
  and receipt count, with no success receipt. Replay and reopening agree.
- Acceptance found two issues before completion: Serde's default struct decoder
  also accepted positional arrays, and RPC hid the new `inexact` error behind
  `internal`. Map-only decoding and explicit safe error mapping close them.
  Duplicate/unknown fields still reject. The raw numeric oracle adapter does
  not replace the stricter production request parser.
- Only `values` is new production numeric code; the two existing bindings do
  not use it yet. Their behavior/model identities, store/codec 4, package
  version 0.4.0 and limits remain unchanged. New direct `num-*` dependencies
  were already locked transitively; no dependency versions were added/updated.

This is a tested source checkpoint, not a new packaged release or a capacity
benchmark. Existing G2 workloads were not repeated because neither their model
formulas nor indexing/causal/storage implementation changed. The test binding's
source projection checks are deliberately narrower than the complete shipped
model integrity checkers; full numeric expectations come from the separate
Fraction oracle. No new accounting business model is claimed.

## Next boundary

G3b should define and implement one bounded accounting workflow, including
fractional invoice pricing, ordered tax/tax-on-tax, linked corrections and
settled-payment handling. Preserve the distinction between gross directional
claims and net balance. Establish that policy with an independent source oracle
before coding a full suite. Inherited calculation parameters also need an
explicit native input seam: the current pure evaluator receives its own record
and resolved query values, not arbitrary parent data. Do not conceal reads or
copy mutable parent rules into child inputs to work around that boundary.

Broader query/monoid support, effects, distributed adapters, frontend and
unrestricted capacity remain separate gates. G3a completion cannot certify them.
