# G3c: bounded invoicing and cumulative tax reassessment

**Accepted 2026-10-22.** [Evidence](evidence/2026-10-22-g3c-invoicing.json)
records final execution, identities and fingerprints. See [usage](../docs/invoicing.md).

## Goal

Ship a small third compiled model through the existing backend and tools, using
G3a exact values and G3b typed parent parameters. Demonstrate fractional line
pricing, chronological tax/tax-on-tax, explicit monetary credits, historical
edits, exact rollback and independent source-derived checking. This preserves
capability through a different model rather than porting the old all-in-one
schema. Work stays in `rebase-next/`, on `main`.

Settlement, refunds, cash and directional claims enter G3d after this checkpoint.
Do not imply that a monetary credit is a quantity-return pricing policy or that
invoice-level reassessment reproduces the old source-specific tax linkage graph.

## Native contracts

| Public contract | Responsibility |
| --- | --- |
| Invoice `101` | Immutable currency; nonnegative complete-time base/gross roots `7/13`. |
| Issue `211` | Invoice, time, nonnegative fractional quantity, unit price in integer minor units, rounding; credit-capacity root `17`. |
| Credit `307` | Same Invoice and original Issue, time, positive authored minor-unit credit; three negative direct memberships. |
| TaxRule `401` | Invoice, mutable `base/net` kind, nonnegative rational rate and rounding; assessed-history root `19`. |
| Assessment `509` | Invoice and rule, time; cumulative desired tax less this rule's earlier assessed total. |

Invoice references on Issue/Credit/TaxRule/Assessment, Credit's Issue reference
and Assessment's Rule reference are immutable dimensions in this first model.
Validate cross-parent agreement. No copied mutable rate columns or hidden
multihop reads. Query slots `31/37/41` select the appropriate Invoice basis and
the rule's earlier assessed history. Both are strictly before the assessment
time; simultaneous records are excluded together.

For prior assessed total `A` at time `t`:

```text
base rule: delta = round(invoice.base_before(t) × rate) − A
net rule:  delta = round((invoice.gross_before(t) − A) × rate) − A
```

Subtracting `A` from the net basis avoids taxing the rule's own prior assessment
again. Assessment times must be unique within a rule. Fixed zero outputs remain
real declared roles. New later credit does not rewrite earlier assessments;
explicit later assessments produce correction deltas. Historical input edits
recalculate the affected existing assessments through the shared scheduler.

Private roles `11/13/17/19` map to four single-membership contracts
`901/902/903/904` for Invoice base/gross, Issue capacity and Rule assessed.
Issue emits three roles; Assessment emits two. Credit itself participates in
three trees. Every relevant root has a nonnegative complete-time invariant.
Assess changed output neighbours for duplicate rule times rather than scanning
the table on each write. No shared tree/codec redesign is needed.

## Independent acceptance

Use one currency with an explicit minor unit. A line at time `0` has quantity
`3/2`, price `6670`, half-even amount `10005`. Base rule `1/10` assessed at `10`
gives `1000`; net rule `1/20` assessed at `20` gives `550`. Gross is **11555**.
A linked monetary Credit of `2001` at `50`, base reassessment at `51` and net
reassessment at `52` give deltas `−200/−110`, base **8004**, taxes **800/440**
and gross **9244**. No payment is asserted in this checkpoint.

Verify historical quantity/price/rule edits, equal-result and zero outputs,
strict/inclusive boundaries, duplicate rule times, reference agreement,
overcredit, inexactness, overflow, receipt replay, complete rollback, reopening
and backup/restore. The production checker reconstructs chronological source
histories before comparing complete memberships, outputs, queries and native
structure. A separate Python `Fraction` oracle validates source arithmetic
against actual authenticated HTTP mutations/queries and the developer fixtures.
Do not use maintained output amounts to derive expected values.

The first invoicing envelope is **64 public sources /256 outputs /512 retained
roles**, within existing engine limits. Test its boundaries without changing
global capacity or implying that G2's larger workload certification covers this
new model. Keep the work budget and all independent limits explicit.

After verified implementation, commit/push G3c and continue to G3d's settlement
and refund history. Frontend, distributed adapters, arbitrary aggregates,
general two-bound queries, full accounting parity and dated rational FX remain
separate capabilities.

## Executed result

- Version **0.5.0** adds `--model invoicing`, its nine contracts, shared-schema
  developer views, and two repeatable fixture recipes. Native calculation,
  ordered aggregation, dependency selection, authority, receipts and redb
  lifecycle remain the same engine. Calculation/equipment model identities and
  store/codec 4 are unchanged. Invoicing behavior is `invoice-assessments-1`.
- **72 debug and optimized Rust tests**, formatting and warning-denying Clippy
  pass. Five native invoicing tests cover both fixture recipes, literal totals,
  historical/rule edits, zero outputs, query topology changes, eleven complete
  rejection rollbacks, replay/reopen and producer/root deletion. A separate
  checker control corrupts derived/private values, query caches, tree heights
  and selector nodes and rejects each altered image.
- All **116 independent native/local cases**, six client controls, three
  population-oracle controls and four new invoicing-oracle controls pass.
- The optimized authenticated HTTP workflow matches Python `Fraction` source
  expectations across **58 mutations /200 source commands**: **51 commits** and
  **seven rejections**. Forty seeded batches shuffle price, quantity, credit
  dates/amounts, rate, rounding and rule kind. Every accepted state is checked
  against complete public source/derived values and source-derived root totals;
  strict time boundaries and zero contributions are exercised explicitly.
- The workflow verifies literal gross **11555 → 9244**, fills **64 public
  sources**, rejects the 65th, checks receipt absence/replay, graceful reopening,
  acknowledged crash recovery and verified restore. Final complete integrity is
  valid with 77 total records, 16 data nodes and 113 roots. This profile does not
  claim G2's larger invoicing capacity or exhaustive authority/workload coverage.
- A copied source directory outside Git builds through its explicit manifest
  using the shared Cargo cache and produces the **identical optimized binary**.
  Its copied Python tools pass the same 58-scenario HTTP workflow. It uses no
  original ReBase runtime imports; this is not a clean-cache compilation claim.

During verification, accumulated debug incremental artifacts filled the cloud
workspace and caused linker/file-write failures. Removing only the generated
incremental cache and setting `CARGO_INCREMENTAL=0` restored the full successful
checks. Source, evidence and database observations were retained. An initial
oracle comparison also included the native enum tag, which public projection
correctly omits; the oracle now compares the declared published fields. Neither
incident changes accepted runtime semantics.

The source checkpoint has no new general accounting framework or arbitrary data
generator. Full original tax linkage, quantity-credit pricing, settlement,
counterparty books and FX remain outside this accepted model. Commit/push this
result, then implement G3d's explicit payment/refund history with its own source
oracle and historical-balance controls.
