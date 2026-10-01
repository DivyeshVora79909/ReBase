# All-in-accounting implementation plan

Current direction, 2026-09-29: the [revised blueprint](./blueprint.md) and
[implementation handoff](./implementation-handoff.md) supersede this plan's
compulsory organization/book assumption, one-effect-per-record interpretation,
and blanket omission of a historical net summary. Follow the new bounded
packets; do not restart the engine prerequisites already proved. Accounting,
logistics, exchange and basic assembly planning is active; CRM/HRM remains
future scope. K4/K5 core stabilization passed on the recorded snapshot; H1
and H2 are implemented for the target all-in-accounting profile, with
focused evidence at
[`2026-09-29-h1-identity.json`](../rebase-system/evidence/2026-09-29-h1-identity.json)
and [`2026-09-29-h2-effects-net.json`](../rebase-system/evidence/2026-09-29-h2-effects-net.json).
H3a sale-side variable tax outputs and H3b purchase-receipt settlement passed;
H3c bounded ancestry passed in a disposable fixture; H4a and H4b1's published
invoice-line aggregate basis and H4b2's finite compound tax dependency passed.
H4b3 assessment and recoverable-credit recognition passed its scoped fixture;
see [evidence](../rebase-system/evidence/2026-09-29-h4b3-purchase-tax-credit-recognition.json).
H2's immediate assessed tax receivable remains; H4b3 tracks eligible/usable
recognition separately without duplicating that receivable.
H4b4a payer-side supplier withholding passed; see
[evidence](../rebase-system/evidence/2026-09-29-h4b4a-supplier-withholding.json).
H4b4b customer-withheld TDS passed; see
[evidence](../rebase-system/evidence/2026-09-29-h4b4b-customer-withholding.json).
H4b5a paired claim offset passed its scoped fixture; see
[evidence](../rebase-system/evidence/2026-09-29-h4b5a-claim-offset.json).
H4b5b treasury-backed remittance passed; see
[evidence](../rebase-system/evidence/2026-09-29-h4b5b-tax-remittance.json).
H4b5c residual policy remains future/unresolved. H5a's complete-timestamp
stock floor, H5b physical return, and H5c standalone receivable cash refund
passed their scoped gates. H6a ordered resource-pair identity and entered-
quantity currency exchange passed; H6b quote-derived currency exchange also
passed. H7 immediate assembly passed its bounded schema/probe and regression
gates; see [H7 implementation evidence](../rebase-system/evidence/2026-09-29-h7-immediate-assembly.json)
and separate [gross-input feasibility evidence](../rebase-system/evidence/2026-09-29-h7-gross-input-feasibility.json).
H8 timed production passed its bounded integration schema/probe and H5/H6/H7/core regression gates; see [H8 integration evidence](../rebase-system/evidence/2026-09-29-h8-timed-production-integration.json) and the earlier [pre-code feasibility evidence](../rebase-system/evidence/2026-09-29-h8-production-feasibility.json).
The run has no writable `end_at`; managed roles compute it from `planned_start + immutable duration` because SurrealDB 3.2.0 rejects READONLY projection refresh and permits writable VALUE override. This is not a production migration. Workforce and costing remain out of scope.
The completed H5a/H5b/H5c/H6a/H6b/H7/H8 packet sequence and its limits are
recorded in the [implementation handoff](./implementation-handoff.md#h5-shared-capacities-returns-refunds-and-logistics).
TCS at invoice time remains on
the existing sales tax-component path; no cash-time duplicate TCS output is
routed. H4b4a's recorded package fingerprint is historical after H4b4b added
its probe script; H4b4a was rerun successfully in H4b4b's regression sequence.
H4b4b's evidence fingerprints identify its recorded checkpoint; do not rewrite the prior
H4b4a evidence artifact.
The H1 migration fixture is bounded; a full populated legacy profile
cutover remains open and must not be inferred from the fixture.

## Recorded implementation baseline and acceptance matrix

The following is historical evidence and retained acceptance detail, not proof
of the revised schema. A1a-A1d identity/dimensions, movements/FX,
standalone claims, and dated opening facts complete the A1 probe gate. A2a-A2d
signed adjustments, cash allocations, issue-date invoice pricing, and required
invoice-line lifecycle are implemented and probed; the rest of claims/documents
and later phases remain open.
Baseline inspected:
`46f0617`, 2026-09-24. This is the accounting/resource module plan within the
wider [ReBase system blueprint](../rebase-system/README.md). It does not claim
that its proposed schema or engine extensions already exist.

## 1. Findings that determine the design

| Current implementation | Consequence for the new suite |
|---|---|
| [Temporal contract](../../research/rebase/temporal-trees.md): intrusive AVL, explicit memberships, associative summaries, declared dependencies, synchronous rollback. | Reuse the AVL mechanics and native transaction boundary. Compiler/runtime simplification now follows the wider [foundation redesign](../rebase-system/plan.md); no second calculation service is required. |
| [Account schema](../all-in-one/accounts/schema.surql) distinguishes `tax_asset`, `tax_receivable`, and `tax_payable` identities. | Replace role-based tax identity splitting with one tax identity and separate typed claim effects. |
| [Money helpers](../all-in-one/accounts/money.surql) carry a large common context containing invoice, claim, allocation, parent, and FX alternatives. | Give each concrete recipe only its required fields and projections. Keep simple real movement independent of billing. |
| [Delivery helper](../all-in-one/accounts/logistics.surql) projects stock, unit activity, original capacity, invoice, both parties, and tax state. | Compose real resource movement and independent claim effects. Maintain unit/ancestor trees only for a stated invariant or query. |
| [Invoice schema](../all-in-one/accounts/billing.surql) assumes two modeled parties and a specific line-before-issue policy. | Scope postings to the direct economic entity (user or organization); keep invoice grouping and counterparty identity explicit. Cross-entity composition is a concrete optional recipe, not a compulsory book. |
| [Tree contract](../../src/tree-contract.js) and [storage generator](../../src/generators/tree.js) require finite owner targets and generate exact table/slot pair checks. | C1 narrows structural links; C2a/b verify multiple positions and complete-time summaries. No performance improvement is inferred from these correctness proofs. |
| [Runtime](../../src/temporal.surql), `coalesce` and `sync`: distinct protected slots from one source can contribute multiple positions to one owner tree. | C2a covers distinct keys, same-key netting, linked-slot deletion, mutation, and rollback. Accounting-specific interval lifecycle remains in the acceptance cases below. |
| Runtime `member`: ordering remains `[effective_at, id, slot]`; summaries retain strict event prefixes and add complete-primary boundary extrema. | C2b verifies simultaneous release/use, direct range reconstruction, and guarded rollback. Accounting-specific historical/window policies remain to be checked. |
| Generator `dependencies`: a membership table cannot directly consume a referenced root summary. | Use a tree-less published-basis record for aggregate-derived outputs. This is already supported, not a new annotation. |
| Runtime `refresh` propagates to existing dependents; `finish` validates the source closure. | Generic source-owned required-output lifecycle passed C2c; accounting-specific paired recipes still need the acceptance cases below. |
| Source events validate after each business statement, not after arbitrary SQL transaction batches. | `BEGIN/COMMIT` alone does not make an invalid intermediate business statement acceptable. |

These are differences from the requested architecture, not claims that the old
suite's existing tested behavior is broken. Earlier replay/state-lane research
is historical; the current temporal contract is the baseline.

The inspected source declares six slots for `payment`, nine for `settlement`,
eight for `delivery`, nine for `delivery_adjustment`, seven for `delivery_charge`,
and thirteen for `money_adjustment`/`money_refund`. These are declared maxima,
not active counts. The [measured baseline](../../research/rebase/write-amplification-results.md)
sampled four active memberships for a payment and five for a charge/refund.
That historical pre-C4 profile reported 49 compiled tables; the current profile
builds 48 after removing the separate `change_logs` table. Forty-four tables
are declared directly in the profile.

The [current handoff](./implementation-handoff.md) owns new domain execution
order. The wider [system plan](../rebase-system/plan.md) retains C1–C4 history;
A/B/C/D below preserve detailed accounting acceptance cases mapped to C2.

## 2. Engine feasibility gates

The shared C2a/b tree capabilities and generic C2c required-output lifecycle
are implemented and probed. The cases below remain the accounting-module
acceptance matrix before this proposed suite can promise interval, rolling, or
paired-recipe integrity. Keep existing event-prefix behavior working.

### A. Multiple dated positions from one record into one owner

The shared membership contract now coalesces `(record, owner, timestamp)` while
retaining distinct slots at different timestamps. The C2a
probe verifies this general engine behavior. The cases below retain
accounting-specific lifecycle and history coverage.

Required cases:

- Insert an interval's two positions, edit both dates/weight, move its owner,
  and delete it, comparing against independent dated sources.
- Cover rotations/transplants where the two positions are adjacent, ancestor
  and descendant, root and child, or share a deleted source record.
- Preserve same-time same-owner netting, exact dimensions, slot uniqueness,
  prefix-consumer causal-slot rules, and owner revision fencing.
- Publish and validate only after all old/new positions and ordinary descendants
  are repaired. A failed end-date change must restore both positions and source.
- Keep temporal-sweep topology restrictions explicit; this extension does not
  authorize a prefix consumer to move earlier while a sweep is running.

### B. Complete-timestamp prefix extrema

The shared runtime implements the [boundary summary algebra](./blueprint.md#complete-timestamp-extrema)
alongside the current prefix fields. Generated summary types, merge,
empty/singleton handling, and the independent oracle are updated and checked in
C2b. The cases below retain accounting-specific policy coverage.

Required cases include equal-time starts/releases in either ID order, many ties
across rotations, capacity changes at interval boundaries, zero-length interval
rejection, empty history, date edits merging/splitting timestamp groups, and
historical/future violations whose final totals still look valid.

The algebra was checked locally using sequences of length 1–5, deltas
`{-2, 0, 3}`, successive time gaps `{0, 1}`, and randomized binary folds/splits.
Result: 4,665 sequences and 92,565 associativity checks passed. Another 3,000
weighted interval and 3,000 fixed-window cases passed direct reconstruction;
the deterministic random seed was `240924`. C2b also passes 5,442 present/absent
measure sequences and 61,386 binary folds, plus compiled adjacent-interval,
range, capacity, and rollback cases. These engine proofs do not replace the
broader accounting-specific matrix below or establish write cost and throughput.

### C. Atomic lifecycle for required dependent outputs

The generic engine path passed C2c with a compiled source-owned recipe fixture.
Before this accounting suite relies on it, verify allocated refunds, paired
offsets, withholding compositions, and generated production outputs with the
accounting-specific schemas and source oracles.

Contract:

1. A normal typed source record supplies the authorized inputs and selects a
   concrete schema-owned recipe. No caller supplies executable table/field names.
2. Required output identities are stable and unique per source and role.
   Their calculated fields and lifecycle are protected from independent client
   writes. Optional user-entered dependent edges remain a separate supported path.
3. Materialization, ordinary dependency refresh, tree repair, and any removal
   of obsolete outputs settle before the operation's final guards run.
4. There is no observable partial set of mandatory outputs, duplicate retry,
   orphan on deletion, or client-controlled validation-disable switch.
5. All source/child/owner changes roll back together on failure. Authorization,
   same-book/dimension checks, native references, and audit boundaries remain intact.

The C2c fixture confirms child events do not independently finish the recipe;
each child refreshes inside the outer source operation, and final publication
and validation occur after the complete required set is reconciled. It also
checks record-user privacy, stable identities, source deletion, populated
reapplication, and atomic final-guard rollback. Accounting recipes still need
to prove their dimensions, authorization, and audit boundaries against their
own complete snapshots. Reuse the existing refresh work representation; avoid
another runtime queue or generic workflow service.

Optional independent postings can be created with current primitives. Native
group references alone do not prove a complete accounting recipe; retain its
creation, mutation, and deletion cases as module acceptance checks.

### D. Aggregate-to-output causality and editable future dates

Use supported tree-less basis records and separate input/output scopes. Prove
parent input edits publish the complete basis, refresh output amount/time, move
all output positions, and validate downstream histories in one source operation.
Include diamond-shaped dependencies, two input roots changing together, unchanged
rounded outputs, and an attempted feedback cycle. Do not infer causality from
AVL parent pointers or bypass compiler dependency diagnostics.

## 3. Module layout

The following is the target implementation layout. `core/schema.surql`, the
cash/stock movement sources, `claims/standalone.surql`,
`claims/adjustments.surql`, the initial `claims/settlements.surql` and
`claims/invoices.surql` slices, and the focused core probe are implemented.
The other entries remain planned. Keep executable probe fixtures outside the
profile's recursively compiled material.

```text
designs/all-in-accounting/
  README.md, blueprint.md, plan.md, implementation-handoff.md, context-map.md
  core/schema.surql                 economic entities and shared identities
  movements/cash.surql              cash in/out/transfer and required FX variant
  movements/stock.surql             resource in/out/transfer
  movements/purchase-receipt.surql   H2 stock, supplier payable, assessed tax receivable and invoice effects
  claims/standalone.surql           explicit receivable and payable entries (implemented)
  claims/adjustments.surql          signed same-family corrections (implemented)
  claims/receivables.surql          priced and real-dependent receivable recipes
  claims/payables.surql             priced and real-dependent payable recipes
  claims/settlements.surql          cash allocations (initial slice implemented); restorations and offsets remain planned
  claims/invoices.surql             issue-date sale/purchase groups, priced lines, and cash allocations (initial slice implemented)
  documents/schema.surql            invoice variants and correction scopes
  calculations/schema.surql         native rules, parent/prefix/aggregate bases
  limits/schema.surql               interval, rolling and calendar limits
  operations/logistics.surql        fulfillment, reservations and returns
  operations/work.surql             service and work-order compositions
  operations/manufacturing.surql    recipe requirements, inputs and future outputs
  valuation/schema.surql            explicit dated value and cost projections

dev-tools/accounting/
  probe.js                         compiled profile integration runner
  oracle.js                        independent reconstruction from authoritative data
  fixtures/                        deterministic scenario inputs
```

Use small native functions for repeated algebra and guards. Author concrete
tables explicitly with required typed fields; avoid another all-purpose context
object with many empty alternatives. Initially use ordinary SurrealQL and the
current compiler. A development-time emitter is justified only if measured
mechanical repetition remains substantial, and must emit inspectable native
schema deterministically without introducing a runtime interpreter.

Adding specialized dependent tables is expected. There is no target of exactly
twelve or sixteen total tables and no target of fewer tables than the old suite.
The targets are understandable contracts, fewer unnecessary projections, and
less total reactive work for equivalent behavior.

Checkpoint A1a (identity and dimension core, 2026-09-26): `core/schema.surql`
defines separate economic organization and book identities; immutable currency
precision and resource units; treasury, tax, miscellaneous, and claim
dimensions; operating units; and distinct item/service/work-type identities.
Unique indexes fence treasury, claim, and stock-account dimensions. Native
validation rejects a treasury/book organization mismatch and a stock account
whose operating unit belongs to another book organization. A stock account's
unit is derived from its resource, so it cannot drift from the referenced
item/service/work type. The fast `probe:accounting-core` exercises these guards,
dimension uniqueness, allowed claim-opponent record types, precision
immutability, reference-protected deletion, derived units, and a signed
minimum-balance floor. `build:all-in-accounting`, `check:all-in-accounting`,
native schema validation, and the focused probe pass. This checkpoint covered
the identity foundation only; movement posting, claim history, FX, and source
reconstruction were added in A1b/A1c.

Checkpoint A1b (movement and FX core, 2026-09-26): `movements/cash.surql` and
`movements/stock.surql` define six typed cash/stock movement tables, covering
the twelve endpoint directions. Cash and stock account roots enforce their
configured minimums and dimension tags. Required FX quotes capture currency
precision, enforce effective time, round at destination precision, retain the
residual, and track quote use. `probe:accounting-core` reconstructs cash and
stock balances from source rows and covers inserts, edits, deletes, invalid
dimensions, floor rollback, and quote guards.

Checkpoint A1c (standalone claims, 2026-09-26): `claims/standalone.surql`
adds explicit positive receivable and payable postings to dated claim history.
The focused probe checks source-row reconstruction, read-time
`receivable - payable`, insert/edit/delete repair, and rejection of a posting
whose book differs from its claim account. Corrections, settlements, and paired
output recipes remain open.

Checkpoint A1d (dated opening facts and A1 exit, 2026-09-26): the blueprint's
opening cash, stock, and claim facts use the ordinary `cash_in`, `stock_in`,
`receivable`, and `payable` dated posting tables. No editable opening-balance
field or parallel opening table was added. Before-cutoff tree reads at the
opening date match direct source-row scans, and an earlier cutoff excludes the
opening facts. This satisfies phase 2's opening-fact requirement and closes A1.

Checkpoint A2a (signed claim adjustments, 2026-09-26):
`claims/adjustments.surql` adds separate receivable and payable adjustment
tables. Each signed delta stays in its original family, must be nonzero, and
must use the claim account's book. The probe confirms history reconstruction,
read-time netting, and rollback when an adjustment would make outstanding
claims negative.

Checkpoint A2b (initial cash settlement allocations, 2026-09-26):
`claims/settlements.surql` adds distinct receivable-from-cash-in and
payable-from-cash-out allocations. Each allocation contributes a negative
delta to its claim history and positive dated use to both its source cash pool
and target claim capacity. The probe reconstructs all three histories from
allocation rows; covers multiple receipts/payments across claims; checks source
and target over-allocation, book/party/currency mismatches, date dependency,
and rollback; and passes in 8.43 seconds. Schema build, compiler check, and
native validation passed after the schema additions. Refund restoration,
non-cash offsets, mandatory paired recipes, and the broader billing/resource
work remain open.

Checkpoint A2d (required invoice-line lifecycle, 2026-09-26):
`claims/invoices.surql` adds issue-date sales and purchase groups, priced lines
from `stock_out`/`stock_in`, and cash allocations against each group's
outstanding amount. Line amount is derived from billed quantity and unit price
at the invoice currency's precision. The source movement's `z_billing` root
limits quantity shared across invoices; the invoice root prevents oversettling;
cash allocations share the original source pool with standalone claims.
Derived dates and amounts remain refreshable when their inputs change. The
48-table profile passed build, compiler check, native validation, and the
focused disposable probe (~16 seconds). A separate issue source requires a
nonempty line set; C2c stable source/role outputs create, refresh, and remove
managed lines atomically. Independent line-price, invoice, billing-source,
claim, and movement oracles passed, including duplicate keys, shared capacity,
dated edits, output rollback, stable IDs, and issue deletion cleanup. Draft
invoice headers may exist without an issue. Further invoice variants, tax,
refunds, offsets, and paired recipes remain open.

## 4. Implementation sequence and acceptance

| Phase | Deliverable | Exit condition |
|---|---|---|
| 0 — Blueprint | These documents and the algebra feasibility check | Concepts, proposed changes, and unverified assumptions are explicit. |
| 1 — Temporal prerequisites | Gates A/B, then isolated proofs for C/D | Independent mutation oracles and existing temporal regressions pass; required atomic recipes have a demonstrated path. |
| 2 — Account and movement core | Typed dimensions, six movement tables, explicit standalone claims, dated opening facts, required FX variant | All twelve endpoint directions; prohibited shapes/types/dimensions rejected; cash/stock/claim histories reconstruct exactly. |
| 3 — Claims and documents | One-sided invoice groups, pricing/tax recipes, source pools, partial/multiple allocations, notes, refunds/returns, advances, tax offsets and withholding | Worked examples reconstruct; neither side of a mandatory composition can disappear; allocation and original capacities hold at every timestamp. |
| 4 — Temporal resource/amount limits | Interval use, weighted capacity, changing supply, fixed rolling limits, explicit calendar periods | Required participant coverage and all boundary/edit/concurrency cases match independent interval/window queries. |
| 5 — Operations | Logistics, service/work orders, one-run production, resource requirements, future dependent outputs | Backdated changes propagate to all affected outputs; unsupported shipment/output/resource use is rejected atomically. |
| 6 — Valuation and useful reports | Explicit inventory value/cost effects and agreed financial classifications; as-of/range query examples | Physical quantity and money stay distinct; reports reconstruct from inputs and clearly state their valuation policy. |
| 7 — Integration and measured cost | Build/check/probe commands, populated schema reapplication, benchmarks, final docs | Required project checks pass and measured cost is reported per equivalent business operation. |

Phase 3 starts with parent-only formulas; add compound/prefix recipes once their
actual basis and ordering are explicit. Manufacturing initially uses an explicit
batch plan and fixed recipe/duration; the limiting-input variant is a later
concrete recipe within phase 5 after the simpler path passes. Missing required
inputs must never produce usable output. Define cancellation and referenced-output
behavior through gate C before allowing readiness changes to remove outputs.

`build:all-in-accounting`, `check:all-in-accounting`, native schema validation,
and `probe:accounting-core` compile and verify A1a-A1d and A2a-A2d using a
disposable database. The focused probe has independent row-source
reconstruction for the implemented movements, openings, claims, adjustments,
cash allocations, and required invoice-line lifecycle; it is not the full accounting
acceptance matrix. Add tax, refund/offset,
paired-recipe, and temporal fixtures as those contracts are implemented. Do
not point feasibility tests at an application profile or populate production
data.

The initial useful scope includes payments, transfers, invoices, direct/indirect
tax calculations, charges, notes, settlement, deposits, basic logistics,
reservations, services, weighted work capacity, and manufacturing by declared
recipe. CRM and HRM are outside this module's schema and dependency graph; the
system blueprint treats them as sibling modules. Also exclude statutory rule
maintenance, payroll, automatic bank integration, optimizer-based scheduling,
automatic FIFO/lot costing, and complex automatic revenue/FX recognition. Those
are additional algorithms or integrations, not free consequences of this
blueprint.

## 5. Membership and performance budget

Count active positions across the complete logical operation, including newly
materialized outputs, basis refreshes, and optional guard scopes.

| Record/operation component | Proposed typical positions | Reason |
|---|---:|---|
| External cash or stock movement | 1 | Its modeled asset account. |
| Internal same-unit transfer | 2 | Source and destination; coincident owner netting applies. |
| Explicit ungrouped claim | 1 | Its claim account. |
| Grouped invoice/claim component | 2 | Claim account plus outstanding document scope. |
| Claim settlement allocation | 3 | Claim account, target scope, shared payment source pool. |
| Optional payment/return pool's dated seed | 1 | Gives the scope capacity from the original effective date. |
| Tree-less shared calculation basis | 0 | Still incurs reference routing and dependent refresh work. |
| One weighted interval or fixed-window contribution | 2 | Start/add and end/expiry in one constrained owner. |
| Production input or output | Asset position plus only its required group/resource constraints | Cost depends on actual recipe dimensions. |

These are design budgets, not hard caps. Quotes, separate FX-leg scopes, notes,
multiple limits, and additional genuine allocation constraints add positions.
For example a receipt with a new source pool and one invoice allocation already
uses `1 + 1 + 3 = 5` positions across its records. Quoting only the receipt's
`m = 1` would conceal that cost.

Compare old/new profiles on matching perspective, information, guards, storage,
and workload. Record:

- declared slots, active positions, and total positions per operation;
- dependent candidates visited, outputs changed, and repeated refreshes;
- tree sizes/heights, summary width, schema size, and stored bytes;
- create/edit/delete/rule-refresh latency and conflict/retry counts;
- rejected-operation rollback latency and whole-operation atomicity.

Use small physical workloads first, with repeatable seeds and exact SurrealDB,
Node, storage, hardware, and batching settings. Expand only when those runs
justify it. Existing measurements show significant native write cost; a lower
asymptotic expression or a synthetic logical million-row tree is not a measured
throughput improvement. Adopt an optimization when it lowers equivalent total
work or provides an explicitly justified invariant.

## 6. Verification matrix

The accounting oracle must reconstruct from authoritative inputs, not from the
suite's derived contexts or membership helper. The tree oracle separately checks
topology, order, heights, summaries, slots, and roots.

| Area | Required adversarial cases |
|---|---|
| Types/dimensions | Wrong endpoint table; absent treasury/stock side; cross-book target; mixed currency/resource; incompatible FX quote. |
| Primitive directions | Every allowed direction and prohibited external-to-external real money/resource shape. |
| Claims | Positive creation, signed amendment, settlement reduction, refund restoration, standalone future claim, advance, and tax credit; no automatic sign-family flip. |
| Historical integrity | Edit/delete/move an old funding, stock, claim, or capacity event so a later prefix fails even though final totals remain positive. |
| Time boundaries | Equal timestamps with reversed IDs, recognition versus due time, exact `[start,end)` reuse, expiry/addition ties, timezone calendar boundaries. |
| Allocations | One payment across invoices; several payments per invoice; duplicate allocations; mismatched counterparty; one minor unit too much; in-kind allocation valuation. |
| Corrections | Cash-only refund, claim-only correction, stock-only return, coupled refund, original amount/date/endpoint edit, FX residual and source-leg capacity. |
| Atomic recipes | Partial children, duplicated retry, direct child forgery/deletion, parent deletion, readiness activation/cancellation, and nested-event premature validation. |
| Taxes | Sale/purchase examples, standalone assessment, compound numeric tax basis, credit offset, remittance/recovery, withholding/collection without invented cash. |
| Resource limits | Weighted overlaps, service slots, multiple resource pools, start/end/weight edit, historical capacity reduction, fixed rolling amount/count, window-duration change, missing participant, policy activation on populated data. |
| Manufacturing | Missing or partial input; wrong resource; excessive output; coproduct batch sharing; duration/input-date edit after downstream consumption; feedback attempt. |
| Dependencies | Parent-only, aggregate, and prefix paths; reparenting; diamonds; opaque helper reads; changed and unchanged rounded outputs; forbidden claim-to-real calculation. |
| Security/concurrency | Forged roots/slots/shadows; restricted readers; unauthorized source/target; two writers competing for the last stock unit, slot, or payable capacity. |
| Persistence | Populated schema reapplication; formula-change refresh procedure; database-version upgrade probes. |

For rejected writes, compare the complete relevant source, derived, group, and
tree snapshots to their pre-write state. Valid source changes should not create
business audit noise for rotations or derived refreshes.

Run focused probes as each capability is added. Once shared engine changes are
complete, run the existing temporal, Accounts, and suite regressions and the
required `npm run verify` gate. Repeat broader checks only after another material
change. The plan-only work does not require deploying or running a new suite.

## 7. Completion criteria

The suite is complete when its documented recipes compile to native strict
schema, all declared past/present/future invariants survive edits and concurrent
writes, mandatory outputs have a proved atomic lifecycle, and the independent
oracle agrees across the covered operations. Publish measured costs and explicit
scope limits alongside the schema.

The reusable result is the edge/group contract in the blueprint plus working
examples of each computation pattern. Adding another application should mostly
mean selecting account dimensions, concrete typed edge recipes, memberships,
and existing guard algebras—not modifying the compiler for every domain.
