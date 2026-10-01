# Accounting architecture handoff

## Next lower-model assignments — lead recheck complete

Start with this section and the [lead audit evidence](../rebase-system/evidence/2026-09-29-lead-checkpoint-audit.json).
Current compiler checks, credential/authentication/environment checks, runtime,
and expanded H8 integration passed. The audit records 125 current file hashes.
H8 now includes an observed independent-session conflict/retry and populated
schema reapplication. Preserve the dirty worktree and historical evidence.

1. **Sol: H8 bounded serial measurement passed, 2026-09-30.** The
   [measurement evidence](../rebase-system/evidence/2026-09-30-h8-measurement.json)
   records three fresh SurrealKV samples each at two and eight prior runs.
   Source/recipe checks and rejected-write rollback passed; the H8 section
   below separates operation timing from setup and lists unmeasured costs.
   Internal writes, operation bytes, dependency visits, contention variance,
   throughput and fan-out remain open. Before another measurement packet,
   identify a direct counter for its missing metric; keep the domain schema
   fixed and reuse the existing harness. Do not repeat these six samples for
   documentation changes.
2. **Luna: H0 routing cleanup passed, 2026-09-30.** Six routing files went from
   1,189 to 950 lines; the new [coverage map](./context-compression-map.md) adds
   41 lines and records retained decisions and evidence. Relative links,
   heading references, and diff checks passed. Broader research compression
   remains a separate future packet using the context map's procedure.
3. **H4b5c stays open.** Define residual source, sign, permitted range, precision,
   destination and effective date before implementing any residual posting.

Select verification from the changed contract and compare audit hashes first.
Repeat passed probes only for relevant changes or unresolved findings; reserve
full verification for a shared integration change. Keep real providers and
personal `.env` outside these tasks. End each packet with evidence and the next
bounded action. CRM/HRM and further domain expansion remain future work.

Updated 2026-09-30. This is the continuation route for Luna/Sol after the lead
review. The [blueprint](./blueprint.md) defines the revised target; the
[context map](./context-map.md) routes longer evidence. H1's direct economic
identity schema and focused probe are implemented and independently verified;
H1/H2 evidence is recorded at
[`2026-09-29-h1-identity.json`](../rebase-system/evidence/2026-09-29-h1-identity.json)
and [`2026-09-29-h2-effects-net.json`](../rebase-system/evidence/2026-09-29-h2-effects-net.json).
H3a sale-side variable tax outputs and H3b purchase-receipt settlement passed
on 2026-09-29; H3c passed as a bounded disposable ancestry fixture, H4a,
H4b1, H4b2, H4b3, H4b4a payer-side supplier withholding, H4b4b customer-
withheld TDS, H4b5a paired claim offset, and H4b5b treasury-backed remittance
passed their scoped gates. H4b5c residual policy remains future and unresolved
pending lead review. H5a's complete-timestamp stock floor and H5b physical
return with its dated source capacity passed their scoped gates. H5c's
standalone receivable cash-refund path also passed. H6a ordered resource-pair
identity and entered-quantity currency exchange passed its scoped gate on
2026-09-29; see the [H6a evidence](../rebase-system/evidence/2026-09-29-h6a-resource-exchange.json).
H6b quote-derived currency exchange passed its scoped gate on 2026-09-29; see
the [H6b evidence](../rebase-system/evidence/2026-09-29-h6b-quote-derived-exchange.json).
H7 immediate assembly passed its bounded schema/probe and H5/H6/core regression
gates; see [H7 implementation evidence](../rebase-system/evidence/2026-09-29-h7-immediate-assembly.json)
and separate [gross-input feasibility evidence](../rebase-system/evidence/2026-09-29-h7-gross-input-feasibility.json).
H8 timed production passed its bounded integration schema/probe and scoped
H5/H6/H7/core regression gates; see [H8 integration evidence](../rebase-system/evidence/2026-09-29-h8-timed-production-integration.json)
and the earlier [pre-code feasibility evidence](../rebase-system/evidence/2026-09-29-h8-production-feasibility.json).
The run exposes no writable `end_at`; required managed roles compute it from
`planned_start + immutable duration`. This is not a production migration;
workforce, costing and valuation remain outside this slice.
The [lead recheck](../rebase-system/evidence/2026-09-29-lead-checkpoint-audit.json)
adds current per-file fingerprints and passing H8 independent-session conflict
retry plus populated schema reapplication. The
[bounded serial measurements](../rebase-system/evidence/2026-09-30-h8-measurement.json)
add local timing and row/position observations; internal physical costs remain
unmeasured. The earlier integration JSON preserves its original probe fingerprint.
See
the [H3a evidence](../rebase-system/evidence/2026-09-29-h3a-sales-tax.json),
[H3b evidence](../rebase-system/evidence/2026-09-29-h3b-purchase-receipt-settlement.json),
the [H4a evidence](../rebase-system/evidence/2026-09-29-h4a-parent-tax-rules.json),
the [H4b1 evidence](../rebase-system/evidence/2026-09-29-h4b-aggregate-sales-tax.json),
and the [H4b2 evidence](../rebase-system/evidence/2026-09-29-h4b2-compound-tax.json),
and [H4b3 evidence](../rebase-system/evidence/2026-09-29-h4b3-purchase-tax-credit-recognition.json),
and [H4b4a evidence](../rebase-system/evidence/2026-09-29-h4b4a-supplier-withholding.json),
and [H4b4b evidence](../rebase-system/evidence/2026-09-29-h4b4b-customer-withholding.json).
H4b5a paired claim offset passed; see the [H4b5a evidence](../rebase-system/evidence/2026-09-29-h4b5a-claim-offset.json).
The treasury complete-timestamp floor prerequisite passed; see the
[treasury guard evidence](../rebase-system/evidence/2026-09-29-treasury-timestamp-guard.json).
See the [H4b5b remittance evidence](../rebase-system/evidence/2026-09-29-h4b5b-tax-remittance.json)
for focused runtime checks, regressions, fingerprints, and limits. H4b5c
residual policy remains future and unresolved pending lead review. H4b5a was rerun against
the combined current profile after the treasury change and passed; its original
source fingerprints remain a historical checkpoint.
H5a implements only the stock-account complete-timestamp floor; H5b adds one
physical return path and dated source capacity; H5c adds one standalone
receivable cash-refund path with dated source capacity. H6a and H6b passed for
ordered resource-pair identity, entered exchange, and explicit quote-derived
currency exchange. H7 immediate assembly passed its bounded schema/probe and
regression gates; see [H7 implementation evidence](../rebase-system/evidence/2026-09-29-h7-immediate-assembly.json).
H8 timed-production integration passed its bounded schema/probe and regression
gates; see the H8 evidence linked above. Its profile fixture does not establish
a populated legacy-profile cutover.
The bounded migration fixture does not establish a complete
populated legacy-profile cutover.

## Scope and starting point

Active: accounting, billing/tax calculations, logistics, resource exchange,
basic assembly, then a bounded timed-production variant. CRM/HRM, statutory
filing, automatic costing, optimizer scheduling, and a universal policy DSL
are outside these packets. Future modules may add concrete tables and declared
memberships without changing the previous tables' business meaning.

Core runtime work **K4a–K5 is complete** on the working snapshot recorded in
the [core evidence](../rebase-system/evidence/2026-09-29-k4b-credentials.json).
**H1 — economic identity and immutable dimensions — is complete** for the
target schema profile, with evidence in
[`2026-09-29-h1-identity.json`](../rebase-system/evidence/2026-09-29-h1-identity.json).
H4b3 — assessment and recoverable eligibility — and H4b4a payer-side supplier
withholding and H4b4b customer-withheld TDS passed within the larger H4b packet;
H4b5a paired claim offset and H4b5b remittance passed. H4b1's published
invoice-line aggregate basis and H4b2's finite
compound sales-tax dependency also passed their bounded gates; see
the
[`2026-09-29-h4b-aggregate-sales-tax.json`](../rebase-system/evidence/2026-09-29-h4b-aggregate-sales-tax.json)
and [`2026-09-29-h4b2-compound-tax.json`](../rebase-system/evidence/2026-09-29-h4b2-compound-tax.json)
evidence for exact scope and limits. H3a sale-side tax outputs, H3b purchase-receipt
settlement, the H3c bounded ancestry fixture, and H4a parent-only sales tax
passed focused gates; see
[`2026-09-29-h3a-sales-tax.json`](../rebase-system/evidence/2026-09-29-h3a-sales-tax.json).
The [H3b result](../rebase-system/evidence/2026-09-29-h3b-purchase-receipt-settlement.json)
records typed allocation, shared capacity, date guards, rollback and limits.
Full populated migration from an old deployed profile remains open; the H1
fixture proves bounded mapping, rollback and reapplication behavior.
H0 documentation and context compression remain an independent maintenance
packet, not a prerequisite to H2. A narrow disposable feasibility experiment
may precede schema migration; label it as such. A blocked provider/deployment
check does not require a new accounting engine or real outbound messages.

Recorded A1/A2 evidence and the pre-H1 baseline describe a compulsory-book
profile with several separate posting rows. Retain its tested invariants while
changing the target representation. Do not treat those older probes as proof
for the revised personal-account or combined-source design.

## Decisions to preserve

1. Economic entity, authorization owner, counterparty, account, document, and
   calculation dependency are separate roles. Personal entity may be the
   existing user. An organization has its own identity; it is not an auth group.
2. Keep real, receivable and payable as distinct typed effects. A single source
   may carry several of them and affect several roots. Co-locate deterministic
   1:1 effects when lifecycle/permissions match; 1:N or independently managed
   facts use typed children. Neither cardinality nor number of accounts is a
   reason to invent an asynchronous posting service.
3. Net is derived, never independent input. Read/record checks use `R-P`.
   Historical bounds require a derived net measure and complete-timestamp
   extrema in the same root. Every eligible source variant must participate.
4. Native schema/indexes establish facts and uniqueness. Ordered derived
   fields establish formulas. Protected memberships establish aggregates.
   Final validation guards the settled closure. Defining an `ASSERT` later
   cannot change event timing. Root/node fields are declared once.
5. Invoice participation does not imply automatic organization participation,
   dependency tracking, or permission inheritance. Declare each. Share one
   effect across roots only for distinct constraints/reports; do not sum those
   duplicated projections as additional economic value.
6. Account currency/resource is inherited by sources. Unique identity versus
   identity+currency is a scoped schema choice; a name string is not an owner.
   Pair resources differ, but either may be currency/item/service. Quotes,
   prices, executed trades, and scheduled trades have explicit populations.
7. Tax bases form a DAG. A tree-less published basis bridges whole-input
   summaries to posting outputs; outputs cannot feed their own input basis.
   Rules/eligibility/timing/rounding are versioned facts, not tax-name branches.
8. Account/document/source-capacity roots use the same maintenance primitives,
   with different semantics. A grouping link and a causal link are independent.
   Depth alone does not bound descendant fan-out or contention.

## What the source review established

These are source findings and retained test evidence, not new execution results.

| Capability | Exact implementation / evidence | Remaining domain proof |
|---|---|---|
| Many source tables and slots into finite owner roots | [Tree contract](../../src/tree-contract.js), `resolveTreeContract`; [runtime](../../src/temporal.surql), `member/coalesce/sync`; C1/C2a | Combined real/R/P source, all specialized table variants, mandatory coverage. |
| Several dates in one owner; complete timestamp extrema | Runtime measure/boundary algebra; [positions](../../dev-tools/temporal-tree/positions-probe.js) and [boundary](../../dev-tools/temporal-tree/boundary-probe.js) fixtures | Historical net limit, return/window policy. H4b5a changes receivable/payable capacity to `instant_min`; recognized-credit remains separately guarded. |
| Natural local derived order | [Derived DAG](../../src/derived-order.js); [generator](../../src/generators/temporal.js), `derivedFields/derive`; [derived-order probe](../../dev-tools/temporal-tree/derived-order-probe.js) | Chosen combined-source formulas and assertions on CREATE/refresh. |
| Mutable one-hop references and final closure guards | Generator `dependencies/events`; runtime `refresh/finish` | Every parent/header reparent path and old/new ancestor repair. A nested dereference alone is not a tracked route. |
| Private source-owned 1:N outputs | Runtime `sync_required_outputs`; generator `requiredOutputs`; [required-output probe](../../dev-tools/temporal-tree/required-outputs-probe.js) | Tax component set, paired claim/cash corrections, assembly leg set and deletion after use. |
| Multi-root aggregate-derived diamonds | [Causal-output probe](../../dev-tools/temporal-tree/causal-outputs-probe.js); tree-less basis | Actual tax/production input/output separation, version changes and rounding. |
| Concurrent shared-root fencing | Runtime `sync` owner revision; [typed probe](../../dev-tools/temporal-tree/typed-probe.js) dual-tree contention; positions multi-root contention | Overlapping but nonidentical account sets, opposite traversal order, duplicate source retries and complete accounting oracle. |
| Root and node fields on one record | Tree contract permits distinct fields; runtime rejects identical link/owner, not all equal record IDs; generated delete guard accounts for own slots | Direct dated self-seed create/edit/delete/rollback before choosing that capacity representation. |

Native owner-only business edits also invoke final validation. Recalculating
descendants after a changed owner dimension still needs declared dependencies;
make dimensions immutable where no such lifecycle is justified. Finite table
unions are a compile-time extension contract, not unrestricted runtime polymorphism.

## Bounded implementation packets

Use Sol for schema/lifecycle changes; Luna can handle H0 and tightly specified
documentation/oracle cases. Ask for lead review only at a concrete unsupported
invariant or after two attempts at the same unexplained failure. Model size is
not evidence of correctness. Execute one packet to its exit before expanding it.

### H0 — Classify and compress the context

Follow [context-map.md](./context-map.md). Start with duplicate routing/status
text in this module and `rebase-system` indexes. Preserve unique algebra,
counterexamples, commands, dates, source fingerprints, probe limits, and
unresolved decisions. Replace repeated prose with canonical links; archive
unique historical material when moving it. Do not silently edit recorded
measurements or invent proof for an unrun case. Broader research compression
is a separate bounded pass, not a prerequisite to H1.

**Exit:** coverage map of old section → retained section/evidence; conflicts
resolved or explicitly open; inbound/relative links valid; shorter active
reading route. The current context map is a first routing aid, not completed
repository-wide lossless compression.

### H1 — Economic identity and immutable dimensions

The 2026-09-29 [pre-H1 baseline](../rebase-system/evidence/2026-09-29-h1-baseline.json)
passes build, check, native validation, and the current 48-table A1/A2 probe.
That probe still tests the compulsory-book design; it is a regression oracle,
not evidence for direct user entities.

Use direct `record<rebase_user | organization>` references for
`economic_entity`; do not create a wrapper entity or infer it from authorization
`owned_by`. Organizations retain their identity; users can own personal
accounts and can also be counterparties. Keep `tax_account`, `misc_account`,
currency, resource and unit identities separate; do not add a universal
name-account table. For H1, keep `treasury` as a reusable named identity,
`treasury_account` as entity-scoped, and `operating_unit` as the current simple
stock-holding scope. Defer a separate nested location hierarchy to H5.

The all-in-accounting profile keeps its current multi-currency treasury policy:
unique `(economic_entity, treasury, currency)`. Prove the single-currency
alternative in an isolated schema fixture by replacing that index with unique
`(economic_entity, treasury)`. This is a schema/profile choice; do not make it a
client-controlled per-record switch. SurrealDB's [index syntax](https://surrealdb.com/docs/reference/query-language/statements/define/indexes)
offers `WHERE` for `COUNT`, not conditional `UNIQUE` indexes.

Limit H1 edits to the new `designs/all-in-accounting` profile; leave the old
`designs/all-in-one` profile intact as separate historical regression evidence.
Replace every compulsory book dimension and book equality guard in the target
profile. Derive a source's entity from its canonical account where the recipe
allows it and assert that all in-scope endpoints agree; do not accept a second
client-controlled copy of the same dimension.

| Source | H1 surface |
|---|---|
| `core/schema.surql` | Remove the required book role; add entity-scoped treasury, claim, and stock dimensions. Keep tax authority/jurisdiction, purpose, currency precision, and resource/unit references distinct. |
| `movements/cash.surql`, `movements/stock.surql` | Replace source book fields and endpoint book checks with entity derivation/consistency checks. Preserve currency, resource, and unit checks. |
| `claims/standalone.surql`, `claims/adjustments.surql`, `claims/settlements.surql` | Replace book scope with the owning economic entity; preserve counterparty, currency, and capacity guards. |
| `claims/invoices.surql` | Replace invoice/line/allocation book scope and `(book, number)` keys with entity scope per sales/purchase table. |
| `dev-tools/accounting/core-probe.js` | Add direct-user and organization fixtures, authorization/entity separation, incompatible references/units, both currency-index variants, and legacy mapping/collision cases. |

For populated legacy data, require one explicit old-book-to-entity mapping per
book. `book.organization` may support an explicitly reviewed organization
mapping; it never supplies a user identity. Preflight missing/conflicting maps
and duplicate destination account or invoice keys before mutation. Reject
ambiguous mappings and collisions atomically; never merge or split histories
silently. Document optional reporting segregation separately if a real use
case requires it.

**Exit:** direct-user and organization fixtures both work; cross-entity
references, unauthorized use and incompatible units fail; both selected
uniqueness policies have explicit fixtures; protected dimensions cannot drift.
The 2026-09-29 probe passed those cases and a populated bounded mapping,
rollback and repeat-safety fixture. See the linked evidence record for exact
commands and source fingerprints. This does not prove a full-profile legacy
cutover or deployment migration. Keep that limitation visible if existing
accounting data must be migrated. No `.env` change or credential redesign was
needed for H1.

**Status:** target-profile schema/probe packet complete. Full historical
profile migration is an explicit deployment follow-up, not implied by H1's
fixture.

### H2 — One source, several effects, exact net bounds

Use this effect matrix for the first H2 implementation:

| Source | Root | Unit and dated delta | Validation purpose |
|---|---|---|---|
| `purchase_receipt.z_stock` | `stock_account.z_history` | resource unit; `quantity += q` | entity, resource/unit identity and minimum stock |
| `purchase_receipt.z_supplier_base` / `z_supplier_tax` | supplier `claim_account.z_history` | invoice currency; same time, `payable += base` / `+tax`, `net -= base` / `-tax` | invoice counterparty, entity, currency and optional net bounds; one active position after coalescing |
| `purchase_receipt.z_tax_claim` | tax `claim_account.z_history` | invoice currency; `receivable += tax`, `net += tax` | tax-account opponent, entity, currency and fixed 1:1 assessed input-tax receivable; this does not assert eligible/usable credit |
| `purchase_receipt.z_invoice_base` / `z_invoice_tax` | `purchase_invoice.z_outstanding` | invoice currency; same time, `outstanding += base` / `+tax` | invoice grouping and amount due; one active position after coalescing |

Derive the supplier claim account from the invoice header. Store one received
quantity, unit price and invoice tax amount; derive base value and gross amount
using the invoice currency precision. H2 records the fixed invoice tax amount,
supplier payable, and assessed tax receivable. It does not claim to validate tax
law or establish credit eligibility/usable status; H4 adds versioned rules and
variable components. The captured tax amount remains editable until a document lock
lifecycle exists; edits reproject every affected root. Every effect uses the
receipt's one effective time. Do not create a
second `stock_in`/purchase-invoice line that repeats an effect. Keep separate
standalone claim tables functional.

Project optional `net = delta_R - delta_P` directly as a derived tree measure
where required; do not add a client-controlled field or another tree by default.
Every source that changes a claim's receivable or payable must publish the
corresponding signed net delta, including existing standalone entries,
corrections, settlements and invoice rows. An omitted publisher makes the net
projection incomplete. Use complete-timestamp `instant_min` for receivable and
payable and treasury balance floors; evaluate optional net floor/ceiling rules with
`instant_min`/`instant_max` across complete timestamps. H4b5a verifies this
policy for claim receivable/payable, and the treasury guard prerequisite is
covered by the [treasury timestamp evidence](../rebase-system/evidence/2026-09-29-treasury-timestamp-guard.json).
`recognized_credit` remains on its existing strict-prefix guard ([H4b5a evidence](../rebase-system/evidence/2026-09-29-h4b5a-claim-offset.json)).
The invoice `outstanding.min_prefix` guard remains a separate complete-time
policy gap; same-time invoice settlement is unsupported until it is corrected
and proved. Stock `quantity.min_prefix` is deferred to H5, including gross
source-availability and self-funding checks. Positive-only `settled`,
`allocated`, and `billed` capacity caps continue to use `max_prefix`.
Use the blueprint counterexample whose final net is zero but
historical peak is 100. Include equal-time R/P changes in both ID orders,
corrections, deletion, future dates, a lowered root limit, and a root without a
net bound.

**Exit:** independent authoritative-input reconstruction agrees after every
mutation; all roots roll back on any failed guard; no duplicated old/new claim
effect; a same-source same-root/time pair coalesces to one stored position;
native local checks and final guards each run at the intended boundary. Record
delta count and active positions, not just source-record count. Keep H2 to the
fixed source shapes above; variable 1:N tax components and multi-hop documents
belong to H3/H4.

**Status:** H2 passed on 2026-09-29; see the linked evidence for commands,
source fingerprints and exact coverage. The fixture captures the tax amount
from the invoice and does not validate tax law. It also creates an invoice
outstanding position that the current cash-allocation route cannot settle
because that route targets `purchase_invoice_issue`; close this lifecycle seam
in the document/settlement packets without duplicating the receipt effects.

### H3 — Multi-hop document and tax participation

H3a extended the existing `sales_invoice_issue` source to own
stable required tax-component outputs alongside its invoice-line outputs. Keep
dispatch on the `stock_out` source and issue/recognition on `issued_at`; include
an unbilled stock-out control. Each fixed tax component is an entered invoice
fact in H3a, not a computed tax rule. Its required child posts receivable and
invoice outstanding to the customer/invoice, and payable to the separate tax
authority claim. Declare immutable or one-hop-derived entity, document,
commercial counterparty, currency and direction. Commercial counterparty and
tax authority are different roles. Keep each recipe's physical stock delta on
exactly one source; old issue/line records must not post the same source again.
Independent optional adjustments keep their own authorized lifecycle. The
H3a and H3b lifecycles are verified in the linked evidence. H3c's bounded
ten-level ancestry fixture, H4a, H4b1, H4b2, H4b3, H4b4a, H4b4b, H4b5a,
and H4b5b passed their scoped gates.

**Feasibility gate:** a disposable compiled probe confirmed
`REBASE_REQUIRED_OUTPUT_FEEDBACK` when a required-output source consumes an
invoice header field and a child contributes to that invoice root; failure
restores source, child and root state on create and retarget. A reference-only
source can own the same-root output. Use `sales_invoice_issue` in that
reference-only role: it already owns generated invoice lines, whose children
derive immutable invoice header facts and contribute to the invoice and claim
trees. Preserve the issue parent's plain `invoice` reference; do not add a
reactive invoice-derived field to that parent unless a new core design proves
the necessary finer-grained feedback rule. See the feasibility note in
[`2026-09-29-h3-feedback-gate.json`](../rebase-system/evidence/2026-09-29-h3-feedback-gate.json).

Keep H2's purchase receipt fixed-tax recipe as the purchase control until a
separate change removes its fixed tax slots before adding variable tax children.
Leave shared returns/refunds and their capacity rules in H5.

#### H3b — Settle the H2 purchase receipt invoice

Close the H2 cash-allocation seam through an explicit typed allocation route
that reaches the receipt invoice's existing outstanding claim. Inspect whether
the allocation targets the receipt or invoice header and define its target
date rule; do not fabricate a `purchase_invoice_issue` row or duplicate receipt,
claim, or cash effects. Reuse the cash source's shared allocation capacity and
the invoice outstanding guard.

**Exit:** independently dated partial and complete payments settle the H2
receipt amount exactly once. A payment cannot exceed the cash source or invoice
outstanding total. Receipt edits/date moves, payment edits/date moves/deletion,
and rejected over-allocation restore the entire source/claim/invoice graph.

**Status:** passed on 2026-09-29. The [H3b evidence](../rebase-system/evidence/2026-09-29-h3b-purchase-receipt-settlement.json)
records the independently rerun checks and limits. H3c is complete for its
fixture-only scope; H4a, H4b1, H4b2, H4b3, H4b4a, H4b4b, and H4b5a passed
their scoped gates; H4b5b remittance also passed. H5a's complete-timestamp
stock floor, H5b's physical return with dated source capacity, and H5c's
standalone receivable cash refund passed their scoped gates. H6a ordered
resource-pair identity and entered-quantity currency exchange passed; H6b
quote-derived currency exchange also passed its scoped gate. H7 immediate
assembly passed its bounded schema/probe and regression gates; see [H7 implementation evidence](../rebase-system/evidence/2026-09-29-h7-immediate-assembly.json)
and separate [gross-input feasibility evidence](../rebase-system/evidence/2026-09-29-h7-gross-input-feasibility.json).
H8 timed-production integration passed; see its integration and feasibility
evidence in the starting-point section.

#### H3c — Bounded multi-hop ancestry

Use a small realistic chain with bounded branching to confirm propagated
identity, direction and document constraints through ten typed levels. Exercise
an ancestor edit, child removal, and a final guard failure with complete
rollback. This is a correctness fixture, not a throughput or production-depth
claim.

**Status:** passed on 2026-09-29 as a fixture-only proof. The
[H3c evidence](../rebase-system/evidence/2026-09-29-h3c-bounded-ancestry.json)
records the independent rerun and limits. No production ancestry hierarchy is
claimed.

**Exit:** child cannot omit/forge a required ancestor; mixed direction or
header mismatch fails even if children are uniform with each other; parent
reparent/quantity/date edits update every old/new root; header-only changes,
required-role removal, source deletion and failure restore the complete graph.
Include dispatch and recognition at different dates, issue edits after dispatch,
and independent payment dates. The short real chain is covered by H3a/H3b before
this depth fixture. Record
cross-table duplicate-event prevention separately if a single external physical
receipt can be entered into multiple recipe tables; table-local record IDs
alone do not deduplicate those events.

### H4 — Tax calculations and recognition

Keep rules as explicitly selected, versioned facts. A tax label does not select
law, jurisdiction, eligibility, calculation order, or rounding. No runtime rule
interpreter or statutory-rate claim is in scope; probe rates are illustrative.

#### H4a — Parent-only fixed and proportional components

Add immutable typed tax-rule versions with a stable component key and version,
tax identity and currency-scoped tax claim, regime/provision metadata,
an inclusive start and exclusive end, and one calculation kind: fixed amount or
proportional rate. The version is selected explicitly on the source; do not
auto-search rules by label/date or infer a regime. The exact selected version
must contain the recognition date. Fixed amounts must be representable at the
selected currency precision. A rule-version edit means selecting a new version
on the parent, not rewriting a referenced version.

For sales invoice issue only, compute each ruled component from that issue
parent's own pre-tax line amounts (sum the already currency-rounded line values):
fixed amount once per component, or `math::fixed(parent_base * rate,
currency_precision)`. Recognition is the invoice issue date. Reuse the existing
stable source-owned tax output and its customer, invoice, and tax-claim roots.
Preserve the H3a entered-amount form as an explicit legacy/manual path, but each
component must choose exactly one of entered amount or rule version. Keep the
H2 purchase-receipt fixed-tax recipe unchanged as a regression control; do not
add purchase rule slots in this packet.

**H4a exit:** on base 10, a fixed amount 1 and a 10% rule produce tax outputs 1
and 1, customer/invoice amount 12, and tax payables totaling 2. Editing a line
to base 7.50 changes the proportional result to .75 while retaining the fixed
amount and stable output IDs. Explicitly selecting a valid 20% version produces
1.50; a previously issued parent remains on its selected version. Wrong key,
currency/account, out-of-interval date, duplicate component key, or a positive
rate rounded to zero rejects and restores the full source/output/root snapshot.
Date moves, component removal, parent deletion, H3a manual facts, and H2 receipt
settlement remain covered. No tax-on-tax, group-tree basis, inferred
recoverability, withholding, offset, or purchase-rule migration in H4a; those
belong to H4b.

**Status:** passed in the disposable accounting profile on 2026-09-29. The
[H4a evidence](../rebase-system/evidence/2026-09-29-h4a-parent-tax-rules.json)
records the selected-version lifecycle, bounded probes, exact source fingerprints,
commands, timings and limits. Production migration remains a separate packet.

#### H4b — Aggregate and compound basis, offsets, withholding, and collection

Deliver H4b as separately verified slices. Keep H4a's parent-local/manual tax
paths as regression controls throughout; do not combine all tax and settlement
variants into one schema change.

##### H4b1 — Published invoice-line aggregate basis (passed)

Add one explicitly selected, immutable proportional tax component whose basis is
published from the invoice's rounded pre-tax line facts. Each eligible
`sales_invoice_line` contributes its already currency-rounded `amount` to a
dedicated taxable-input root. The `sales_invoice_issue` source owns a sibling
set of line, tree-less basis, and tax-effect outputs. The basis reads the
published summary; the tax-effect sibling references that typed basis record
and posts one stable amount to the existing customer receivable, invoice
outstanding, and tax-authority payable roots. Do not make a managed basis child
own a nested output recipe; C2c currently prohibits it.
Preserve the H4a parent-local path unchanged. The current schema permits one
issue per sales invoice, so the first slice aggregates only lines in that issue;
it does not imply a multi-document group basis.

The taxable-input root excludes tax outputs, claim balances, invoice outstanding,
cash, and stock effects. The output graph must remain acyclic: no output may
contribute to the root its basis reads, and the issue's invoice reference stays
plain if an invoice-root membership would create feedback. Preserve stable
source/role identities, exact owner/customer/currency/tax-account/version/date
and precision checks, and one tax output per component key. No legal
recoverability or jurisdiction meaning is inferred.

**Status:** passed on 2026-09-29. The [H4b1 evidence](../rebase-system/evidence/2026-09-29-h4b-aggregate-sales-tax.json)
records the independent rerun, all 21 matching executable/schema/configuration
fingerprints, and detailed limits. The disposable all-in-accounting profile
passed build (53 tables), compiler check, SurrealDB validation, Node syntax
check, focused H4b probe, H4a and core regression probes, and the H3c
validate-only/runtime controls.

**H4b1 exit:** multiple lines independently reconstruct the rounded taxable
basis and proportional output; line add/edit/remove refreshes the same output
identity; a zero-rounded result and duplicate component key follow an explicit
rejection policy; invalid selected version/date/account/currency or a failed
downstream guard restores source, derived rows, and every affected root. Confirm
stock and cash remain unchanged and there is exactly one customer, invoice, and
tax-authority effect for the component. A no-eligible-input case is
structurally unavailable in the current schema: issue lines are required and
all sales invoice lines are eligible because no eligibility discriminator
exists. H4b1 does not add statutory meaning, recovery, tax-on-tax,
withholding/collection, offsets/remittance, purchase-rule migration, or
multi-document grouping.

##### H4b2 — Finite compound tax dependencies (passed)

After H4b1, allow a declared component to consume a prior calculated component
amount through a finite acyclic calculation dependency. Keep component identity,
version selection, order, rounding, and residual policy explicit. Reject cycles,
missing predecessors, and version/date/currency mismatch atomically. Do not
expose a general client formula interpreter.

**Status:** passed on 2026-09-29 in a disposable profile. The [H4b2 evidence](../rebase-system/evidence/2026-09-29-h4b2-compound-tax.json)
records one aggregate proportional predecessor and one compound proportional
component per sales invoice issue, stable sibling outputs, refresh/version/
mismatch/rollback cases, and unchanged stock/cash. It does not prove a general
DAG, compound-to-compound dependency, multi-document grouping, production
migration, statutory interpretation, recoverability, purchase tax migration,
withholding/collection, offsets, or remittance. SurrealDB 3.2.0 requires a
predecessor tax key in the nested source input because it rejects a nested
`REFERENCE`; the managed output stores the typed reference.

##### H4b3 — Assessment and recoverable eligibility (passed)

Preserve H2's immediate posting of the invoice's assessed tax amount to the
supplier payable and tax-account receivable. Treat that receivable as the
explicit assessed claim; it does not assert that the amount is eligible or
usable. Add a separate recognition fact/status with an explicit eligible amount,
its own recognition date, and a selected immutable policy version linked to the
assessed claim. That fact must not post the same amount as a second receivable.
A tax label or invoice alone does not create recognized eligibility. Keep policy
inputs and authority explicit without claiming statutory completeness.

**Status:** passed on 2026-09-29 in a disposable profile. The [H4b3 evidence](../rebase-system/evidence/2026-09-29-h4b3-purchase-tax-credit-recognition.json)
records focused schema/probe/regression gates, fingerprints and limits.

**H4b3 acceptance:** with base 100 and assessed tax 18, receipt creation yields
supplier payable 118, assessed tax receivable 18, invoice outstanding 118, and
one stock movement; recognized/usable amount is absent or zero. An explicit
recognition of 12 under one immutable policy version/date records
`recognized_credit = 12` while receivable stays 18. The amount must be positive,
within assessed tax and currency precision. Reject zero/negative or excess
precision, amount above assessment, mismatched entity/tax identity/currency,
invalid policy interval, and recognition before the receipt. Receipt tax edits
below an already recognized amount and receipt deletion while recognized reject
atomically. Recognition edit/removal changes only the distinct measure; it does
not change receivable/payable/net, supplier/invoice amount, cash or stock. This
is a policy-agnostic fixture; it does not establish statutory eligibility or
completeness. H2's `tax_amount` remains the only assessed purchase-tax input.
The first slice supports one current recognition fact per receipt.

##### H4b4 — Collection and withholding

###### H4b4a — Payer-side supplier withholding (passed)

Tie one explicit withholding fact to an actual `purchase_receipt_cash_allocation`.
The ordinary allocation remains the sole cash and cash-source-capacity effect;
the withholding fact contributes no second cash allocation. For supplier
gross supplier payable of 100, a `cash_out` allocation of 90 plus distinct
withholding of 10 must leave supplier payable 0, selected tax-authority payable
10, purchase-invoice outstanding 0, treasury balance -90, and stock unchanged.
The fixture's base 90 and assessed receipt tax 10 leave a distinct assessed-tax
receivable of 10. The cash allocation subtracts 90 from supplier payable and
invoice outstanding; the withholding sibling subtracts 10 from those same claim
and invoice roots and adds payable 10 to its selected tax claim. The selected
withholding tax claim may differ from `receipt.tax_claim_account`; it must share
the receipt's economic entity and currency and have a `tax_account` opponent.
Do not require equality with the receipt's assessed-tax claim. Use supplier
payable and invoice outstanding as shared caps across both legs; the cash source
itself remains capped by its cash-out allocation tree.

The explicit withheld amount selects an immutable, tax-claim-account-scoped,
date-bounded version. It is entered as a fact; there is no statutory calculation
or inference from a tax label. H4b4a passed the disposable fixture and gates in
the [H4b4a evidence](../rebase-system/evidence/2026-09-29-h4b4a-supplier-withholding.json).
It supports one fact per actual `purchase_receipt_cash_allocation`; splits,
multiple withholding reasons per allocation, reversals, remittance, and
production migration remain outside the fixture. The probe covered endpoint,
party, entity, currency and policy mismatches; duplicate and over-capacity
rejection; date edits; amount edit/removal/re-addition; rollback; and unchanged
cash allocation capacity and stock.

TCS included in a sales invoice uses the existing `sales_invoice_tax_component`
at invoice time: it contributes the invoice's receivable, invoice outstanding,
and tax payable like another explicitly selected tax component. A later actual
cash-in/allocation settles the claim. Do not add a duplicate TCS table/output or
make TCS a cash-time calculation.

###### H4b4b — Customer-withheld TDS (passed)

Keep customer-side withheld TDS as a separate source with one current fact per
actual `sales_invoice_cash_allocation`. For invoice receivable 100, a cash-in and
allocation of 90 plus explicit withholding credit 10 must leave customer AR 0,
invoice outstanding 0, selected tax-account receivable 10, and treasury +90.
The ordinary cash-in/allocation contributes treasury +90, reduces customer AR
by 90 and invoice outstanding by 90, and consumes only 90 of cash-in allocation
capacity. The distinct withholding fact reduces customer AR and invoice
outstanding by 10 and posts tax-account receivable +10; it adds no cash movement
or cash-allocation capacity. Use the customer claim and invoice outstanding
roots as shared caps for cash allocation and withholding.

The explicit positive amount must match currency precision and cannot overdraw
the shared customer-claim or invoice-outstanding roots. Select one immutable
account-scoped, date-bounded policy version and enter the withholding amount
explicitly. Require matching economic entity and currency,
a valid tax-account opponent, and an effective date within the selected version
and no earlier than the invoice/allocation. No inferred formula or statutory
meaning. This route is distinct from H4b3 purchase-receipt recognition and from
TCS already included on `sales_invoice_tax_component` at invoice time. TCS does
not create a cash-time tax output or duplicate component. H4b4b passed the
disposable fixture: one invoice-time tax component posts payable 10 exactly
once; cash-in/allocation 90 plus explicit withholding 10 clears customer AR and
invoice outstanding, posts a separate selected tax-account receivable 10,
leaves treasury +90, and leaves stock unchanged. It adds no extra cash or
allocation effect. No statutory inference is made. See [H4b4b evidence](../rebase-system/evidence/2026-09-29-h4b4b-customer-withholding.json)
for gates and limits; its source fingerprints identify that recorded checkpoint.
H4b4a's checkpoint `package.json` fingerprint is historical after H4b4b added
its probe script, though H4b4a reran successfully in H4b4b's regression
sequence. Preserve the H4b4a evidence unchanged.

##### H4b5 — Offsets, remittance, and rounding residuals (H4b5b passed)

H4b5a paired claim offset and H4b5b treasury-backed remittance passed their
scoped fixtures. H4b5c residual policy remains future and unresolved pending
lead review. Split this packet so its independent claim, treasury, and rounding
decisions can be accepted separately.

###### H4b5a — Paired tax-claim offset (passed)

Scope the first fixture to one selected `claim_account` row. One explicit
instruction contributes two required measure effects to that same
`claim_account.z_history` root: `receivable -= amount` and `payable -= amount`.
For the blueprint fixture, receivable 6 and payable 18 with explicit offset 6
must leave receivable 0 and payable 12; the two effects have net delta 0.
Require a positive explicit amount no greater than either measure's available
balance at the effective time, preserving each measure's nonnegative bound.
Both effects share the account's economic entity, opponent and currency
dimensions and must commit or roll back together across create, edit, and
removal. This packet has no treasury or cash-allocation effect. Offsets between
different-opponent accounts are outside this slice: entity and currency
equality alone do not authorize cross-account netting; require a separately
explicit authorization/pair policy before considering that route.
H4b5a passed its focused build/check/native-validate and probe/regression gates;
see the [H4b5a evidence](../rebase-system/evidence/2026-09-29-h4b5a-claim-offset.json)
for commands, fingerprints and limits. The disposable fixture confirmed same-
timestamp ID-order independence and per-measure complete-time capacity. It does
not implement cross-account authorization, remittance, or residual policy.

###### H4b5b — Treasury-backed remittance of direct tax-account payable (passed)

Represent remittance with a typed link from one explicit tax-payable reduction
to an actual `cash_out`. Reduce the selected direct tax-account payable by the
same amount as the cash-out allocation, with matching economic entity,
currency, tax-account opponent, and valid effective-time ordering. The
existing `payable_cash_allocation` targets standalone `payable` rows, while
the current H4 tax payable is posted directly to `claim_account.z_history`;
that allocation relation does not settle this direct tax fact. The remittance
link therefore needs its own typed payable effect and must consume the
`cash_out` allocation root exactly once. Keep the payable balance and cash-out
allocation-capacity roots as the shared capacity guards, and commit or roll
back both effects together. Do not add a second treasury or allocation effect.
The disposable fixture confirmed payable 12 plus cash-out 12 plus remittance 12
leaves payable 0, treasury -12, and allocation 12 exactly once. It independently
tested the payable floor and cash-out allocation cap; dimension, precision,
effective-date, edit/rekey/delete/re-add, rollback, and source/account deletion
guards also passed. See the [H4b5b evidence](../rebase-system/evidence/2026-09-29-h4b5b-tax-remittance.json)
for exact commands, source fingerprints, and limits. This records an explicit
amount only and makes no production migration or statutory interpretation claim.

###### H4b5c — Rounding residual policy (future; unresolved)

Do not implement a generic residual until its source, sign, range, currency
precision, destination measure/account, effective date, and selected policy
are explicit. The FX-transfer residual is specific to that transfer formula
and does not select a tax residual destination or policy. A residual must be
posted as an explicit typed effect; it must not imply cash movement on its own.

### H5 — Shared capacities, returns, refunds and logistics

Implement this as ordered slices so stock policy, physical returns, and financial
corrections each get a direct oracle:

- **H5a — Complete-timestamp stock floor (passed).** The stock-account floor
  uses `quantity.instant_min`, so every movement at one effective timestamp is
  evaluated as a single boundary regardless of record-ID order. The disposable
  probe covers both transfer tie orders, direct stock-in/out at one timestamp,
  same-time deficit rollback, an outflow before a later receipt, source-edit
  rollback, and an independent movement-row oracle. See the [H5a evidence](../rebase-system/evidence/2026-09-29-h5a-stock-timestamp-floor.json).
  This does not implement gross source availability, returns, invoice policy,
  or production migration.
- **H5b — One physical return path and dated source capacity (passed).** Link
  a positive, unit-compatible return to one original `stock_out` and credit a
  compatible destination stock account in the same economic entity. Preserve
  the original recipient as the return party. Represent the source quantity
  as exactly one capacity grant dated at the original stock-out time; use a
  self-seed only after its direct lifecycle probe passes, otherwise use one
  stable required seed child. Return quantity consumes that shared source
  capacity. A return at the source timestamp is accepted as one same-instant
  correction boundary; use complete-timestamp capacity semantics so ID order
  has no effect. Return-before-source and cumulative over-return reject. Cover
  competing returns, an alternate compatible destination, source quantity/date
  edits and deletion, return edits/deletion/re-addition, historical stock, an
  independent source-row oracle, and full rollback. The physical return does
  not imply a cash refund or claim correction.
  Recommended first shape: a `stock_out.z_returns` root; one source-quantity
  grant from a distinct `stock_out.z_return_grant` node into that root; and
  each `stock_return` contributes `-quantity` to the source capacity tree and
  `+quantity` to its destination stock history. Guard the source pool's
  `remaining.instant_min` at zero. The source and its grant may be the same
  record only if the direct self-seed lifecycle probe passes. Keep source date,
  party, resource, and unit derived from the referenced `stock_out` so tracked
  source edits refresh the return and both roots. In this typed slice, the
  `stock_out` source key sorts before `stock_return` consumer keys, so the
  grant/consumer order cannot be reversed by choosing different record IDs;
  record that exact key order and rely on the existing boundary-tree probe for
  reversed-key algebra rather than adding a capacity wrapper solely for that
  fixture.
  **Status:** passed on 2026-09-29. The [H5b evidence](../rebase-system/evidence/2026-09-29-h5b-physical-return.json)
  records the disposable profile, source fingerprints, serial regressions,
  lead rerun, and limits. No cash refund, claim correction, or production
  migration is claimed.
- **H5c — One standalone receivable-cash refund variant (passed).** Use
  `receivable_cash_allocation` as the sole refund target and link each
  `receivable_cash_refund` to exactly one such allocation. The refund record is
  itself the real movement: derive its treasury account, cash source,
  receivable target, claim account, customer, entity, and currency from the
  allocation; debit the treasury once and do not also create a `cash_out`.
  Restore the same claim account's `receivable`/`net`, reverse the same
  receivable's `settled` amount, consume that allocation's refund capacity,
  and record equal `refunded` and `allocation_reversed` amounts on its original
  `cash_in.z_allocations` root. Keep gross `allocated` unchanged. Thus the
  dated source equation remains
  `original - refunded - allocated + allocation_reversed`, and an allocated
  refund has zero net effect on source allocatable capacity.

  Give each original cash allocation one dated refund-capacity grant equal to
  its amount at its allocation timestamp, and subtract each refund at its
  effective timestamp. Use a direct self-seed only with a passing lifecycle
  probe; otherwise use one stable seed child. On `cash_in.z_allocations`, add
  one dated source grant equal to the cash-in amount at its effective time.
  Every existing allocation from a cash-in source must subtract its amount
  from `available` while retaining the existing positive gross `allocated`
  measure. A refund writes equal `refunded` and `allocation_reversed` deltas,
  leaving `available` unchanged. Guard `available.instant_min >= 0`, retain the
  existing gross allocation cap, and use exactly one grant per source/purpose.
  Probe self-seed lifecycle and source amount/date edits directly.

  Require refund time to be strictly later than its allocation because the
  receivable settlement target currently uses a strict-prefix cap. Multiple
  sibling refunds may share a later timestamp and are checked as one complete
  timestamp boundary. Cover partial/full and same-time sibling refunds,
  excess/duplicate refund, currency precision, source amount/date/endpoint
  edits, allocation amount/date edits, source/allocation/target deletion,
  refund edit/delete/re-add, and atomic rollback across treasury, claim,
  receivable settlement, allocation refund-capacity, and cash-source roots.
  Keep the independent oracle on source rows. This does not implement an
  invoice refund variant, physical return, generic credit note, or refund of
  unallocated cash. **Status:** passed on 2026-09-29. The
  [H5c evidence](../rebase-system/evidence/2026-09-29-h5c-cash-refund.json)
  records the source fingerprints, lifecycle oracle, serial regressions, and
  limits. The lead independently rechecked all 11 fingerprints, rebuilt and
  checked the 64-table/21-material profile, ran native validation, H5c,
  H4b4b/H4b4a, H5a/H5b, boundary-tree, and accounting-core; all passed.

Reservations, partial fulfillment/release, correction-note groups, and any
additional return/refund variants follow only when a concrete consumer requires
them. A rejected write must restore source, children, all roots, and business
audit; each accepted packet compares its maintained summary with an independent
source-row oracle.

### H6 — Resource pairs and two-leg exchange

Split pair identity and entered execution from quote-derived execution:

- **H6a — Ordered resource-pair identity and entered-quantity execution (passed 2026-09-29).**
  Define `exchange_pair` over the finite resource union
  `record<currency | item | service>`. Scope pair identity by both authorization
  owner (`owned_by`) and economic entity; uniquely index that scope plus the
  ordered `(given_resource, received_resource)` IDs. Reject identical resources
  and treat the inverse as a separate explicit pair. Resource records provide
  canonical identity; currency amounts use immutable currency precision and
  item/service identities use their immutable `measure_unit`. Do not introduce
  unit conversion or execute item/service pairs until their quantity precision
  and stock-account policy are specified.

  Start with one currency-to-currency `cash_exchange` variant: both positive
  entered amounts must match the ordered pair and the two treasury accounts
  must belong to the same economic entity and authorization owner. Require each
  amount to match its currency precision. Debit the given treasury, credit the
  received treasury, and publish `executed_given`/`executed_received` to the
  pair's effective-time history in one atomic write. Keep it separate from
  `currency_exchange` quotes and `cash_fx_transfer` quote-derived movements.
  The reported rate is a read-only query projection
  `sum(executed_received) / sum(executed_given)` when the denominator is
  positive; it is `NONE` at zero, never a stored field. Never sum row rates or
  mix quotes into this population.

  Allow at most one explicit full `cash_exchange_reversal` per execution. It references
  the original, uses an effective time at or after it, and derives both account
  legs, the pair, and the exact amounts from that source. It credits the original
  given treasury, debits the original received treasury, and subtracts both
  quantities from pair history. A full reversal therefore removes the execution
  from net volume; a zero net denominator has no reported rate. One unique
  reversal is enough for this slice; partial reversal and fee recipes remain
  separate. The probe must prove edits/reversal/delete/re-add and invalid-write
  rollback across both treasury roots and pair history. The [H6a evidence](../rebase-system/evidence/2026-09-29-h6a-resource-exchange.json)
  preserves the independent-session pair race, row oracles, limits, and its
  original nine-source checkpoint. H6b changed four shared-source fingerprints;
  its [evidence](../rebase-system/evidence/2026-09-29-h6b-quote-derived-exchange.json)
  records current hashes and reruns H6a against the combined schema.
- **H6b — Quote-derived currency execution (passed 2026-09-29).** Reuse the existing
  `currency_exchange` quote and `cash_fx_transfer` movement; do not add a
  parallel FX route. Require an explicit quote whose ordered currencies,
  authorization owner, and economic entity match the `exchange_pair` and both
  treasury accounts. Never infer the latest quote. The transfer effective time
  must not precede its quote. Record `quoted_given` and `quoted_received` in
  pair history, separate from H6a's `executed_given` and `executed_received`.
  Compute the received amount with `fn::accounting::currency_round`; require
  positive source and rounded output so an amount that rounds to zero rejects
  atomically. Keep quote-use history when an execution is reversed, while
  subtracting its quote-derived amounts from pair history. Allow at most one
  typed full reversal per transfer. Fees, partial reversal, item/service
  execution, and latest-quote selection remain outside this packet. Derive any
  as-of quoted rate only from summed quoted quantities when the denominator is
  positive. The [H6b evidence](../rebase-system/evidence/2026-09-29-h6b-quote-derived-exchange.json)
  records the precision-zero, historical quote-use, reversal, source-row,
  failed-update and delete/re-add checks, current fingerprints, and limits.

**Exit:** same-resource pairs, duplicate ordered pairs in one owner/entity
scope, wrong orientation, mismatched account resources/entities/owners, wrong
currency precision, and unrelated private pair references reject. Inverse
orientation requires its own pair. As-of pair history, both treasury balances,
and ratio-of-summed quantities match independent source-row oracles. Cover
concurrent pair creation, same-time execution ID orders, one full reversal,
reversal exclusion, and an empty/zero-total denominator. Do not expose ordinary
rate sums or mixed quote/execution averages. Editing or reversing a source
repairs both asset accounts and pair history atomically.

### H7 — Immediate multi-input/output assembly

Keep the execution route H6b then H7; H6b is not a runtime dependency of a
physical-only assembly, but the packet order is deliberate. Bound the first
proof to one immediate recipe version with exactly two typed input roles and
two typed output roles, one economic entity, exact-count units, and integer
quantities. Do not add unit conversion, valuation, cost allocation, or a
client-interpreted recipe language. A later recipe variant can add a concrete
table and declared memberships without changing this contract.

Use stable `(batch, role)` identities for the four stock legs. Draft batches
contribute no stock and expose no usable output. One immutable recipe version
contains all four typed roles, so a partial leg set is unreachable through the
normal write path; completion atomically reconciles all four managed children.
All coproducts share one batch-consumption basis. The schema must declare each dependency;
do not infer tracked dependencies from arbitrary arrays or permit executable
identifiers/formulas in a manifest.

The pre-code gross-input feasibility gate passed on 2026-09-29; see the
[H7 feasibility evidence](../rebase-system/evidence/2026-09-29-h7-gross-input-feasibility.json).
It proved that a settled source validator can compare an explicit,
schema-owned same-time gross-demand root with stock strictly before the batch
timestamp. A `dependent=true` stock-history membership rechecks later batch
guards after an earlier stock grant is edited or deleted. The exact half-open
range `[T, T + 1ns)` was verified on SurrealDB 3.2.0; preserve that precision
in this profile. H7 production-schema integration now passes its focused probe;
see [implementation evidence](../rebase-system/evidence/2026-09-29-h7-immediate-assembly.json).
The output use root is linked through `stock_out`, which remains the single
physical stock debit.

**Status:** passed the scoped H7 schema/probe gate on 2026-09-29. The evidence
records valid/draft lifecycle, structurally complete role creation, duplicate
retry and repeated completion, gross same-time capacity in both ID orders,
source/grant rollback, linked output capacity, independent root oracles, and
H5/H6/core regressions. Partial child roles cannot be created through public
writes because the four roles are generated from the fixed recipe and child
tables deny direct writes. This is not a production migration; see the
[H7 evidence](../rebase-system/evidence/2026-09-29-h7-immediate-assembly.json).
No HRM records are required.

### H8 — Bounded timed production, integration and cost

**Status: bounded production integration passed on 2026-09-29.** See the
[integration evidence](../rebase-system/evidence/2026-09-29-h8-timed-production-integration.json)
and earlier [pre-code feasibility evidence](../rebase-system/evidence/2026-09-29-h8-production-feasibility.json).

The disposable [pre-code feasibility probe](../rebase-system/evidence/2026-09-29-h8-production-feasibility.json)
passed on SurrealDB 3.2.0. It established separate physical `quantity` and free
`available` measures on `stock_account.z_history`: reserve input from
`available` at the planned start; at the end post physical quantity as
`output - input` and availability as `output`. This combines physical input
consumption with reservation release into one end membership. Pre-start and
exact-start cancellation remove all effects; post-start cancellation releases
the reservation at its cancellation time before the fixed end. The subsequent
[production integration probe](../rebase-system/evidence/2026-09-29-h8-timed-production-integration.json)
proved coexistence with the current stock writers and downstream `stock_out`.
Both are bounded in-memory profile fixtures and do not establish a production
migration.

The bounded implementation keeps the H7 finite, immutable recipe shape and
adds one fixed duration. It uses `draft`, `scheduled`, and `cancelled` source states;
stable managed input/output role rows compute end as planned start plus immutable
duration. `production_run` has no writable `end_at`: on SurrealDB 3.2.0 a
READONLY projection failed during reactive refresh, while a writable VALUE
projection could be overridden by a caller. Each input role reserves free
availability at start and posts one end membership with physical quantity `-q` and available
`0`; post gross input `q` to the existing `stock_account.z_gross_input` root
for the strict before-end capacity guard. On cancellation after start, release
the hold without posting physical consumption. Each output role posts quantity
and availability `+q` at end and owns an output-use capacity root. Keep H7
immediate assembly working as its own path.

The production profile keeps `stock_account.minimum_quantity` as a physical
floor and adds a separate `available.instant_min >= 0` reservation guard.
Every direct stock-history writer contributes both measures consistently:
`fn::movement::stock_position` for receipts, deliveries, returns and transfers;
`purchase_receipt`; H7 `assembly_input`/`assembly_output`; and H8 production
rows. The H8 probe checks the actual production `stock_out` path for reserved
and produced stock, not only the feasibility debit stand-in.

Source inspection of `fn::tree::coalesce` shows that multiple dependent slots
from one source row to the same owner at the same timestamp are rejected as
`TREE_COALESCE_CAUSAL_SLOT`. Emit one net causal membership per source row,
owner and timestamp, or use distinct managed child rows for the legs. Do not
assume arbitrary dependent same-root legs are supported.

The production gate passed date shifts and earlier stock edits; overlapping
reservations in both ID orders; ordinary stock-out during a hold; mid-run
physical versus available as-of reads; exact-end completion; same-account
input/output without self-funding; cancellation before, at, and after start
plus rejection at/after end; downstream output-use capacity when an output is
reduced, shifted, or cancelled; and unchanged full snapshots on rejected
writes/retries. Independent source-row/root oracles reconstruct stock,
availability, gross input and output capacity. H7/H8 use the schema-owned
`stock_account.z_gross_input` root and strict pre-end stock comparison to guard
gross demand; H5a alone remains only an account-level floor. Keep the recipe
DAG finite. Advanced workforce, valuation and cost optimization remain
separate requirements.

Final profile reapplication, schema validation and scoped integration gates
passed. The [lead recheck](../rebase-system/evidence/2026-09-29-lead-checkpoint-audit.json)
adds two independent-session operations touching overlapping but nonidentical
owner sets in opposite input traversal orders. One observed conflict was
retried with the same business identity; all source/recipe/root oracles matched
after the initial commits and retry, with exactly four managed roles per run.
Reapplying the schema with populated runs and linked output use preserved the
full captured state; output-date dependency rejection still worked afterward.

The [2026-09-30 measurement packet](../rebase-system/evidence/2026-09-30-h8-measurement.json)
passed six fresh SurrealKV samples with the unchanged generated schema and
one fixed four-account, two-input/two-output recipe. The command is
`node dev-tools/accounting/h8-measurement-probe.js`; captured evidence adds
source fingerprints and summaries to its raw observations.

| Prior scheduled runs | Samples | Median successful create | Median capacity rejection |
|---|---|---|---|
| 2 | 3 | 654 ms | 560 ms |
| 8 | 3 | 766 ms | 797 ms |

Each successful create added four managed rows and eight live tree positions;
four stock-account rows changed. Source/recipe oracles passed, and all six
`ACCOUNTING_PRODUCTION_RESERVATION_CAPACITY` rejections preserved the full
captured snapshot. Setup is separate: each database imported the schema in
about 45.5 seconds, dominating the roughly five-minute packet duration.

Returned-row differences, serialized summary widths and whole-database
directory sizes are observations, not internal write counts or operation
bytes. Dependency visits, internal writes and isolated operation bytes remain
unmeasured. Serial samples observed no retries; the earlier bounded contention
case establishes functional retry behavior only. Repeated-run contention,
throughput, fan-out and representative capacity remain open. A constant-sized
root guard does not make the whole write constant-time. Select direct counters
for the next missing metric before running more samples.

## Execution settings and evidence discipline

- Preserve the dirty tree, including untracked schemas/probes. Scope the diff
  before work; do not reset unrelated files or treat HEAD as the tested snapshot.
- Existing settings live in [core-configuration.md](../rebase-system/core-configuration.md).
  Do not source personal `.env`, contact providers, or add environment flags for
  mathematical/domain choices. Reuse the disposable probe harness.
- For an accounting source change: `npm run build:all-in-accounting`, then
  `npm run check:all-in-accounting`, `surreal validate build/all-in-accounting/schema.surql`,
  and `npm run probe:accounting-core` with the packet's oracle coverage.
  Rebuild before diagnosing a generated-output-stale message.
- A shared engine change additionally runs only affected derived/tree/lifecycle
  probes first; broad integration runs once at a stable boundary. The positions
  probe is `node dev-tools/temporal-tree/positions-probe.js`; it is not included
  in the current `npm run verify`. The revised accounting profile also has its
  own gate above and is not implied by a general verify pass.
- For docs-only changes, check links, scoped diff and contradictory routing;
  do not start databases. New feasibility probes must state the unknown they
  resolve. Preserve prior unchanged evidence with its date/fingerprint.
- Checkpoint packet, source fingerprint, exact commands/durations, results,
  limitations and next action. A compiled schema, written fixture, historical
  pass and fresh pass are four different evidence states.

## Copyable continuation

> Read `designs/rebase-system/core-handoff.md` and the starting-point section of
> `designs/all-in-accounting/implementation-handoff.md`. K1–K5 and H1/H2/H3a/H3b
> passed on the recorded snapshot; H3c's bounded ten-level fixture, H4a, H4b1,
> H4b2, H4b3, H4b4a, H4b4b, H4b5a, and H4b5b passed. H4b5c residual policy
> remains future and unresolved pending lead review. H5a complete-timestamp
> stock floor, H5b physical return with dated source capacity, and H5c
> standalone receivable cash refund with dated source capacity passed. H6a
> ordered resource-pair identity and entered-quantity currency exchange and
> H6b quote-derived currency exchange passed; preserve both evidence files.
> H7 immediate assembly passed its bounded schema/probe and H5/H6/core
> regression gates; preserve the [implementation evidence](../rebase-system/evidence/2026-09-29-h7-immediate-assembly.json)
> and separate [gross-input feasibility evidence](../rebase-system/evidence/2026-09-29-h7-gross-input-feasibility.json).
> H8 timed production passed its bounded production schema/probe and H5/H6/H7/core
> regression gates; preserve the [integration evidence](../rebase-system/evidence/2026-09-29-h8-timed-production-integration.json)
> and earlier [pre-code feasibility evidence](../rebase-system/evidence/2026-09-29-h8-production-feasibility.json).
> The run has no writable `end_at`; its stable managed role rows compute end
> from `planned_start + immutable duration` because SurrealDB 3.2.0 rejects
> readonly projection refresh and permits caller override of writable VALUE.
> H7/H8 gross input uses `stock_account.z_gross_input` with pre-end stock; H5a
> remains an account-level floor only. This is a bounded fixture, not a
> production migration. Workforce, valuation, costing and general recipes are
> outside scope. Preserve the dirty tree and continue only from the active
> packet selected by the lead.
> Preserve H2's immediate assessed tax
> receivable and keep recognized-credit facts separate from it.
> Preserve the dirty tree, retain H4b1/H4b2 and H4a/H3a regression paths, use
> focused accounting probes, and preserve H4b5b evidence and limits.
