# Temporal calculation system — implementation contract

Status: implemented v2 with explicit datetime/int contracts added in C1, 2026-09-25. Replaces the
Accounts replay design and earlier suite/tree plans. Requirements include the entity/interaction extension through 2026-09-22;
scalar feasibility baseline: `a5eb8f8`.
Implementation: [shared functions](../../src/temporal.surql),
[tree contracts](../../src/tree-contract.js), [storage expansion](../../src/generators/tree.js),
[dependency expansion](../../src/generators/temporal.js),
[composed domain](../../designs/all-in-one/README.md).

## Scope and decisions

- Calculation software, not prescribed accounting. Client owns effective dates, amendments, rules, and presentation. Ordinary dated transfers supply opening funds; no opening-balance subsystem, invoice locks, or compatibility layer.
- Vocabulary: **entity** = identity; **dimension account** = entity + currency/resource/unit with aggregates/guards; **interaction** = dated fact; **contribution** = signed, unit-correct projection into an owner; **document** = claim/grouping/note. An interaction can itself own a history. This is not an accounting-only model.
- Reuse one intrusive augmented AVL across typed business tables. No duplicate membership/position/replay records. Existing owner records hold roots. Dimension accounts are meaningful domain entities; currencies are identities with immutable precision, not trees merely for naming units.
- Distinguish **structural maintenance**, **ordered aggregates**, and **business dependencies**. Functions own rotations and ancestor repair; dependencies propagate only consumed changes. Structural links never confer authorization.
- A fact explicitly participates in each required ancestor tree. Derived references copy parent/ancestor identities; dependency propagation keeps them current. Do not also add the ancestor's subtotal to the same tree: that double counts facts.
- The union is an overlapping forest of intrusive trees plus a business dependency DAG. Parent/child links are not causal edges; an AVL parent is not the chronological predecessor.
- Use native SurrealQL functions/events and small compiler expansions, not a runtime registry, formula interpreter, plugin, migration framework, or table-specific balancing code. Keep useful native indexes and nominal views.

## Primitive

```text
Link = { rid: record, slot: string }
owner.slot = { root?, height, revision, published summary, maintenance state }
node.slot  = { owner, parent, left?, right?, prev?, next?, key, value,
               height, summary }
key = [ordered_value, canonical_record_id, slot]
```

Each root and node declares `datetime` or `int`; one tree has one key type.
Datetime keys retain native instant precision. Integer keys are limited to
`[-9007199254740991, 9007199254740991]` for exact JSON/JS transport. Integer
trees share the AVL and ordered summaries, but have no temporal prefix consumers.
Scale identity/version is a domain constraint, demonstrated by the
[compiled stage fixture](../../dev-tools/temporal-tree/typed-fixture.surql).

Each independent membership needs separate metadata on the same business record.
Root.parent is the owner link (sentinel); root is mutable under rotations. A singleton
owner gives a table-wide tree without a second algorithm. A prefix consumer has
`value.dependents = 1`; other members have zero. Required typed references
alone do not establish a tree. Maintain strict order, reciprocal topology, one reachable
root, no orphans/cycles/shared children, AVL balance, exact summaries, and root consistency.
Polymorphic root uniqueness comes from protected roots + same-transaction maintenance +
a write fence on the owner, not table-local UNIQUE or reverse-reference counting.

Insert/search/delete/reposition walk height-bounded paths. Deletion transplants links,
never business payload. Repair demoted nodes before promoted nodes. Equal summary is
not permission to skip unfinished structural repair. `prev`/`next` splice on insertion,
deletion, or reposition; rotations leave chronology unchanged. Coalesce same-owner legs
to avoid artificial intra-transfer deficits. Keep old keys/contributions to undo edits.

## Summary algebra

For consecutive blocks A,B, include the empty prefix:

```text
empty = (count=0, sum=0, min_prefix=0, max_prefix=0)
combine.sum = A.sum + B.sum
combine.min_prefix = min(A.min_prefix, A.sum + B.min_prefix)
combine.max_prefix = max(A.max_prefix, A.sum + B.max_prefix)
combine.count = A.count + B.count
node.summary = combine(combine(left.summary, singleton(contribution)), right.summary)
```

Apply the algebra componentwise to a schema-bounded vector of quantities/amounts/category
totals. The stored summary has `count`, `dependents`, `first`/`last` keys,
`measures.{name}.{sum,min_prefix,max_prefix,min,max}`,
`tags.{name}.{value,uniform}`, and `spans.{name}.{min,max}` datetimes.
An absent measure contributes zero to prefixes and is absent from per-value extrema.
Uniformity uses exact representatives/equality, never a hash as proof. Currency/item units
must agree per component. Do not sum different currencies or arbitrary distinct sets.
Absent tags do not affect uniformity. When absence is part of the constraint, emit
an explicit value: correction notes use `invoice: false` for an unlinked correction,
so another member's invoice cannot mask it in the aggregate.
Guarded history starts at zero: `root.min_prefix >= 0`. At least one funding/source
account must permit negatives. Original facts participate in their own history as dated
members; treating them as timeless opening values incorrectly permits early refunds.

Rank/kth/nearest-rank percentile are in the tree's ordering (date quantiles here, not
amount quantiles). Rank is the 1-based lower-bound position; select returns a member
link or NONE. Percentiles accept [0,1], use `max(1,ceil(p*count))`, and return NONE
for an empty tree. Prefix excludes the current full key. `[datetime]` excludes all ties
at that instant. Range extrema require an ordered fold; subtracting prefix minima fails.
Identity remains stable on date edits. UUIDv7 has millisecond timestamp precision and
cannot replace mutable, full-precision effective time. Ties follow the deterministic key;
simultaneous batching would be a distinct policy. Timezones matter for calendar boundaries,
not comparison of instants.

## Dependencies and settlement

- Fixed deltas (including adjustments/refunds/returns) need no chronological dependency.
  They remain ordered for prefix integrity. Order sensitivity does not imply nonassociative
  summary composition: min-prefix is associative but not commutative.
- Parent-only shadows consume declared parent fields. Parent+prefix rules consume both.
  A rule's basis is the aggregate strictly before its key, independent of AVL topology.
- Chronological links alone do not invalidate prefixes. An inserted fixed delta can alter
  every later prefix without changing a dependent's immediate predecessor. Use a subtree
  dependent count to find later consumers without walking all fixed facts. Process those
  consumers in increasing key order and update only changed output projections.
- A static record between two live rules must not terminate invalidation. An unchanged
  charge amount also does not prove the remaining prefix is unchanged (caps/rounding).
- Structural writes must not recompute live formulas against partly repaired trees.
  Store protected shadows; refresh them at the business event boundary. Publish completed
  aggregates after affected memberships and causal refreshes settle. Validate final state
  in the same transaction; record users cannot invoke private mutation functions.
- Dependencies must be acyclic. Reading a whole-tree result while contributing to it can
  create feedback. Prefix-before-key gives a strict causal order; ordinary parent links
  require a DAG. No silent freezing or arbitrary truncation of dependent refreshes.
- Source statement validation is not deferred SQL commit validation: a user batch with an
  invalid intermediate business statement can fail even if its proposed final state is valid.
- User timestamps/audit track authoritative edits, not pings, rotations, or derived refreshes.

Execution is one synchronous source event: `refresh` stored shadows → synchronize
each membership from its cached old slot → refresh consumed ordinary dependencies →
drain later prefix consumers → publish repaired roots → refresh their consumers →
validate affected records/owners. No event per rotation; no upward aggregate-view
cascade. Ordinary descendants are refreshed before entering temporal sweeps. During
a sweep, contributions may change, topology may not, and earlier causal edits throw.
Published summaries can feed downstream records outside their contributing trees.
Schema-declared business dependencies have a cycle guard; custom helpers must remain
causal. Native references handle business deletion; protected roots reject nonempty
owner deletion even without reverse references. A self-only history can be deleted.

## Schema and query API

| Annotation | Contract |
|---|---|
| Field `@rebase-tree-root` | Protected root storage on an existing owner. |
| Field `@rebase-tree-node` | One protected membership slot on a business record. |
| Field `@rebase-tree-key datetime` or `int` | Mandatory on every root and node. No implicit type or `temporal`/`ordinal` aliases. |
| Field `@rebase-tree-owner table.root_field` | Mandatory finite target on each node; repeat for a real union of owners. Exact table/slot pairs are enforced. |
| Table `@rebase-members fn::name` | Pure row → array of membership specifications. |
| Field `@rebase-derived` | Protected stored shadow with a native VALUE expression. |
| Field `@rebase-depends ref.field, ref.other` | Explicit consumed fields for opaque helper reads. |
| Table `@rebase-validate fn::name` | Final-state row/aggregate guard; throws on invalid state. |
| Field `@rebase-system` | Technical field excluded from business timestamps/audit/readers. |

An adapter returns `fn::tree::member(row.id, node_slot, owner_record, owner_slot,
effective_at, measures, tags, spans, reads_prefix)`; NONE owners omit membership.
Integer adapters use `fn::tree::int_member(row.id, node_slot, owner_record,
owner_slot, order_value, measures, tags)`; NONE owner/order omits membership.
Declare optional source codes as `TYPE option<number> ASSERT $value = NONE OR
fn::tree::valid_key([$value], 'int', false)`. This checks the native numeric type
and transport range before SurrealDB 3.2.0 can coerce a fractional value into
integer storage. The compiler still emits `[int, string, string]` stored keys.
Malformed keys and query bounds are rejected before comparison or coercion.

Root/node declarations are storage placeholders (`TYPE object` and
`TYPE option<object>` respectively). Keep only their select policy and markers;
put business defaults, VALUE expressions and guards on inputs, derived fields or
`@rebase-validate`. Duplicate, unknown, nested or incompatible tree declarations
fail compilation. Generated link assertions group permitted slots by table to
keep expression depth bounded in composed profiles without permitting cross-pairs.

The shared `fn::tree::coalesce` nets coincident owner projections into one singleton
(count=1, prefix extrema from the net value). It requires equal instants and exact
dimensions/spans; the first declared slot wins. A prefix-reading projection must
be first for that owner, preserving its causal key. Different instants cannot be
coalesced. Names and dimensions are schema-owned; never add unbounded measure keys.
Changing contributions repairs ancestors; changing key/owner removes and reinserts.

Derived VALUE expressions are pure functions of `$this` and declared references.
Local derived fields must precede consumers alphabetically (`z10_`, `z11_`, `z20_`).
Remote dependencies require typed scalar top-level `REFERENCE` fields. Materialize
multi-hop references one hop at a time. Compiler inference covers explicit field
traversals, not arbitrary function bodies: declare hidden reads with `@rebase-depends`.
Stored shadows cannot read local tree storage; use prefix helpers for live rules or
native COMPUTED accessors for published state. Referenced identities/dimensions that
do not declare dependency routes must be immutable, as in the Accounts schema.
Changing a function/schema definition preserves stored facts; explicitly refresh
affected rows with `UPDATE table SET system_ping = time::now()` when a formula
definition changes. Editing a rule record already triggers its declared dependencies.

```surql
RETURN fn::tree::read(money_account:bank, 'z_book', 'summary', []);
RETURN fn::tree::read(invoice:sale, 'z_book', 'before', [d'2026-02-01T00:00:00Z']);
RETURN fn::tree::read(invoice:sale, 'z_book', 'range',
    [[d'2026-01-01T00:00:00Z'], [d'2026-02-01T00:00:00Z']]);
RETURN fn::tree::read(invoice:sale, 'z_book', 'select', [3]);
RETURN fn::tree::read(invoice:sale, 'z_book', 'percentile', [0.95dec]);
```

Range is [lower,upper); full keys can split ties. `rank` takes a key like `before`.
Read helpers preserve native node row/field ACL and fail closed when a required
member is unreadable. The public entrypoint also checks owner access and retains
the root field's select policy. A readable cached root summary publishes its
aggregate even if contributor slots are private; broader publication is an
explicit domain policy, not a per-caller filtered aggregate. The compiled fixture
tests both guarded ownership/visibility and deliberate aggregate publication.
Mutators are private. Structural/root storage and derived refreshes never grant readers.

Run `npm run probe:typed-tree` for compiled datetime/int mutation, query, scope,
pairing and rollback checks. `npm run probe:temporal-tree` preserves temporal
dependency coverage; `npm run probe:ordinal-tree` retains the handwritten
integer primitive regression. Exact decimal/full-width integer transport,
integer prefix dependencies and distinct positions in one source/owner remain
outside C1. Current results are in [verification](../../designs/rebase-system/verification.md).

## Entity / interaction composition

| Entity or fact | Meaning / maintained contributions |
|---|---|
| `organization`, `treasury_account`, `misc_account` | Identities. Treasury/misc identities do not fix currency. No implicit “us”; our organization is an ordinary party. |
| `tax_asset`, `tax_receivable`, `tax_payable` | Accountable direct-tax assets versus indirect claims. Jurisdiction, eligibility, rates, withholding/collection order and labels remain client policy. |
| `money_account(entity,currency)` | Native unique pair, immutable dimensions; `asset`, `receivable`, `payable`, signed flow/report components. Multiple currencies per identity. Nonnegative asset policy is configurable; claim histories cannot be negative. Claim entities cannot be cash endpoints. |
| `stock_account(endpoint,item/service)` | Unique resource capacity. Items/services share the same algebra and configurable nonnegative policy. Ordinary transfers grant/consume resources; source accounts may allow negative capacity. |
| `currency_exchange` | Immutable currency pair, mutable positive rate/effective date, protected ordered usage root. Rate changes refresh actual users; quote cannot postdate a usage. |
| `invoice` | Explicit issuer/recipient organization/currency accounts; same currency, different parties. Ordered outstanding/billed/settled amounts. No invoice lock; edits succeed iff all constraints remain true. |
| `payment`, `settlement` | Independent debit/credit projections, own capacity history, direct organization projections. Settlement also consumes invoice and party claims; one endpoint currency must equal invoice currency. |
| `money_adjustment`, `money_refund` | Inherit endpoints, origin, invoice/tax/parent relationships. Required note. Source delta + destination residual; separate nonnegative original leg capacities. Same correction primitive supports cash charges/allocations. |
| `money_parent_charge`, `money_charge` | Actual asset movement from original debit account to a real receiving account. Parent-only or earlier-prefix basis. Own refundable capacity; fees affect parent's compound basis, not its original transferable leg capacities. |
| `asset_parent_allocation`, `asset_allocation` | Parent-only/prefix rule redirects received assets to an associated direct-tax asset account. Consumes original received refund capacity. Linked reversal restores it; unrelated recovery payment does not. |
| `delivery`, `delivery_adjustment`, `delivery_return` | Quantity/value facts, stateless two-delta corrections, quantity-only returns. Resource endpoints, original history, optional invoice/parties, operating units. No invented value refund. |
| `delivery_parent_charge`, `delivery_charge` | Parent-only / earlier-prefix assessed value; original, own capacity, invoice/parties and selected tax claim account. Amount-only `delivery_charge_adjustment` inherits exactly those owners. |
| `tax_assessment`, `tax_adjustment` | Standalone claim creation/correction, own history and direct organization projection. No asset creation. |
| `tax_remittance`, `tax_recovery` | Real asset transfers plus consumption of the appropriate tax payable/receivable, validated currency and organization. Their refunds restore claims and reverse assets. |
| `adjustment_note` | Required on monetary/delivery corrections, refunds and returns; ordered correction amounts/count, exact currency, correction dates at/before note issue. An optional invoice constrains every entry; unscoped notes can group corrections in the same currency. Never sums heterogeneous quantities. |
| `operating_unit.z_activity` | Direct inherited activity counts for physical quantity movements and HR interactions. Detailed resource/money balances remain dimension-scoped. |
| `crm_case`, `crm_transition`, `crm_interaction` | Case starts open; dated -1/+1 transitions enforce prefix state in [0,1]. Notes/effort may follow closure. Direct organization case-state/effort history; no automatic sales pipeline. |
| `employment`, `leave_account`, `leave_grant`, `leave_use` | Employment interval and unique employment/service allowance; dated grants/approved usage keep capacity nonnegative. Direct employment/unit activity. No implicit accrual, payroll, leave calendar, or time-triggered writes. |

**Dimension access.** Create an organization's currency account before its treasury/tax
dimensions. A native unique-index lookup resolves `money_account.z10_party`; its tracked,
protected reference preserves deletion integrity. Identities/currency/organization links
used this way are immutable. No dimension registry or hashed equality proof. Ordinary
reference reactivity handles mutable invoice, case, employment and rule relationships.

**Amounts/FX.** `payment.a_amount` is source-denominated; destination is rounded using
its currency precision after the selected exchange. Missing exchange means identity and
requires equal currencies. Corrections accept `a_from_delta` and an independent
`a_to_delta` residual, permitting target-only correction. Refund uses positive `a_amount`
to reverse the source, and computes the reversed destination with its selected/inherited
quote plus optional residual; it cannot create a positive destination contribution.
Quotes may be shared; edits can therefore refresh many facts. Signed `inflow`/`outflow`
are informational projections and reverse with refunds. No cross-currency scalar total.

**Claims/time.** Original delivery/assessment lines must be at/before invoice issue;
settlements at/after issue. Each fact has its real effective time in source/original/
invoice histories; party and invoice-derived tax claim recognition is
`max(fact effective time, invoice issue time)`. This explicit per-membership time mapping
prevents receivables existing before issue. Later amendments retain their dates. Changes
to invoice issue/parties refresh every affected leaf, including descendants. Both invoice
and original history bounds are enforced; no silent date rewrite to satisfy a guard.
Taxes assess liability/receivable only; they do not fund an account. A tax assessment
selects one accountable claim; opposite-party assessments are separate explicit facts.
Cash settlement/remittance/recovery changes assets and claims in the same transaction.

**Corrections/ancestry.** A correction is a dated interaction, not an in-place rewrite
of its parent. It participates directly in chosen original, dimension, document and
ancestor trees. Required notes support correction documents without freezing source
edits. Invoice-scoped notes reject corrections with a different or missing invoice;
assigning an invoice to a populated note validates all existing entries. Derived
ancestor context is protected and refreshed from parents. Deleting a
referenced source is rejected; removing an unreferenced fact removes all memberships.
Uniform dimensions, source-before-child and issue/settlement bounds are aggregate guards.
No automatic tree for every ancestor, duplicate rollup subtotals or implicit expenses.

## Complexity and evidence

For bounded summary width q and m declared projections: coalescing costs O(m²q);
then fixed tree work is O(q·Σ log n_i), usually O(m log n) for schema-fixed m,q; rank/prefix/range O(q log n); whole summary O(1) record reads (O(q) output);
listing k costs at least O(k). Stored space O(mq) per fact, O(log n) walk state,
and O(r) candidate/work state for a dependent sweep. Additional ordering fields
require additional memberships, not free indexes. No amount-ordered tree is requested.
With r dependent refreshes: conservative O((1+r) m q log n), plus dependency routing
and cycle checks. r includes visited consumers with unchanged capped/rounded outputs
and repeated visits across dependency paths; it is not bounded by AVL height. A local
tax-count policy can bound a particular domain, not the primitive.
Current compositions need at most nine active memberships (e.g. a two-unit delivery
correction: two resources, two units, original, invoice, two parties, note). Coincident
owners reduce this; eight is a design preference, not an integrity-breaking hard cap.
Intrusive slots share record conflicts. Native lookup/I/O/indexes, audit, retries, and
hot-root contention remain; LSM storage does not remove them. Custom trees are not query
planner indexes. No million-row throughput claim follows from asymptotic work.

## Engine findings and verification

Measured on SurrealDB 3.2.0 / 3.2.4; retain these upgrade-sensitive boundaries:

- MERGE preserves omitted nested keys. Slots/shadows use replacement PATCH to remove
  obsolete aggregate categories; stale keys can otherwise silently corrupt summaries.
- During synchronous DELETE, `record::exists` may return true while SELECT sees NONE.
  Read visible existence with SELECT; unlink using cached old slots and deleted-root height.
- Nested event traversal may reuse the outer document's stale derived fields. Refresh
  expressions explicitly SELECT referenced fields to observe current transaction state.
- Nested REFERENCE is unsupported. Structural links are typed/untracked; business
  dependency references are top-level tracked fields.
- Typed COMPUTED arrays create automatic `.*` schema fields that block a later
  OVERWRITE. Generated dependency/readers fields remove that automatic definition
  before redefining the parent; source/framework declarations explicitly use OVERWRITE.
  The root-principal seed uses UPSERT; schema reapplication preserves existing facts.
- Defaults do not defeat forged CREATE metadata. Controlled VALUE initializes roots/shadows;
  `rebase_derived_ready` prevents live VALUE formulas from rerunning during rotations.
- Function arguments are unavailable inside PERMISSIONS WHERE on tested builds. The public
  query entrypoint checks argument-specific authorization inside its body. Public functions
  cannot elevate through private helpers; read helpers remain public with native data ACL.
- Mutation folds require a write transaction. Normal source events supply it and roll back
  every affected tree on failure. Concurrent writers conflict through owner revisions.
- Parser `$value` inside ASSERT is not a VALUE clause. Clause-aware analysis is essential
  to include validated amounts in source-change detection. Quoted SQL stays untouched.

`npm run probe:temporal-tree` exercises the compiled shared runtime; `--quick` reduces
random mutations. The independent sorted-source oracle verifies topology, height,
summaries, chronology, inherited shadows, live prefixes, range/rank queries, and rollback.
Full run: 240 seeded mutations plus deterministic deletion, authorization, timestamp,
concurrency, date-boundary, and schema-reapplication scenarios. `npm run probe:accounts`
reconstructs money/delivery/invoice/tax/FX/note/unit contributions and rule outputs from
authoritative inputs, including both invoice directions, claim recognition, direct versus
indirect tax, partial settlements, cross-tree edits and record auth. `npm run probe:suite`
reconstructs CRM lifecycle/effort and HRM allowance/employment/unit histories independently.
`npm run verify` also gates deterministic builds, schema validation, compiler, authorization,
runtime/effects, queues, adapters, and data probes. All use disposable instances.

Verification complete for the entity extension (49 tables, no aggregate views):

| Gate | SurrealDB | Result |
|---|---|---|
| Full `npm run verify`, including Accounts, CRM/HRM and populated schema reapplication | 3.2.0 | Passed 2026-09-23 |
| `npm run probe:accounts`, including record auth and populated schema reapplication | 3.2.4 | Passed 2026-09-23 |
| Shared temporal probe (`--quick`) and `npm run probe:suite` | 3.2.4 | Passed 2026-09-22 |

Both current Accounts runs include rollback regressions for invoice-scoped notes:
creating or moving an unlinked correction, changing its source, and assigning an
invoice to a mixed populated note. Unscoped grouping and restoring a valid scope
also pass the source reconstruction. These are correctness/consistency probes,
not throughput benchmarks.

```sh
npm run build && npm run build:all-in-one && npm run verify
REBASE_TREE_SURREAL_BIN=/path/to/surreal node dev-tools/temporal-tree/probe.js
REBASE_TREE_SURREAL_BIN=/path/to/surreal node dev-tools/accounts-probe.js
REBASE_TREE_SURREAL_BIN=/path/to/surreal node dev-tools/suite-probe.js
```

Historical scalar baseline (`a5eb8f8`, both versions): 260 seeded mutations; ascending
32/64/128/256 inserts produced heights 6/7/8/9; one historical edit changed all 64 later
live charges. The duplicate prototype was removed; current probes use production code.

## Composition boundary

CRM case lifecycle and HRM allowances are implemented sibling examples. Warehouse,
manufacturing, ecommerce, marketing and communications can reuse the same principal/
organization/currency/resource/rule kernel; they are not complete suite products.
Manufacturing consumption/production can compose resource transfers. Interval scheduling
requires explicit timezone, calendar policy, window/cursor and idempotency; passage of time
does not trigger record reactivity. External communications use the effect runtime,
outside synchronous calculation guards. Legacy standalone design examples are not imported
into this profile. Keep one shared AVL; do not restore replay/position tables, opening
fields, invoice locks, registries, or compatibility layers. Edit native declarations.

The generated strict profile exceeds `/sql`'s default request-body limit. Import through
SurrealDB's import interface or split DDL at parsed statement boundaries (`applySchema`
in the probe harness). Reapplication is tested on populated databases. Formula-definition
changes still require explicit refresh of existing affected facts; no hidden migration
or data-rebuild subsystem is implied.
