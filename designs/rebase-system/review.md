# Design review and resolved requirements

Current scope and later user corrections are in the
[core handoff](./core-handoff.md). Core stabilization precedes further domain
work. The historical attachment review below remains design context; its
scope statements do not authorize current application implementation.

Status: reviewed design, updated 2026-09-26. This is the decision record for the
[implementation plan](./plan.md). Target behavior is specified in
[foundation](./foundation.md), [operations](./operations.md), and the
[domain blueprint](./blueprint.md). These documents do not describe a completed
compiler/runtime rewrite.

## Source and precedence

Reviewed the complete 269-line attachment `5928ecdb-5c0b-4b1c-b66a-babc4f251a69/Pasted text.txt`.
SHA-256: `d0137490c6bc871c32580bb6f86655e71fd3b5130826d3b2005e456640e98452`.
Lines 151–198 quote an earlier conversation; they are context, not fresh test
evidence. The later instructions at 200–269 take precedence over earlier
restrictions. In particular, CRM/HRM are back in scope, breaking changes are
allowed, and a complete foundation plan comes before application implementation.

## Recommendation

Redesign the boundaries and authoring contract. Keep the augmented AVL
mechanics and native SurrealQL. The project needs fewer implicit policies and
clearer ownership of state; replacing the tree algorithm or adding a general
workflow/formula interpreter does not resolve those problems.

The target has four independently understandable parts:

1. Native typed records and references describe authoritative facts.
2. Ordered memberships and associative summaries maintain exact calculations.
3. Explicit field dependencies settle a synchronous database write.
4. Typed operation records and adapters perform external work outside that
   transaction, with durable retry and receipt handling.

## Requirement map

| ID | Source lines | Resolved requirement | Specification / acceptance gate |
|---|---|---|---|
| R01 | 207–216, 251–259 | A record can participate in several ordered classes. Table identity, membership identity, mutable order, and owner instance are separate. | Foundation: composition; C1/C2. |
| R02 | 200, 255–259 | Trees order native comparable values, including non-temporal values. Start with datetime and guarded integer keys; decimal transport gets its own gate. | Foundation: key contract; C1. |
| R03 | 125–131, 259 | One record may have multiple positions in one tree. Interval endpoints are separate slots; same-key real legs can be explicitly netted. | Foundation: membership and summaries; C2. |
| R04 | 127–143, 259 | Constant-width root guards after logarithmic maintenance; exact historical/future constraints. | Foundation: summary laws; C2. |
| R05 | 211–218, 263 | A small compiler understands structural contracts, emits native SQL, and makes choices at build time. No business formula interpreter. | Foundation: compiler passes; C3. |
| R06 | 213–220, 247 | Field-only audit inclusion, a distinct value-free change marker, no include/omit/redact precedence. | Foundation: annotation contract; C4. |
| R07 | 220–224, 241 | Fixed framework principal names; native privacy; remove principal/internal/auth-private marker dialects. | Foundation: identity/permissions; C4. |
| R08 | 222, 265 | Readers exist under both select policies; only explicitly marked direct parents contribute their owners. | Foundation: readers; C4. |
| R09 | 224, 249; later user clarification | Two reusable email/phone credential families support root-group-owned platform records and tenant BYOC. Developers provision/bind them; no automatic core provisioning. Runtime bootstrap credentials remain infrastructure configuration. | Operations: credentials; core K4. |
| R10 | 226–230, 238 | One-shot scheduled task per record; due time and priority have different meanings. No repeat/cron occurrence subsystem. | Operations: scheduling; O2. |
| R11 | 228 | Bound Redis work; leave deferred accepted tasks in the database for reconciliation. | Operations: admission; O2/O3. |
| R12 | 230–234 | One context/identity convention, fixed handler dispatch, typed per-state functions and provider adapters. | Operations: envelope and dispatch; O1/O2. |
| R13 | 236, 241 | Native Node HTTP, JS composition tools, one configuration boundary. | Operations / Foundation: repository layout; O1/D1. |
| R14 | 240–241 | Rename effects to operations; declare execution mode and CRUD events together. | Operations: authoring contract; O1. |
| R15 | 243 | Test with local mock providers and disposable storage, including signed webhooks. | Verification matrix; all runtime gates. |
| R16 | 245 | Make a coherent breaking cutover; remove retired surfaces after replacements pass. | Plan: cutover; D1. |
| R17 | 259–261 | Small function-vs-inline measurement and bounded algorithm review; no write-amplification probe for this question. | [Verification](./verification.md); current research. |
| R18 | 261, 265 | Keep calculation causality separate from tree links and reader inheritance. | Foundation: dependency contract; C3. |
| R19 | 267–269 | Plan the foundation first, then complete domain designs using the same primitives. | Plan; [applications](./applications.md). |
| R20 | 103–149, 200 | Accounting/billing/logistics/manufacturing and independent CRM/HRM modules. | Applications and [accounting plan](../all-in-accounting/plan.md); A1–A5. |
| R21 | 133–147, 251 | Real/receivable/payable are economic effects projected into trees. They are not framework-level graph-edge types. | Applications; existing accounting blueprint. |

Gate IDs refer to [the work plan](./plan.md). A decision is not an implemented
feature; its gate needs independent evidence.

## Corrections that preserve the intent

| Proposed shortcut | Engineering decision and reason |
|---|---|
| All tables/trees form a DAG. | Calculation dependencies must be acyclic. AVL parent/child and predecessor/successor links are reciprocal; the whole storage graph is not a DAG. Ordinary references have their own domain constraints. |
| Split every conditional into a new table. | Split when required fields, permitted endpoints, lifecycle, or formula dependency changes. Labels, ordinary algorithm branches, and user-defined status records do not automatically need new tables. |
| The compiler should know nothing. | It should know types, ownership, dependencies, and legal compositions. Those checks remove ambiguity; it should not embed GST, invoice, CRM, or payroll policy. |
| OCC makes everything atomic. | It can reject conflicting database writes when the relevant invariant has a write fence. It does not roll back an HTTP request or automatically validate a complete multi-statement business recipe. |
| A full key is an object's identity. | The record/slot identity stays stable when a score or date changes. The sort key is an index position, not identity. A record ID is scoped by namespace and database. |
| A higher numeric priority means more urgent. | BullMQ processes smaller positive priorities first, and unprioritized/zero-priority work before them. Use explicit positive priorities for every job. |
| A delayed task executes exactly at its time. | The time is earliest eligibility. Worker availability, clock precision, retries, and queue load can make execution later. |
| The reconciler makes any dropped message safe. | Only a message reconstructible from committed database state can be dropped. A webhook body must be durably accepted before acknowledgement. |
| Deleting a schedule cancels an external action. | Deletion invalidates unclaimed work. An in-flight provider call can already have happened; keep its execution record and reconcile the outcome. |
| A hidden URL or DNS name authenticates SurrealDB. | Authenticate internal calls with a configured service secret or an equivalent enforced private transport. Ordinary DNS settings and URL secrecy provide no caller authentication. |
| `SELECT NONE` makes credential use safe by itself. | It hides reads, not client writes, log copies, or arbitrary privileged execution. Also constrain writes, config references, handler capabilities, and audit projections. |
| Settling a payable creates a receivable. | Settlement reduces the same payable. A separate credit/advance requires an explicit economic basis. Receivable/payable are not synonyms for double-entry debit/credit. |
| A liability is the minimum treasury balance. | Recognition, maturity, liquidity forecasts, and treasury funding are different dimensions. Store those distinctions without imposing statutory accounting policy in the engine. |
| Tree maintenance and root validation are both O(1). | Reading a bounded published summary is constant-sized. Maintaining it costs logarithmic path work per position, plus all dependent refreshes and database I/O/conflicts. |
| Appending until imbalance reaches 6–8 is an obvious optimization. | That changes the balancing guarantee and write bursts. Keep AVL until an equivalent durable workload demonstrates an improvement from another policy. |

## Code findings at the original design review

For current independent findings and preserved/corrected decisions, use the
[2026-09-26 core audit](./core-audit.md). Several runtime descriptions below
predate the one-shot/single-queue implementation.

- `src/temporal.surql` separates AVL mechanics, membership synchronization,
  causal refresh, and final validation. Reuse the mechanics.
- `src/tree-contract.js` and `src/generators/tree.js` now require explicit
  `datetime`/`int` keys and finite owner targets. C1 replaces the implicit global
  unions with exact table/slot assertions, grouped by table to avoid excessive
  expression depth in the existing accounting profile.
- Membership coalescing still groups by owner and rejects different keys in one
  source/owner pair. Reusing slot storage alone does not implement intervals.
- `src/derived-order.js` resolves local derived fields into a topological order.
  Private initial-value shadows and the refresh adapter preserve that order on
  CREATE and reactive updates; C3 verifies reordered declarations.
- Audit is selected on concrete fields. Value projections and value-free
  changed-field names share one synchronous `audit_mutation` event path. CREATE
  and DELETE retain lifecycle entries when an optional selected leaf is absent;
  rejected writes do not commit audit rows.
- Annotation parsing supports exact nested leaf audit paths and rejects
  overlapping/container/wildcard selections. Nested tree storage remains
  unsupported; retired principal, internal, and audit-redaction markers are
  rejected with native replacements.
- Principal names are fixed to `rebase_user` and `rebase_group`. Reader
  generation uses only explicitly marked direct reference fields, adds each
  direct parent's owner to a private computed index, and does not copy parent
  indexes. Cascades follow those references on owner changes; direct and
  multi-row reader cycles are rejected.
- `gateway/` now uses the native Node HTTP listener (O1a), while three queue
  lanes, repeat schedules, retries, webhooks, and provider dispatch remain. The
  native JS compiler API already exists
  underneath CLI wrappers; expose and organize it instead of inventing another
  compilation implementation.
- Provider credentials are already partly stored in typed rows. Platform
  Resend/Twilio recovery configuration is a second path to remove. Existing
  lease claims, scoped loads, output allowlists, and signature adapters are
  useful pieces to retain.

The initial worktree contained unfinished source and design changes. Preserve
that work and update its status honestly. The current [verification record](./verification.md)
records fresh checks separately from the historical integer fixture results.
