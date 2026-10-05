# Tenant/tree redesign: execution handoff

Updated 2026-10-05. **Status: backend T0–T6 complete; ready for lead review.**
All required local backend gates passed. Use the
[dated evidence](evidence/2026-10-05-tenant-tree-verification.json) and
[archived output](evidence/2026-10-05-tenant-tree-verification-output.txt) with the
final status below. This route takes precedence over older K/H/DX completion
sections. MetaSol implementation remains a separate deferred packet.

## Checkpoint and evidence boundary

This section records the original 2026-10-04 source review. The executed
2026-10-05 acceptance is recorded under [Continuation](#continuation--2026-10-05).

- ReBase HEAD: `eb001a2`. At review start: **141 tracked modifications and 17
  untracked files**, including substantive new source. Preserve all of them.
- MetaSol is a separate ignored repository, clean at `ada483e`. Its implementation
  was not reviewed or changed in this handoff. It still needs the later tenant
  compatibility packet; older browser passes do not establish compatibility.
- Node is `v22.23.2`; installed SurrealDB and `.surreal-version` are **3.3.0**.
- The [checkpoint inventory](evidence/2026-10-04-tenant-tree-handoff.json) records
  both heads, pre-handoff paths, critical source hashes, and attachment hash.
  It is a source snapshot, **not a test result**. No application tests ran during
  this lead review. The prior conversation reports focused passes but ends
  during delivery-tax/reference integration, without a complete current result.
- User context: attachment `b7109afa-bf90-4215-ba2d-34a7542b96f9/Pasted text.txt`.
  Its last addition requires dependent fields to follow actual dependencies,
  independently of alphabetical field names. The interpretation below preserves
  that requirement without replacing existing working machinery.

Read this guide and [the design decisions](tenant-tree-redesign.md) first.
Open only the active packet's sources and its named contract. Keep a small
progress record here with changed files, exact checks and next action; do not
restart the historical redesign or reread every old conversation.

## Meaning to preserve

| Concept | Implementation boundary |
| --- | --- |
| Entity, component, contribution | Roles of ordinary typed records, not a new object/inheritance framework. A record can participate in several explicitly declared trees. |
| Tenant | Parentless authorization principal in one design database. It is distinct from an economic organization, user identity, tree root and runtime database context. |
| Design deployment | One configured namespace/database per runtime. Tenants are records inside it; a client cannot select another deployment's database. Native NS/DB configuration still exists. |
| Ownership | `owned_by` determines immutable tenant. Authorized owner moves within that tenant remain possible. No hardcoded root group or implicit tenant provisioning. |
| Authorization | Current stored roles and a protected ancestor/descendant closure. Enforce same-tenant DAG parents, cycle rejection, deletion, diamonds and revocation. Token claims are not the permission source. |
| Readers | Immediate `owned_by` of declared membership roots, plus deliberately declared direct reader relations. Do not traverse AVL parents or recursively union another record's readers. |
| Ordered trees | Existing intrusive AVL, exact summaries and links. Explicit scalar/composite key types; default logical uniqueness; temporal roots explicitly permit duplicate timestamps. Stable source/slot identity is separate from the business key. |
| Query cost | Balanced seek O(log n), then O(k) links for k results. Total writes also include fan-out, dependent outputs, closure maintenance and contention. No universal logarithmic whole-transaction claim. |
| Aggregate privacy | Same tenant is necessary, not sufficient. Owner/reader permissions and explicit publication govern aggregates and tree pages. |
| Dependencies | Pure same-record calculations use dependency order. Cross-record causal updates and required-output lifecycle are separate contracts. Ordinary references/tree memberships are not automatically calculation edges. |
| Accounting | Preserve independently chosen real/receivable/payable contributions, exact decimals, complete-time guards, atomic outputs and source provenance. Tenant ownership does not replace economic identity. |
| Runtime | UUIDv7 is a default ID choice, not authorization or idempotency. Live notifications wake durable work; reconciliation and atomic queue admission remain necessary. |

The newer backend contract supersedes `visibility`, descendant arrays,
namespace-per-tenant routing and `rebase_group:root` provisioning. Classify old
occurrences before editing: historical evidence and offline typed-ID examples
are not active provisioning. Keep the native SDK, native schema and ordinary JS
modules. No new query DSL, generic object framework or frontend rebuild here.

## Current acceptance

| Slice | Present in source | Verified result / remaining boundary |
| --- | --- | --- |
| Tenant/auth | Principal closure, tenant fences, scoped identity indexes, verified-credential flows and actual WebAuthn verifier. | Record-token isolation/revocation, concurrency, scoped views and passkey verification passed in `verify-03`. |
| Compiler | Tenant generation; direct/nested reference guard; root-derived readers; typed/composite unique trees and bounded pages. | Nested/derived references, public read permissions, rollback, exact key types and uniqueness passed. |
| Dependency order | Existing topological resolver, private CREATE helpers and UPDATE refresh; managed outputs ordered by prerequisite references. | Reordered declarations, dependent-first deletion, live-root cleanup, cycle rejection and atomic rollback passed. |
| Runtime | Fixed design routing, v2 record locators, design queue prefix, tenant callbacks, live wakeups and recovery. | Disposable runtime/auth/passkey/live, queue/admission, scheduling, retention and webhook gates passed. |
| Accounting | Explicit tenants/duplicate policy and sales line tax outputs. | Complete `verify:accounting` passed. Invoice-wide inputs remain additive; purchase/withholding retain their separate models. |
| Frontend | Migration instructions only in this backend change. | Deferred implementation; do not certify the unchanged browser against this backend. |

## Source-review findings

F1–F4 below preserve the source-review diagnosis and acceptance requirements.
Their repairs or retained behavior are verified in the final continuation;
these descriptions are historical conditions, not unresolved current defects.

### F1 — aggregate view permissions lose the owner/reader boundary

`dev-tools/compiler/generators/reactivity.js` generates view SELECT permission
from authentication, `tenant`, and the source table's select permission. It does
not apply the owner/reader predicate in `security-policy.js`. The views in
`designs/test/views.surql` aggregate records by references, not necessarily by a
common readable owner. The difference is confirmed in source; the exact visible
disclosure must be demonstrated with ordinary authenticated clients.

**Decision:** aggregation must not silently publish otherwise private data to
every member of a tenant. Prove two sibling owners with the same table permission:
one cannot read the other's source rows or infer their private count/sum through
direct view SELECT or a generated `c_*` field. Test another tenant and an
anonymous caller too. Use an ordinary declared ownership/publication boundary
that the grouped result can actually enforce. If the compiler cannot establish
one, reject that view contract until it has an explicit policy. An intentionally
tenant-published aggregate must be an explicit design decision. Do not bolt a
source-row predicate onto an aggregate that no longer retains the needed scope,
or disable all legitimate views without replacing the fixture's intended use.

### F2 — managed output deletion follows table declaration order

`generators/temporal.js` enumerates `managedOutputs` in schema order;
`temporal.surql::sync_required_outputs` deletes obsolete rows in that enumeration
order. `claims/delivery-taxes.surql` and its contract explicitly rely on declaring
compound taxes before base taxes before lines. This is a confirmed ordering
coupling, distinct from the already working derived-field topological resolver.

**Decision:** supported causal outputs must be created after their prerequisites
and removed before those prerequisites, independently of table names, file names
and authored declaration order. Extend the existing bounded reconciliation path.
Use declared causal/required-reference dependencies among the managed outputs;
do not turn all business references into a DAG. Prefer compile-time ordering
where the existing contract determines it. If ordering depends on actual rows,
resolve it only within the source's finite output set. Reject unsupported cycles
with a clear error. Preserve stable IDs, per-child live snapshots, atomic refresh
and final validation; do not introduce another workflow engine.

Prove reordered declarations and renamed fixture tables, base/compound removal,
whole-source removal, replacement/rekey, and rollback when a required output is
still externally used. Keep the final source and every participating aggregate
unchanged after a rejection. Update the declaration-order comments only after
this behavior is implemented and verified.

### F3 — dependency clarification is mostly implemented already

`dev-tools/compiler/derived-order.js` topologically sorts annotated derived fields
from direct `$this.<field>` references and rejects cycles. Alphabetical sorting
only makes independent choices deterministic. `generators/temporal.js` creates
numbered private `__rebase_derived_*` helpers for the native CREATE path, then
evaluates UPDATE shadows in the same dependency order. Preserve these internals;
they do not require developers to alphabetize business fields.

`derived-order-probe.js` already reverses declarations and checks rollback and
private-field access. Run it on 3.3.0. Extend it only for a concrete missing case
from the new schema. The resolver does **not** infer dependencies hidden inside
arbitrary helper bodies, dynamic object access, or every unannotated native
VALUE expression. Keep dependencies visible or declare a small explicit supported
contract if a real use requires one; do not promise whole-language analysis.
`@rebase-depends` describes cross-record paths, not every opaque local formula.

### F4 — initial live-subscription failure is not retried

`gateway/server.js` attempts `startLiveWakeups` once and catches/logs failure;
`gateway/live.js` does not retry an initial `store.watch` rejection. Periodic
reconciliation preserves durable work, but live latency is lost until restart.
The existing probe tests reconnect after a successful subscription, not initial
attachment failure. T4 must add a bounded retry using the existing lifecycle,
with one active watcher, cleanup of partial subscriptions, and cancellation on
shutdown. Prove first attachment fails, a later attempt succeeds, reconciliation
continues meanwhile, and stopping during the retry delay leaves no timers or
watchers. Do not replace the durable recovery path with retries alone.

## Execution packets

These packets define the acceptance contract completed on 2026-10-05. Use the
final status and source hashes before selecting any further implementation or
reverification; the original imperative wording does not reopen passed gates.

Work in this order. One agent owns shared compiler edits at a time. A second
agent may inspect or verify independent runtime code with separate disposable
ports/directories. Do not run duplicate broad suites or competing database
fixtures. Routine repairs within these boundaries need no further lead approval.

### T0 — recover the actual checkout

Compare both Git roots with the checkpoint. Read `package.json`, `.surreal-version`
and the relevant configuration contract. Preserve newly authored untracked files;
never reset the worktree or delete probes because they look experimental. Use
the pinned installed binary. No dependency upgrade or reinstallation is needed
unless an actual mismatch is found. Record later user edits before touching them.

### T1 — close compiler authorization boundaries

Sources: `generators/{security,references,reactivity,tree}.js`,
`security-policy.js`, `framework/{auth,access}.surql`,
[tenant authentication](tenant-authentication.md), and
[ordered tree contract](ordered-tree-contract.md).

1. Resolve F1 with the smallest coherent view policy and regression.
2. Review the new reference guard on final materialized rows: direct references,
   optional references, unions, nested `lines.*.tax_components.*` arrays,
   derived references, missing targets, and same-tenant owner changes. Empty
   optional arrays must remain valid. Check create and update, including
   privileged writes; inspect source, audit and tree state after rejection.
3. Root/reader refresh must follow membership removal/move and root ownership
   change. A sibling owner, cross-tenant root or forged readers array must not
   widen access. Permission revocation must affect an existing record token.
4. Exercise public `fn::tree::read` with real record users. The current ordered
   fixture is core-only; its administrator success does not prove generated
   auth integration. Cover permitted page/seek, private roots/nodes, wrong
   tenant, no table permission, invalid slot/key, and direct helper calls.
   Preserve native field permissions; a private node may make a page fail.

Checks: `probe:tenant-auth`, `probe:tenant-records`, `probe:credentials`,
`probe:compiler`, `probe:ordered-tree`, plus the new focused view/reader cases
inside the nearest maintained probe. Do not create a second security harness.

### T2 — dependency and lifecycle correctness

Sources: `derived-order.js`, `generators/temporal.js`, `temporal.surql`,
`tree-contract.js`, and the derived/required/causal-output fixtures.

Implement F2; retain and verify F3. Preserve unique business-key enforcement
under root revision conflict, duplicate-time accounting roots, typed cursor
comparisons, multiple slots, native decimal precision and final rollback.
Test two independent sessions competing for one logical key, not just sequential
duplicate writes. Keep complete-timestamp guards specific to datetime trees;
a composite key with a preceding partition is not globally chronological.
The current ordered probe only validates the shape of bool, UUID and standalone
record keys. Add a small insert/find/page/rekey case for those advertised types;
the existing decimal/string/composite execution cases do not establish them.

Checks: `probe:derived-order`, `probe:required-outputs`, `probe:causal-outputs`,
`probe:typed-tree`, `probe:ordered-tree`, `probe:boundary-tree`, and
`node dev-tools/temporal-tree/positions-probe.js`. Broad DELETE of linked rows
remains unsupported: use sequential single-record deletes within one transaction;
prove the unsupported form rejects atomically. No general bulk-delete redesign.

### T3 — finish the sales delivery tax slice

Sources: `claims/{invoices,delivery-taxes}.surql`,
[delivery tax contract](../all-in-accounting/delivery-taxes.md), and
`dev-tools/accounting/delivery-tax-probe.js`.

The implemented meaning is tax on a **priced invoice line backed by a delivery**,
with line, invoice, customer-claim and tax-claim contributions. Recognition is
the issue timestamp, not an automatic rewrite to the physical movement date.
Keep per-line currency rounding, explicit provenance, stable `(issue, role)`
identities, and the current bounded one-stage compound formula.

This deliberately allows a physical delivery to be billed in portions: duplicate
`source` values with distinct line keys are not themselves invalid. Tax is per
priced portion, not once per physical delivery. Test a split source explicitly
and document the resulting rounding; preserve the aggregate billed-quantity
ceiling. Do not impose physical-source uniqueness or claim unbilled delivery tax
without a separate domain decision.

Prove manual/fixed/proportional inputs, `10.06 + 10.08` taxed separately at 10%
producing `2.02`, zero-precision currency, unchanged peer lines, reference/date/
quantity/tenant rejection, same-time settlement, and line/invoice/currency moves.
Add an actual second tenant with foreign invoice/tax-claim/rule references: the
current tax fixture only provisions one tenant, so generic nested-reference
coverage alone does not establish this accounting integration.
Verify replacement clears removed optional rule/amount fields. Direct managed
row writes must fail for record users. Compare all four roots and outputs to
independent source-derived expectations, including audit state after rollback.
Exercise populated schema reapplication and deletion after the T2 ordering fix.

Top-level invoice-wide tax arrays still exist. Selecting both levels posts both;
do not silently convert or merge them. Document and test empty, per-line-only,
invoice-only and both-selected behavior. Review purchase tax and withholding for
regressions and keep their old sources explicit; do not claim this sales slice
redesigned purchase taxes, unlimited tax-on-tax stages or jurisdictional rules.

Checks: `probe:delivery-taxes`, affected invoice/settlement checks, then final
`verify:accounting` in T6. Do not add CRM, HRM or new manufacturing scope.

### T4 — integrate authentication and durable runtime

Sources: `framework/{authentication,passkeys,webhooks}.surql`,
`gateway/{authentication,passkeys,live,runtime,store,directory,connection,server}.js`,
`gateway/queues/port.js`, `gateway/webhook-routes.js`, `config/environment.js`,
and [single-design runtime](single-design-runtime.md).

Verify tenant-scoped username/email/phone identities (same identity in two tenants
is valid), disabled/unverified users, role and identity revocation, bounded
one-use challenges and non-enumerating failures. Keep actual WebAuthn verification
of challenge, origin, RP ID, user verification, signature, tenant/credential
binding and replay; use synthetic local credentials, never a live provider.
Check the recent-auth enrollment and one-use exchange boundaries.

Record-only locators still need canonical native identity and scoped authorization.
Check UUID/quoted-ID equality using native values; no lossy string rewrites.
V2 envelopes and queue prefixes must prevent cross-design collisions. Callback
tenant, config and target must agree before credential use. Preserve durable
receipts, execution/revision fences and credential redaction.

Live hints must coalesce/bound pending IDs and recover after startup, socket
loss, overflow and reconnect. Keep periodic reconciliation and atomic admission.
Fix the first-attachment recovery gap in F4 and prove its shutdown behavior.
Use the existing `ws` transport choice; do not repeat the prior native-WebSocket
experiment without a new failure. Redis capacity testing is limited to existing
correctness regressions unless an observed defect requires more stress.

Checks: `probe:authentication`, `probe:passkeys`, `probe:runtime`, `probe:live`,
`probe:queues`, `probe:admission`, `probe:scheduling`, `probe:webhook-inbox`,
`probe:razorpay-refunds`. Provider calls stay mocked/injected.

### T5 — builds, fixtures and public contracts

Update all three profiles only as needed for shared compiler compatibility;
`all-in-accounting` is the active domain. Development fixtures must explicitly
provision a tenant before inserting tenant-owned rows. Preserve plain-JS
workbench entry points, exact typed values, and authored JSON-schema flexibility.
Keep private runtime contracts, credential fields and SurrealQL out of public
frontend exports; only deliberately public JSON validation schemas are exported.

Build all profiles before check mode. Retain build output/source separation and
atomic file replacement regressions. Run `test:dev-tools`. A stale generated
output means regenerate it, not weaken a compiler assertion. Do not mass-remove
historical IDs, useful probes or migrations that are merely syntax-checked.

### T6 — one final integration and evidence pass

Use an environment without personal `.env` or inherited provider credentials.
For these local scripts, a normal invocation is
`env -i PATH="$PATH" TZ=Asia/Kolkata npm run <script>`; inspect each harness's
disposable connection setup first and supply only documented fixture settings.
Never load a personal environment profile into the verification process.

Run the following final sequence after focused fixes stabilize:

```text
npm run build
npm run build:all-in-one
npm run build:all-in-accounting
npm run verify
npm run verify:accounting
node dev-tools/temporal-tree/positions-probe.js
npm run probe:razorpay-refunds
```

`verify` already covers the three checks, native schema validation and most
named backend probes; `verify:accounting` covers the domain matrix including
delivery taxes. The two explicit trailing probes are outside those aggregators
at this checkpoint. Review scripts if they change to avoid duplicate runs. A
focused check may count toward final evidence if its source/dependencies are
unchanged; do not claim a final suite passed if it stopped at an early failure.

Run database probes serially. Capture exit codes, elapsed time, actual versions,
raw log paths and final source/build hashes. Keep failures until resolved. Reuse
the existing evidence format in a **new dated result**, separate from this
source-review snapshot and 2026-10-03 results. Record exclusions and known limits.
No load benchmark, physical-capacity claim, production migration or provider-key
test is part of this acceptance.

Update this guide, `core-audit.md`, `core-handoff.md`, the readiness report and
relevant contracts together. Report **ready for lead review**, with any failed
or deferred gate named. Do not label the unchanged MetaSol compatible. Do not
push, deploy, or amend the user's history as part of verification.

## Frontend continuation and final lead review

After backend acceptance, follow the existing
[tenant frontend migration packet](../frontend/continuation-prompts.md#tenant-backend-migration--next-required-packet).
It covers fixed design configuration, explicit tenant identity, session/cache
and late-response fencing, new auth routes, removal of visibility assumptions,
typed ordered pages and delivery-tax provenance. This is subsequent work.

The final lead review should compare the checkpoint to the final diff, inspect
F1/F2/F4 and the nested-reference guard, match actual logs to source hashes, and
check permission/rejection oracles rather than accepting pass-count prose.
Rerun only missing or changed gates. Local evidence cannot establish provider
delivery, production capacity or the still-deferred frontend migration.

## Execution progress — 2026-10-04

Historical progress before the final integration; superseded by the table below.

| Packet | Current evidence | Status / next action |
| --- | --- | --- |
| T1 root/member reads and F1 views | Updated `generators/tree.js`, `tenant-record-probe.js`, and `ordered-tree-contract.md`. `npm run probe:tenant-records` passes against the disposable SurrealDB harness. It covers visible root/member reads, a declared reader paging a member they own, root-authorized stored summaries, denial on private-node traversal and member links, direct-helper denial, scoped view groups, ownership refresh, tenant/reference rollback, uniqueness, and populated reapplication. Native slot queries enforce table/field policies directly, avoiding a second implementation of private `readers_index` logic. | Focused packet complete for this pass. No claim about all compiler or integration probes yet; retain F2 and full T6 gates. |
| T2 causal managed-output order and typed keys | Current source still deletes managed outputs in authored/schema order; ordered-tree runtime coverage for bool, UUID, and standalone record keys is incomplete. | In progress: dependency-ordered create/delete, rollback/lifecycle regressions, and typed runtime cases. |
| T3 delivery taxes | Split-source rounding, quantity ceiling, second-tenant reference rejection, additive tax modes, and same-time settlement were added to the probe and contract. Static syntax/whitespace checks passed; no probe run yet. | Await T2 deletion-order fix, then run the focused delivery-tax probe and accounting checks. |
| T4 live recovery | `npm run probe:live` passed after an injected SDK mock correction. It covers failed initial attach/retry, reconciliation, shutdown/partial cleanup, committed notifications, socket loss/reconnect, and resubscription. | Focused packet complete. The SDK has no attach-cancel signal; shutdown waits up to its configured attach timeout and late resolution cleans itself up. |
| T5/T6 integrated builds and verification | Not run. | After T2/T3 integration, inspect scripts and run the non-provider backend acceptance sequence serially. Preserve the pinned local SurrealDB version and keep MetaSol deferred. |

## Continuation — 2026-10-05

Recovered ReBase `eb001a2` with 145 tracked modifications and 19 untracked
files; MetaSol is unchanged and clean at `ada483e`. The preserved starting diff,
source hashes and raw command logs are in
`/tmp/rebase-tenant-tree-20261005-vmr9wyb4`. The 2026-10-04 progress table above
is historical where the following repairs supersede it.

The [final evidence](evidence/2026-10-05-tenant-tree-verification.json) records
commands, exit codes, elapsed times, versions, source/build/document hashes and
archived raw output. All required backend gates passed.

| Packet | Final acceptance | Status |
| --- | --- | --- |
| T0 checkout recovery | Preserved the initial dirty/untracked work and baseline patch; separate MetaSol remains clean at `ada483e`. | Complete |
| T1 compiler authorization | Tenant/closure/revocation, scoped views, root/member privacy, nested/derived reference guards and rollback passed in `verify-03`. | Complete |
| T2 dependency and trees | Managed prerequisite order, live-root removal, typed/ordered oracles and independent-session uniqueness passed; explicit positions gate passed 221 mutations, 1,084 reads and 12 rejection snapshots. | Complete |
| T3 delivery taxes | `accounting-02` passed all existing accounting gates and delivery taxes: 20 mutation checkpoints, nine full rollbacks, four tax modes, same-time settlement and complete cleanup. | Complete |
| T4 authentication/runtime | Authentication, passkeys, credentials, runtime, initial live retry/reconnect, queues/admission/retention, scheduling, webhooks and mocked refunds passed. | Complete |
| T5 builds/tooling/contracts | All three profiles built and checked; native validation, 26 developer-tool tests, 84 JS syntax checks and updated public/frontend contracts. | Complete |
| T6 integration/evidence | Full backend and accounting suites plus explicit positions/refund gates passed; evidence and handoffs identify final bytes and excluded work. | Ready for lead review |

- T1: the tenant-record probe passes current owner/reader privacy, owner-only
  scoped views and computed fields, real foreign-tenant tree reads, optional,
  union, nested and derived references, and source/root/audit rollback. The
  scoped-view generator now inherits the configured source select policy.
- T2: native `??` precedence in generated reverse/inclusive seek expressions
  was reproduced and fixed. Ordered trees passed 683 reads/pages, including
  bool/UUID/record keys and independent-session uniqueness. Typed trees passed
  113 mutations, 1,101 reads and 105 rejection snapshots. Required-output,
  causal-output, derived-order and boundary probes passed. A later managed-root
  regression also passes: deleting a prerequisite after its children uses live
  node counts, and the final sweep ignores roots removed by the same transaction.
  Publication and final guards remain at the outer transaction boundary.
- T3: `delivery-03` and final `accounting-02` passed all 20 mutation checkpoints and 9 full rollback
  snapshots, including currency/line moves, four input modes, same-time
  settlement and complete cleanup. The fixture issue belongs to its writer,
  preserving native deletion rules. Both managed-root and tax source snapshots
  use `WITH NOINDEX ORDER BY id`: 3.3.0 returned duplicate rows from an indexed
  ID-order scan in the multi-reader fixture. The raw reproduction is retained;
  no database upgrade or blanket index removal was performed.
- T4: final `verify-03` passed authentication, tenant authorization, passkeys,
  credentials, architecture, queues/admission/retention, runtime, live retry and
  reconnect, scheduling, webhooks and adapters. The earlier `verify-02` stopped
  at the temporal case below; its failed attempt remains in the evidence.
- Final-suite repairs: the OAuth compiler assertion now allows verification of
  an existing identity while rejecting provisioning and unrelated mutations.
  A native authenticated charge CREATE exposed a VALUE expression using the
  newly private prefix helper. The fixture and three all-in-one formulas now
  use `fn::tree::read`. Authenticated system sessions use the same API through
  a private-getter permission check; guests still fail, including with guest
  queries enabled. `temporal-quick-01` passed record create/update, hidden-prefix
  rollback, private-helper denial, 36 randomized mutations, concurrency and
  populated reapplication. Local derived-field ordering remains unchanged.
- T5: all three profiles were rebuilt after that reader change. Final
  `syntax-final-02` checks pass for all 84 changed/new JavaScript files, including
  the last H7 probe repair. No personal environment profile was loaded.
- T6: `verify-03` passed the complete `npm run verify` sequence in 1,006.086
  seconds, including the three profile checks, native validation, every named
  backend probe, populated reapplication, and all 26 developer-tool tests.
  Start/end source fingerprint:
  `be508bbb8f8e903e4f38df0891564a48132de21780944e8c171c957a5a31966f`.
- The first full accounting attempt stopped at handwritten H7 feasibility roots
  that omitted `root_unique`. Those adapters now explicitly permit equal
  timestamps. Only `dev-tools/accounting/h7-gross-input-probe.js` changed after
  the retained builds and backend pass; their production and executed test
  dependencies remain byte-identical. The focused H7 rerun passed, followed by
  complete `accounting-02` in **694.793s**, `positions-01` in **291.274s**, and
  mocked `razorpay-01` in **1.028s**, all exit 0. Final source fingerprint:
  `bcbecccc86c04ce6fb9bac0c4516a7b607b9b782378915203506c02160ade585`.
- The evidence records this exact source difference rather than relabeling the
  earlier backend pass as a run after the H7 change. Builds and full verification
  were retained because they do not load that isolated probe. No failed suite
  attempt is counted as a pass.
- Next: review the coherent local backend commit against these hashes and logs.
  MetaSol migration, live providers, production deployment/migration and capacity
  remain excluded. The documented 3.3.0 ID-order source-scan workaround remains.

## Prompt for lead review

```text
Review the completed ReBase tenant/tree backend T0–T6 commit. Read
designs/rebase-system/tenant-tree-handoff.md and
designs/rebase-system/evidence/2026-10-05-tenant-tree-verification.json with its
archived output. Inspect Git in ReBase and the separate ignored MetaSol repo.
Compare final source/build hashes before rerunning anything. The retained builds
and backend suite differ only in the isolated H7 probe they do not load; full
accounting, positions, refunds and final syntax passed after that fixture repair.

Review F1 scoped views, F2 managed dependency/live-root cleanup, F3 retained
derived ordering, F4 initial live retry, nested references and native public
reader permissions. Check independent source/rollback oracles and the documented
SurrealDB 3.3.0 indexed ID-order scan limitation; do not deduplicate its output.
Rerun only missing or changed gates with disposable services and mock providers.
Keep MetaSol migration separate and retain its continuation packet. No live
providers, production migration/deployment, capacity claim or remote push.
```
