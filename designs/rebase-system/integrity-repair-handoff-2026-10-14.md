# Integrity repair: lead decisions and Luna execution handoff

**Status: implementation and fresh accounting acceptance complete; final commit
and push pending.** The original diagnosis is preserved below; §8 records the
reproduced causes, repairs, tests and current limits.
The original lead handoff was prepared against `17f956bfcad7f7f9731bb08a4abba11d1b995cc8`
with a clean working tree. The execution recorded in §8 began from
`98a54ada496f1c15712ad1ed3c7d6d8ee820aa28` and changes compiler and test code.

The user explicitly requested a lead-model investigation followed by execution
with Luna to conserve resources. These instructions governed the execution
recorded in §8. Breaking changes are authorized; the application is not deployed
and backward compatibility is unnecessary. Use disposable databases. Read
current Git status before editing, preserve intervening user changes, and do
not touch the application's `.env`, live database, provider services, or
deployment. The user's later explicit request authorizes pushing the final commit
to `main`; deployment remains out of scope.

## 1. What the user actually wants

These conclusions come from the user's statements across the exported chats,
their referenced attachments, and the latest instructions, rather than the old
agents' proposed plans.

- A declarative calculation engine: author strict tables, formulas, memberships,
  and constraints, then let the compiler maintain derived values and aggregates.
  A membership can exist for analytics without imposing a business constraint.
- Automatic dependencies for supported ordered and record reads. The developer
  writes the calculation once, not a separate inverse/impact function. Reading a
  predecessor watches its value AND the gap where a new predecessor can appear.
  Prefix aggregates depend on earlier contributions, not just the last record.
- Dependencies follow actual helper calls and branches, including empty reads,
  fallbacks, date changes, parent changes, and deleted sources. Their identity is
  a logical query, independent of physical AVL rotations.
- Accurate, deterministic, synchronous transaction closure. Invalid formulas,
  cycles, tenant violations, and business constraints roll back the entire
  transaction, including private metadata. Valid operations must succeed.
- Sparse accounting dimensions, native quantities separate from dated reporting
  values, shared dated FX sources, generalized adjustments, and linear temporal
  constraints. Receivable/payable postings retain their positive directional
  meaning. Invoice documents group calculations; they are not compliance flows.
- Less developer effort and less unnecessary work. Complexity claims must include
  candidate discovery, consumed-value comparisons, calculations, and writes.

The October 14 automatic-read request supersedes the October 13 authored-impact
approach. Do not revive `@rebase-impact`, ask applications to declare FX reader
trees, or add per-table dependency repair events. Rootless trees, new business
modules, frontend migration, storage-engine replacement, and deployments are
outside this repair. Permission to redesign is latitude to simplify, not an
instruction to replace a working abstraction without evidence.
`gateway/reconciler.js` processes background effects; repairing calculation
closure through an asynchronous queue would violate this transaction contract.

## 2. Evidence and what remains unknown

The stress attachment contains an embedded JSON report, not just prose. It names
the current commit. Its counts reconcile: 564 generic operations, 18 expected
rejections, 54 accounting mutations with 3 unexpected FX rejections, and a final
audit of 69 tables / 48 populated accounting tables / 343 roots / 807 reachable
nodes / 895 typed references. All 54 accounting mutation snapshots retained the
same missing successor already present in their baseline. Their arithmetic
checks report no errors; this is not a clean structural acceptance campaign.

The local `/workspace/accounting-lab` directory and its scripts are absent.
Therefore the lead reviewed supplied error logs and current source but did NOT
independently reproduce the original database writer failures. The embedded
report lacks the full initial fixture, raw before/after snapshots, and the early
cached-summary failures. Do not invent these or claim the precise root cause is
known. The two failures may share a cause, but this is unproved.

Original reproductions to preserve if their artifacts become available:

```surql
CREATE exchange_rate:targeted_early SET owned_by=rebase_tenant:default,
  pair=exchange_pair:eur_inr,rate=13dec,
  effective_at=d'2027-01-02T00:00:00Z';
-- REBASE_READ_INDEX

CREATE issue_adjustment_net_tax:stress_purchase SET
  owned_by=rebase_tenant:default,source_tax=issue_net_tax:stress_purchase,
  adjustment=issue_adjustment:stress_purchase,
  effective_at=d'2027-01-12T00:00:02Z';
-- AVL_MISSING_SLOT:rebase_read:[...exchange_pair:usd_inr, 'z_rates',
-- 'latest', 'measures:rate'...]/z_position
```

The FX report identifies a missing `next` from the EUR/INR reader belonging to
`purchase_issue:f` at January 6 + 1ns to `invoice_settlement:f_purchase` at
January 9 + 1ns. Updating the pair's fallback works; a January 2 quote fails;
a January 7 quote and its deletion work. The purchase adjustment failure is
reported three times from a healthy final snapshot, each with full rollback.

The three accounting FX attempts retain raw `rollbackError` comparisons.
Their recorded state digests equal the preceding committed digests. The report
attributes comparisons to row ordering and claims an identity-based recheck.
The missing snapshots prevent independent confirmation. Canonicalize snapshots
by record identity before asserting rollback in the new harness.

### Lead's fresh checks

The current private oracle accepted six deliberately corrupt synthetic inputs:
missing successor, wrong leaf count, wrong root first key, stale cursor, reads
whose group was removed, and all registrations/frames/groups removed. Its valid
control also passed. Reproduce the inspection with:

```bash
node designs/rebase-system/evidence/2026-10-14-integrity-oracle-diagnostic.cjs
```

This is an oracle coverage diagnostic, not a database fixture or writer repro.
The last mutation requires an independent expected-read inventory: validating
only metadata that survives can never detect that all metadata disappeared.
The synthetic control describes the existing checker's input contract. For new
rejection tests, construct fully valid schema snapshots, including newly required
fields; rejecting an incomplete control is not evidence of detecting corruption.

A static compiler check also confirmed a hidden-helper scheduling gap:

```surql
DEFINE FUNCTION fn::lead_probe::total($row: object) {
  RETURN $row.z_rate * 2dec;
};
-- z_rate VALUE $this.input COMMENT '@rebase-derived'
-- a_total VALUE fn::lead_probe::total($this) COMMENT '@rebase-derived'
```

`resolveDerivedOrder` returns `[a_total,z_rate]`; the formula requires
`[z_rate,a_total]`. This check did not execute the full generated CREATE path.
Packet C must cover both that initial path and later runtime derivation.

A disposable native SurrealKV microprobe on SurrealDB **3.3.0** also showed:
`PATCH add` of an existing object slot replaced that object, and `INSERT IGNORE`
on an existing record returned `[]` and preserved its stored node. These simple
controls do not prove the full generated-schema/event behavior. They do rule out
assuming that either operation is inherently corrupt in the tested simple case.
The prior accounting evidence also records 3.3.0 / Node 22.23.2.

Historical acceptance at this commit recorded 103 accounting checkpoints and
51 rollbacks, plus 50 generic checkpoints and 7 rollbacks. Those bounded runs
remain useful history; their incomplete private-index checks do not certify
this repair. Do not rewrite the historical evidence to say it tested more.

## 3. Probe audit: concrete gaps and trustworthy parts

| Area | What current code checks | Missing evidence / required change |
| --- | --- | --- |
| `temporal-tree/oracle.js` | Business source facts, leaf/subtree/root aggregates, owner/parent/BST/AVL, reachability, `prev` and `next` | Add rejection controls for each invariant; use schema declarations to inventory empty roots and slots rather than relying entirely on object shape. Numeric aggregate comparisons currently use Number/tolerance. |
| `temporal-tree/read-oracle.js` | Existing cached read results, live reader/source, generation, active index reachability, height/count/first/last, interval maximum end | Missing neighbour checks, complete leaf/root summaries, cursor and inactive-root checks, read-to-group existence, and expected subscription coverage. Fresh diagnostic demonstrates false acceptance. |
| `temporal-tree/observed-probe.js` | Formula outputs, selected affected calls, branches, interval shape, concurrency, permissions, rollback | Skips structural validation for ALL non-range groups. Duplicates a weaker interval oracle; does not inventory every expected read. Replace this duplication with a stronger shared checker plus independently authored fixture footprints. |
| `accounting/source-oracle.js` | Independently replays source equations using rational arithmetic for derived amounts; expected business memberships | Tree measures are converted through `.number()` into the tolerant tree checker. Metadata coverage is delegated to the incomplete private oracle. Snapshot list includes accounting, audit, and four read tables, not every framework table. |
| Typed/ordered/tree probes | Call the business structural oracle and test real ordered queries | Their success is valuable for those fixtures; it does not exercise shared private registration histories. Add the repaired private checker whenever subscriptions exist. |
| Compiler / derived-order checks | Determinism, generated contracts, lexical direct field dependency graph, tested helper capture | A helper receiving `$this` can hide local derived-field inputs from `resolveDerivedOrder`. Raw SELECT and impure helper behavior are not established as tracked dependencies. Add positive/rejection cases for the supported boundary; do not claim arbitrary SurrealQL is automatically reactive. |
| Required/causal outputs | Business output lifecycle and rejection snapshots in their fixtures | Include private reads, groups, frames, locks and publication-induced invalidation when these features compose. |
| Authentication/runtime probes | Their own contracts, including mock/service behavior in some probes | Distinguish static/mock checks from actual DB actor checks. Their pass does not certify dependency topology. Audit read isolation using root and restricted actors in the repaired fixture. |

The full probe suite was NOT rerun in the lead turn. This is a source audit plus
the fresh targeted controls above. Strengthen existing useful probes; do not
delete them or label all prior results useless.

## 4. Architecture decisions for implementation

Keep the operator-based logical subscription API: `fn::tree::read_value` and
`fn::record::read_value`, transitive helper capture, and separate refresh/validate
generations. Keep typed source order and sparse reverse indexes. Preserve the
existing accounting equations unless an independent domain check finds a defect.

Repair the common writer/lifecycle first. In particular, investigate
`fn::reads::{remember,remove,end,forget}`, `fn::tree::{sync,insert,remove,put,patch,
replace,rotate,repair,publish}`, and generated tree fields. A cached BEFORE image
can define old contributions; it must never overwrite the current topology after
neighbour writes or rotations. New and already-live registrations must be
distinguishable and duplicate reads must be idempotent.

Also simplify reverse point enumeration: use bounded in-order traversal of
`left/right/key` with lower/upper comparisons and pruning. Avoid deriving a row
count from summaries and then following `next` that many times. Match existing
boundary semantics explicitly, including full versus partial keys. A balanced
point tree gives O(log R + k) traversal for k matches. This removes redundant
dependencies from enumeration, but is NOT permission to leave corrupt threads
or summaries behind: the common writer and structural gates must still pass.

Do not remove `prev/next` globally in this packet. Public paging and legacy
chronological drain still use them. If a later architectural change removes
threads, update every consumer and test before removing their invariant. Do not
silently fall back to full scans, rebuild trees on every write, suppress the two
errors, or mark these valid operations as expected rejections.

Do not restore native primary-ID temporal range scans. The earlier accepted
investigation found a native range omitted a date + 1ns record despite its
logical comparison ordering. Exact group-prefix lookup and equality are a
different access path and need their own controls. Preserve source/subscription
fences and transactional conflict handling when changing registration.

## 5. Ordered execution packets

### A. Build the trustworthy oracle first

1. Implement one shared private structural checker and use it in both observed
   and accounting probes. Expected members come from logical read descriptions,
   not the maintained node's key or its neighbours.
2. Check read/group source-slot-kind-channel/tenant agreement; legal phase and
   operation; query position; observed value; current frame; exact active slot;
   no missing, duplicate, orphan, stale, or wrongly indexed subscription.
3. For BOTH point and interval indexes, check complete leaf/subtree/root values,
   heights and balance, key order, parent/child reciprocity, owner, unique
   reachability, correct `prev/next` and endpoints, and empty inactive indexes.
   Validate `end_key` only where present/required. Finished roots have no dirty
   marker/cursor and are not refreshing. Empty roots are still inventoried.
4. Add an independent expected-read set in each fixture/reference evaluator.
   Describe `(reader,phase,source,slot,operation,args,path,fallback)` from executed
   model branches. Assert exactly that set. Use source facts/model calculations,
   never production capture/invalidation code, to derive this inventory.
5. Create oracle rejection tests using valid controls and one mutation at a time:
   every demonstrated blind spot, dangling child, wrong parent/owner, cycle,
   duplicate child, missing node, wrong count/boundary/end maximum, stale frame,
   removed dependency with unchanged business values, and wrong inactive slot.
   Also prove that permutations of returned record rows do not change results.
   Keep a red baseline at `17f956b`, then retain the regression after repair.

Finish A even if the original external stress scripts cannot be recovered. It
should expose an existing product failure rather than redefining corrupt state
as normal. Avoid a test whose only expected values are copied from actual output.

### B. Minimize and repair the two writer failures

1. If `/workspace/accounting-lab` becomes available, preserve its exact fixture,
   source/schema fingerprints, first failing snapshots, and reproduction commands.
   Otherwise build repository-owned minimal fixtures from the maintained harness
   and the report's operations. Do not wait for an unavailable external path.
2. Start FX with one pair/fallback and at least two dated readers sharing its
   point group. Include January 6 and 9 readers, quote dates 2 and 7, +1ns read
   positions, nested/duplicate helper reads, and registration changes after
   recalculation. Check every setup write; find the FIRST mutation that breaks
   topology, rather than starting from an already-broken baseline.
3. Compose date/parent moves, fallback-to-quote transitions, quote deletion,
   re-registration, generation cleanup, and same-group insertion/removal orders.
   Assert candidate reads equal an independent brute-force selection and that
   every valid FX write commits with correct values and healthy metadata.
4. Reconstruct a purchase issue, base tax, net tax, issue adjustment and its
   net-tax child using a converted USD/INR posting. Start from a structurally
   healthy graph. The child creation must commit. Repeated failed attempts from
   an unchanged snapshot prove reproducibility but are not three independent
   histories; add multiple fresh construction orders after minimization.
5. Trace every relevant slot write and mutation phase in a disposable fixture:
   insert-versus-existing decision, group/frame generation, node materialization,
   neighbours, parents, root pointer, rotation/removal, publication and cleanup.
   Query CURRENT slots immediately around the suspected write. Transactional
   trace records disappear on rollback, so retain external transcript or enrich
   temporary failure diagnostics. Do not inspect only the final rolled-back DB.
6. Prove where the state first diverges. If native INSERT/PATCH/record-ID handling
   is suspected, reduce it to a tiny native schema before blaming the backend.
   The lead's simple native controls passed; no backend cause is established.
7. Fix the common lifecycle/mutator that produces the divergence. Ensure a new
   read is materialized and indexed once, an existing read updates only consumed
   value/generation, and removal unlinks the LIVE node before deleting metadata.
   Multi-slot deletes must thread the updated detached frame through every edit.
   Add cheap local pre/postconditions for affected edges where useful, without
   running a full-tree audit inside each application write.
8. Implement bounded child traversal for point candidates and compare its exact
   results with the independent model for partial/full keys, equality, empty and
   unbounded intervals. A traversal change alone does not complete B.

If minimization shows a structural redesign is necessary, write its invariant
and why the current kernel cannot satisfy it before changing storage shape.
Prefer one common kernel with one topology writer to per-feature patches. If a
stronger model is needed, provide the shortest failing SQL history and exact
first divergent slot, not another broad context dump or an unsupported guess.

### C. Close compiler/closure gaps exposed by the audit

- Test derived fields with names that conflict with dependency order and a helper
  that receives the whole row and consumes another derived field. Current local
  ordering scans lexical `$this.field` only. For supported helpers, infer local
  dependencies through their parameters/call graph and make native CREATE helper
  evaluation see earlier computed values too. Merely reordering runtime derive
  is insufficient. An unsupported opaque shape must fail compilation clearly;
  silently using alphabetical order is forbidden. Keep this bounded to ordinary
  known helper calls; do not build a general SurrealQL interpreter.
- Define and test a deterministic/pure boundary for functions reachable from
  calculations, membership providers, recipes, and validators. Hidden mutable
  cross-record reads must use supported capture or statically generated routes.
  Reject unsupported untracked reads/writes/dynamic behavior rather than silently
  emitting an incomplete dependency model. Treat generated private bookkeeping
  separately from user-authored formula purity.
- Test conditional dependencies, empty/fallback reads, selected record/key
  projections, arrays and FLEXIBLE objects, schema field order, and transitive
  helpers. Existing arrays must be replaced, not appended.
- Exercise diamonds and root-publication feedback, not just direct peer cycles.
  `finish()` currently re-enters `refresh()` with a fresh path; verify cycle
  detection across those phases. Reject unsupported feedback atomically. Do not
  globally assert one evaluation per record when a valid dependency join can
  require settling another prerequisite; final values and termination matter.

### D. Extend bounded history testing and exactness

- Use deterministic seeds `20261014,7,1031` initially. Maintain an independent
  source model; generate both legal mutations that MUST commit and deliberate
  invalid mutations that MUST reject. Unexpected engine errors always fail.
- Mix source and subscriber creates/edits/moves/reparents/deletes, duplicate
  evaluations, branch toggles, empty gaps, equal timestamps, nanoseconds,
  predecessor/successor/prefix/range/exact/summary/record reads, overlapping ranges,
  AVL rotations, two-child removal, multiple slots on one record, outputs and
  deferred validators. Include restricted actors and competing transactions.
- Check business math, complete topology and exact read coverage after every
  committed mutation; check full snapshot equality after every rejection.
  Stop on the first integrity failure in acceptance mode. Diagnostic continuation
  may record later behavior but must retain failure status.
- Add metamorphic checks: equivalent construction orders, move-away-and-back,
  insert-and-delete, branch-off-and-on, duplicate read, and schema reapplication
  preserve the appropriate business results and registration sets. Generation,
  audit, and revision counters may legitimately differ between valid histories;
  compare semantic results there. Rollback must preserve the entire stored state.
- Canonicalize each table's rows by opaque record identity and each object's
  fields. Preserve order within meaningful arrays, including composite keys.
  Inventory all compiled tables/declared roots/node slots, and include private
  metadata and audit rows in rejection snapshots. Do not omit a table merely
  because it is empty or not in the accounting oracle's hand-maintained list.
- Retain rational monetary calculations. Add exact tree aggregate/extrema checks
  using decimal/rational transport, including large balances plus small fractional
  changes and a zero-boundary validator. Do not route those expected measures
  through Number and then accept tolerance. Use values within the verified native
  decimal domain. Typed comparison must retain nanoseconds, exact decimals,
  supported composite parts and canonical record/slot ties.
- Prove oracle effectiveness with fault injection. More seeds alone do not fix
  a checker that accepts corrupt state. Shrink any failing seed into a permanent
  regression with a complete standalone setup.

### E. Release gates and documentation

Run inexpensive targeted checks per packet. Reuse a disposable populated fixture
for exploration, but run final acceptance from a FRESH database. The complete
accounting run previously took about 31.5 minutes including reapplication and
cleanup; do not restart it after every unit edit.

```bash
node --check dev-tools/temporal-tree/read-oracle.js
npm run test:dev-tools
npm run build:all-in-accounting
npm run check:all-in-accounting
surreal validate build/all-in-accounting/schema.surql
npm run probe:observed-reads
npm run probe:temporal-tree
npm run probe:typed-tree
npm run probe:ordered-tree
npm run probe:boundary-tree
npm run probe:derived-order
npm run probe:required-outputs
npm run probe:causal-outputs
npm run probe:compiler
npm run probe:architecture
node dev-tools/accounting/probe.js --all --evidence designs/rebase-system/evidence/2026-10-14-integrity-accounting.json
git diff --check
```

Add named npm commands for the new standalone regressions and seeded campaign.
They belong to maintained verification, not only a temporary directory. Include
the strengthened oracle's negative controls. Use the root/record permissions,
tenant/authentication and relevant runtime checks when shared generators change.
Rebuild/check the other maintained compiler profiles affected by common changes.
Inspect `npm run verify` before invoking it; distinguish provider/mock/static
checks and record any skipped scope rather than implying a universal suite pass.

Acceptance requires both former valid writes to SUCCEED, complete structural and
subscription checks throughout their setup, correct exact source calculations,
metadata/audit rollback on deliberate failures, concurrency serialization or
explicit conflict with successful retry, populated identical-schema reapplication,
and child-first single-record cleanup with no orphan subscriptions/frames/groups.
Recheck nodes on ordinary business roots AND private indexes. A clean final
snapshot cannot compensate for any earlier accepted structural corruption.

Record source/schema/probe hashes, native version/storage, exact commands, seeds,
successful operations, deliberate rejections, unexpected failures, query checks,
and timings separately. Run the final gates on the exact sources you commit.
Never use counts from a prior commit as evidence for later untested changes.

Update the developer read contract, accounting guide, verification and current
handoff with actual resulting behavior and supported boundaries. Commit coherent,
validated packets and push the final commit to `main` as later authorized by the
user; do not deploy. The final report must distinguish fixes, freshly executed
verification, and remaining limits. Bounded evidence supports a release
decision; it does not prove the absence of every future bug.

## 6. Files to read and edit

| Purpose | Files |
| --- | --- |
| Logical read schema and lifecycle | `framework/reads.surql`, `dev-tools/compiler/reads.surql` |
| Shared AVL mutation and transaction phases | `dev-tools/compiler/temporal.surql` |
| Typed fields/public reads | `dev-tools/compiler/generators/tree.js`, `dev-tools/compiler/tree-contract.js` |
| Helper capture/derived order/events | `dev-tools/compiler/observed-reads.js`, `derived-order.js`, `generators/temporal.js`, `pipeline.js`, `fields.js`, `surql.js` |
| Structural and independent source models | `dev-tools/temporal-tree/{oracle,read-oracle,observed-probe,observed-fixture,harness}.{js,surql}` as applicable; `dev-tools/accounting/{source-oracle,acceptance,probe,extension-probe}.js` |
| Actual FX and tax calculations | `designs/all-in-accounting/core/exchange-rates.surql`, other `core/`, `postings/`, and public `schemas/` |
| Existing authoring contract | `designs/rebase-system/function-reactivity.md`, `designs/all-in-accounting/developer-guide.md` |
| Historical verification only | `designs/rebase-system/evidence/2026-10-14-automatic-*.json`, `designs/all-in-accounting/verification.md` |

`build/` is generated output, not the authoring source. Database fixtures should
use `temporal-tree/harness.js` to start/close disposable native servers; it does
not read application environment profiles. Namespace/database initialization and
large-schema batching are already provided. Preserve failed artifacts before
cleanup. Do not accidentally classify a namespace/setup error as a product repro.

The original context is at `~/.codex/attachments/` under IDs
`c2f6302d-89e7-4bb1-9e0e-793f7650f2eb` and
`8971e2ca-d1d7-4fa9-8ccd-cfb7a375bb5d`; their recursive references were inspected
and resolved in this lead turn. The latest October 14 chat is also
`~/Downloads/ChatGPT-Reactivity questions-20261014-0149.txt`. The stress attachment
is `8ad588cf-6320-44ad-9069-8a770f40d11d/Pasted text.txt`. Treat old AI responses as
navigation; the latest user instructions and freshly reproduced facts decide.
See the [lead-audit JSON](evidence/2026-10-14-integrity-lead-audit.json) for hashes,
scope and exact diagnostic results.

## 7. Ready-to-use continuation instruction

> Read `designs/rebase-system/integrity-repair-handoff-2026-10-14.md` and inspect
> Git status. Execute packets A through E in order. The lead has established
> oracle blind spots, not the precise writer cause. Build complete structural
> and expected-subscription checks, minimize and fix both valid-write failures
> in the common engine, simplify point traversal, and close the stated compiler
> boundary gaps. Preserve automatic logical read capture and accounting math.
> Breaking changes are authorized; use disposable databases and proceed without
> another planning/permission loop. Keep progress and evidence current. Do not
> declare completion until both regressions commit successfully and the new
> fault-injection, seeded-history and fresh accounting gates pass.

## 8. Execution findings and implementation record

The subsequent execution started from `98a54ada496f1c15712ad1ed3c7d6d8ee820aa28`;
`git fetch origin` and `git pull --ff-only origin main` confirmed it was the
latest upstream revision. `/workspace/accounting-lab` was available, so its
multi-currency fixture was preserved as a repository-owned standalone regression
instead of depending on that external directory.

The first accounting failure was reproducible while creating the second sale in
the shared INR/EUR/USD history. Earlier source rows had updated a read group;
later sibling refreshes changed another member before the transaction published
the group. The previous per-reader repair point was too early. The writer now
patches only changed slot fields, performs sequencing-sensitive child work in
folds, and settles only groups whose membership changed at the end of the full
cascade. The settled group is rebuilt bottom-up from its live links; unrelated
groups are not traversed. Reverse point candidates use bounded in-order child
traversal with typed lower/upper pruning rather than summary-sized `next` walks.

The purchase-tax child regression also commits with a converted purchase issue,
base tax, tax-on-tax, an issue adjustment, and both explicit adjustment-tax
children. Its net-tax child consumes the adjusted basis and its own dated USD/INR
quote. All source writes are checked independently, including the former failing
child creation.

The stress run then found a separate cleanup defect: after deleting a subscriber,
an indexed lookup by its typed record reference could no longer find the read
row even though a `WITH NOINDEX` scan still found it. The evaluation frame was
therefore removed while its read registration remained. Private read rows now
retain an indexed stable string identity in addition to their typed reader
reference, and deletion uses that identity. The shared oracle checks the identity,
live fence source and tenant, read/group/frame agreement, every point/interval
node and summary, inactive roots, threads and the settled `tree_changed` flag.

The accounting snapshot now includes every compiled table plus audit and private
metadata in full rollback comparisons. The independent accounting evaluator
continues to use exact rational arithmetic; business-root membership is derived
from source facts, while the shared private-read oracle checks every currently
registered subscription. The observed-read fixture separately supplies an exact
independent expected-read inventory and fault-injection controls.

The typed-tree campaign now runs seeds `20261014`, `7`, and `1031`. It exercises
mixed typed-key mutations, deliberate rollback, reparent-away/back, branch
off/on, inserts, deletes, populated schema reapplication, and competing writers.
See `designs/rebase-system/evidence/2026-10-14-integrity-fx.json` for the FX and
purchase regression and `designs/rebase-system/evidence/2026-10-14-integrity-accounting.json`
for fresh full acceptance. `designs/rebase-system/evidence/2026-10-14-integrity-repair.md`
lists the complete targeted gate results, timings, hashes and limits.

The historical instruction not to push predates the user's later explicit
request to commit and push these improvements. The current instruction controls;
all required gates passed in the fresh run, so the remaining action is the
authorized repository push. No application environment secrets, live database,
provider service or deployment were touched.

The fresh full accounting acceptance completed on SurrealDB 3.3.0 / Node 24.19.0
with SurrealKV in 14m36s: 103 source-oracle checkpoints, 105 structural checks,
90 exact value queries, 51 full rollback snapshots, populated schema
reapplication and cleanup across all 69 compiled tables. The maintained FX and
purchase-tax regression passed 44 source writes, 31 checked deletes and 2 full
rollback snapshots. The typed-tree seeds passed 252 mutation checkpoints, 1,570
ordered reads and 108 rejection snapshots. Detailed gate outputs and fingerprints
are in [integrity-repair evidence](evidence/2026-10-14-integrity-repair.md),
[fresh accounting evidence](evidence/2026-10-14-integrity-accounting.json) and
[FX evidence](evidence/2026-10-14-integrity-fx.json). The repository-wide
`npm run verify` was inspected but not run because it includes unrelated live,
service and payment-provider probes; targeted tree, tenant, authentication,
compiler, runtime and accounting checks passed.
