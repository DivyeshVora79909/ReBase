# V1: a self-explaining workshop verification suite

**Prepared 2026-10-23 against `1fa0748`; documentation only, not implemented.**

**Execution update:** V1.1–V1.5 are now accepted in the separate
[workshop result](44-workshop-verification-result.md). The preparation claims
and proposed commands below describe this packet at its original checkpoint.

The latest user instruction selects this non-accounting verification goal before
broader business applications. This packet prepares implementation by another
agent. It changes no executable, model, package version, storage format or dated
acceptance evidence. G4a–G4d and G5a–G5c retain their bounded acceptance in the
[capability program](30-capability-program.md). The next assigned implementation
checkpoint is **V1.1**, below; this planning task stops after documentation checks.

## 1. Decision and finish line

Use **stateful model-based testing**: execute sequences against the actual
engine and compare them with an independent, deliberately simple source model.
Combine bounded exhaustive exploration, reproducible generated sequences,
metamorphic checks and existing process/fault controls. These are established
testing techniques; this is not a new database, scheduler or test language.

The example is a small workshop: book shared equipment, observe its sensors,
calculate quantities and perform external service work. The developer should
learn why a result changes, which declaration caused the dependency and what
was preserved after failure. A complicated successful demo alone is insufficient.

**V1 is complete when** a developer has one documented entry point, small
composable scenario functions, readable before/after explanations, an explicit
capability-to-case map, independent expected results, replayable failures and
bounded verification of the supported core. Missing obligations must be reported
as incomplete or deferred, never silently counted as passing. No finite suite
proves all possible programs or permutations.

Keep the identifiers G6/G7/G8 stable. **G6 accounting is deferred** rather than
renamed or replaced in historical evidence. V1 is the next goal ahead of G6;
G7 distributed storage, G8 release/workload acceptance and frontend remain
deferred. Live provider integration and other unsupported capabilities do not
become implemented by testing a fake provider.

## 2. Reuse small models; do not invent a universal example

| Chapter | Existing foundation | Small addition for V1 | Independent expected state |
| --- | --- | --- | --- |
| Equipment bookings | [Equipment model](../src/models/equipment.rs), [guide](../docs/equipment.md) | Explain the existing delivery/reservation example and generate bounded edits | Plain dated signed-event lists and literal grouped prefix scans |
| Sensor observations | [Measurement model](../src/models/measurement.rs), [report workflow](https://github.com/DivyeshVora79909/ReBase/blob/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next/tools/observation_reports.py), [selection workflow](https://github.com/DivyeshVora79909/ReBase/blob/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next/tools/observation_selection.py) | One readable chapter showing reports and selectors over the same authored facts | Filter a list by exact bounds, scan count/extrema, and take a plain maximum of complete keys |
| Quantity flow | [Publication fixture](../src/publication_tests.rs), [exact values](../src/values.rs) and [Fraction oracle](https://github.com/DivyeshVora79909/ReBase/blob/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next/research/experiments/exact_values.py) | One minimal public non-accounting reference binding if needed for the walkthrough, described below | Ordinary rational arithmetic and a plain dependency graph over authored facts |
| Service quota and external work | [Effect demo](../src/models/effect_demo.rs), [worker workflow](https://github.com/DivyeshVora79909/ReBase/blob/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next/tools/effects_worker.py), [ingress workflow](https://github.com/DivyeshVora79909/ReBase/blob/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next/tools/effects_ingress.py) | Explain existing Account/Dispatch fields as service quota and units; retain their actual names | Authored quota plus immutable expected actions and the separate fake provider's journal |

One store selects one compiled `Binding` and its native index family. These
chapters use **separate disposable stores**. Matching workshop labels are an
explanatory association, not a cross-store reference or transaction. Do not merge
Standard and Statistics families into a new heterogeneous framework for V1.
Each chapter covers its own interactions; common API/lifecycle controls run on
representative stores and identify that scope in the report.

The quantity chapter fills a real presentation gap: the ready-publication HTTP
example currently uses invoicing. Prefer adapting the legal subset of the
existing native publication fixture, not duplicating its engine. Its minimal
contracts are Source, Scale and Join. Source publishes a bounded exact quantity;
Scale reads a declared ready parent quantity and applies a rational factor with
explicit rounding; Join reads two declared parent quantities and adds them.
Support a chain/diamond, repeated parent in distinct slots, zero factor and a
final cyclic retarget. Use the ordinary `Binding`, publication slots, shared
scheduler, schema/binder, client and source checker. No private output or custom
index is needed in this chapter; equipment supplies managed-output coverage.
Keep the initial fixture small (at most 16 public records and bounded magnitudes
such that admitted regroupings fit). A new model has its own behavior identity;
do not change existing models merely to rename their teaching vocabulary.

Existing parameter/window/terminal native fixtures remain focused probes where
they cover a distinct contract. Explain them as authored policies, capacity
windows and final checks, without copying a tax or invoice design into this
suite. Historical test names need not be rewritten just for presentation.
Existing invoicing tests and evidence stay intact as optional regressions; no
new accounting suite or accounting acceptance claim belongs to V1.

## 3. The walkthrough is the example's specification

Every teaching step states **intent → ordinary command/read → expected public
result → dependency/invariant → independent internal checks**. Show actual
schema/contract names alongside friendly labels. Show authored fields separately
from published values, query registrations and private role identities. Present
known empty/zero values explicitly. Do not present work counters as a causal
trace: if the engine exposes only totals, show totals and the separately computed
expected affected set, without inventing intermediate execution order.

The following small literals are mandatory anchors. They prevent an oracle and
generator from agreeing on an accidental policy. Branches start from the named
baseline, not from an unspecified prior mutated state.

### Equipment: allocation and historical validation

Baseline E0: deliver 10 units at time 0; A requests 8 over `[10,30)`; B requests 7
over `[20,40)`. Reservations read availability **strictly before** their starts.

| Step, on the indicated state | Expected result and explanation |
| --- | --- |
| E0 | A allocates 8, B allocates 2. Each active reservation has consume/release private roles. |
| From E0, increase delivery to 12 | A remains 8; B becomes 4 through declared chronological dependencies. |
| Then move A's end to 15 | A remains 8; B becomes 7 because A's release is now before B's start. |
| Then disable/reactivate A | Its occurrences disappear/reappear; the retained producer/role identities remain stable. B remains 7. |
| Then move A to a second pool with 6 delivered units | A becomes 6; B remains 7. Validate inventories and histories on both roots. |
| Fresh E0, move A's end to exactly 20 | B still allocates 2: the release at 20 is outside B's strict prefix. Moving the end to 19 instead gives B 7. |
| Fresh E0, add C requesting 3 over `[10,15)` | Reject: A and C each see the old strict prefix, but their total makes the complete-time history negative at 10. Final later recovery cannot repair that historical violation. |
| Fresh E0, add C and increase delivery to 12 atomically | Accept in either valid command order: A=8, C=3, B=4. Validate after final settlement. |

Also include a zero-allocation reservation: its query and two required private
output identities must not disappear because the amounts happen to be zero.
Native allocator collision/exhaustion and private-write rejection are separate
negative controls, not public fixture features.

### Sensors: exact windows, typed results and absence

Baseline M0: one unit-7 instrument with observations `(0,5)`, `(10,12)`, `(20,-2)`.
A report over `[0,20)` with threshold 5 has count 2, sum 17 in the matching raw
root **range** read (the full-root sum is 15),
minimum 5, maximum 12 and a true report predicate. A selector at 10 chooses the
observation at 10. A report publishes its declared unit; an empty raw root summary
has absent extrema/dimension. These are different projection contracts.

| Branch from M0 | Expected result and explanation |
| --- | --- |
| Move the last observation from 20 to 15 | Report becomes count 3/minimum -2/maximum 12/false. Selector at 10 still has the same winner; report and selector have different dependency windows. |
| Report range `[10,10)` | Empty, absent extrema, predicate false; do not substitute zero for the absent minimum. Query identity/registration remain present. |
| Selector before the first observation; then insert its first eligible observation | Absent becomes present. The dependency covered `(-infinity, at]` even while absent. |
| Insert a same-time observation with the same payload and a greater UUID | The selector's winner identity changes. Payload equality is not selection equality. |
| Edit an eligible nonwinner without changing the winner | Invalidation may evaluate the selector, but an unchanged materialized value retains its record version. |
| Move a member between instruments; retarget a consumer | Check original/final times and both roots, stale-route removal and the final source-derived result. |
| Wrong unit, then a joint owner/member/report/selector unit repair | Reject the wrong final dimension; accept a valid complete repair in either valid order. Temporary mixed staging state is not a publication. |

Native boundary probes cover `i64::MIN/MAX`, inclusive/exclusive/unbounded ranges
and equal-time member-slot ties not reachable through this model's single public
observation slot. Selection candidates are authored Observations only.

### Quantities: ready publications and exact ratios

Source quantity 12 feeds Scale L at factor `1/2`, Scale R at `1/3`, both with exact
rounding; Join reads L and R. Values are L=6, R=4, Join=10. Editing Source to 18
gives 9, 6, 15 after parents become ready. Editing it to 13 with exact rounding
rejects the whole mutation (`inexact`). Explicitly choosing suitable rounding is
a different authored intent. Include signed tie examples from the existing exact
value oracle, canonical strings beyond `2^53`, overflow and intermediate-overflow
controls under their actual declared bounds.

Retarget an existing scale to a different existing source in the same batch as
a parent edit, in both valid orders. Preserve dependencies when the resulting
quantity is equal. Retarget L to Join to create a declared cycle and reject even
if L's factor is zero. Separate native controls establish final edge reversal,
mixed aggregate/publication cycles and output-free terminal validation.
Newly created referenced parents must precede children during command staging;
the suite must not call every creation permutation valid.

### Service work: facts cannot be rolled back remotely

Use the existing fixed fake adapter. Quota 12 is edited to 10 in the same mutation
that creates Dispatch of 3 units and its immutable execution intent. Confirmed
remote success leads to quota 7 exactly once. If quota is 2 when success arrives,
preserve the success fact and block its domain application. Repair quota to 5;
applying that same fact gives 2, without another provider submission.

Explain cancellation before start versus uncertainty after start; signed event
deduplication; stale lease rejection; and restoring a backup predating remote
acceptance. Restored dispatch stays reconciliation-only, and an empty lookup
does not authorize submission. Reuse the separate SQLite provider journal as the
remote-side observation, not an engine receipt or the worker's claim of success.

## 4. Coverage map and the internal checks

Each row is a verification obligation, not a claim of new execution. In V1.1,
bind it to exact existing test names or new scenario names and a source revision.
Give each row one of `passed-current`, `reused-evidence`, `failed`, `incomplete`
or `deferred`. A reused earlier result identifies its version and scope; it is
never added to this run's executed count. All required V1 rows need current
execution before V1 closeout; expensive historical capacity campaigns may remain
separately labelled historical rather than required V1 rows.

| ID | Observable obligation | Existing seams to reuse / minimum additional case |
| --- | --- | --- |
| V-C01 | Shared schema/native binding, canonical UUID/decimal/rational values, CAS and malformed input | [Exact values](../tests/exact_values.rs), [strict JSON](../src/json.rs), [quantity oracle](https://github.com/DivyeshVora79909/ReBase/blob/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next/research/experiments/exact_values.py); include a valid first command followed by a failing one |
| V-C02 | Typed references, same tenant, parent existence, delete restrictions and source identity reuse | [Mutation path](../src/mutation.rs), [equipment tests](../tests/equipment.rs), [measurement tests](../tests/measurement.rs); distinguish legal staging orders |
| V-C03 | Native family ownership, algebra, linked AVL order/balance/neighbours, exact subtree caches | [Native tree tests](../tests/native_tree.rs), [non-time/non-Copy fixture](../src/index_tests.rs), [integrity](../src/integrity.rs); alternate insertion/deletion orders and disconnected/orphan/corrupt images |
| V-C04 | Declared authored-parent parameters, changes and inactive-query fallback | [Parameter controls](../src/parameter_tests.rs); explain a small policy input and both valid edit/retarget orders |
| V-C05 | Managed role identity, zero contributions, activation/removal/retirement, allocator collision/exhaustion and private write protection | Equipment plus [causal settlement](../src/causal.rs); compare symbolic `(producer, role)` identity and actual retained reservation inventory |
| V-C06 | Exact old/new point discovery, interval stabbing, empty registrations and all bound shapes | [Window controls](../src/window_tests.rs), [reverse routes](../src/route_tests.rs); disjoint changed points and both old/new roots |
| V-C07 | Final dependency graph, chains/diamonds, readiness, equal results, zero feedback and final edge reversal | [Publication controls](../src/publication_tests.rs), quantity walkthrough; distinguish final graph from a cyclic union of old/new graphs |
| V-C08 | Output-free terminal checks after managed settlement and complete-time historical invariants | Parameter/window controls plus E0 rejection/atomic repair; positive final totals alone are insufficient |
| V-C09 | Native statistics, dimensions and output-free report reactivity | Measurement report workflow plus its source-only list oracle; unit repair, all-members-deleted and empty=false |
| V-C10 | Optional latest authored selection and complete occurrence ties | Measurement selection workflow; first/last insertion/deletion, nonwinner changes, equal payload/different identity and complete absence dependency |
| V-C11 | Principal DAG diamonds, owner/reader separation, new-reference authority, revocation and materialized-result Read policy | [Access tests](../tests/access_control.rs), [equipment HTTP](../tests/equipment_http.rs), [network tests](../tests/network_api.rs); use plain graph reachability for expected scopes, not the production prepared graph |
| V-C12 | Pages/exists/cursors, indexed authorized partitions and bounded residual equality filtering | [Local API tests](../tests/local_api.rs), [merge controls](../tests/semantics.rs); sparse empty resumable page differs from exhaustion/`no`, budget-limited exists can be unknown, mutation/scope changes invalidate cursors |
| V-C13 | Atomic publication, CAS races, duplicate/reused operation IDs, uncertain response, status/replay redaction and archive fence | Network/local API plus [storage lifecycle](../tests/storage_lifecycle.rs); compare every application table/revision and absent receipt after rejection |
| V-C14 | External intents, lease/start fencing, immutable facts, application repair, signed inbox and restore quarantine | [Effect tests](../src/effect_tests.rs), [worker controls](../src/effects/worker_tests.rs), [inbox controls](../src/effects/inbox_tests.rs); retain independent provider journal observations |
| V-C15 | Finite work/population/output/receipt/effect/inbox limits, recovery and failed-restore isolation | Existing model/effect limits and storage controls; just below/at/above selected bounds, real write aborts, no destination after failed restore; do not raise constants or repeat million-row campaigns |

Supported public reads remain `records.by_id` pages, optional contract and
declared scalar equality postfilter, exists and declared root reads. Residual
equality filtering is supported **within its visit budget**; it is not an
unbounded arbitrary scan/query API. `model.describe` is a public RPC; developer
model inspection and fixture/check/inspect/backup/restore CLI commands remain
operator tools. Do not add testing bypasses to production
authorization or expose private allocation and failure-injection fields to clients.

## 5. Oracle and observation independence

The expected-state evaluator starts with its own authored facts, command order,
versions, authority actions and declared semantics. Stage commands in their real
order, then compute final settled facts using plain scans/rational arithmetic
and an independently constructed graph. Tiny graph controls can enumerate legal
topological orders; larger generated cases use ordinary independent traversal.
Do not call the engine scheduler, tree fold, route selector, `lift/combine`,
prepared authority graph or integrity checker to compute expected values.

Expected inventories are logical memberships, roots, routes, queries and role
bindings. They do not prescribe one physical AVL shape. Reuse existing focused
structural walkers and corruption controls to check actual links/cache contents;
do not rebuild a second complete storage-integrity subsystem for this suite.

After a successful transition compare public authored/published values, root
results, retained roles and expected complete inventories. The actual checker
may inspect links; its expected memberships, queries, routes and summaries must
come from facts, not cached nodes. Include missing rows, extra disconnected rows,
wrong summaries/counts/spans, wrong result variants, false absence and stale
registrations as corruption controls. A checker accepting its own writer's
output is not an independent comparison.

For rejected attempts preserve the oracle's previously committed state and
compare **all application tables**, revisions, roles, receipts and effect data.
Prove no receipt for a new rejected operation. Existing operation-ID replay or
conflict cases retain their earlier receipt. Successful redb opens can alter
maintenance bytes: compare logical table bytes. A clean incompatible-open
rejection additionally checks physical bytes as the accepted controls already do.
Never use production recomputation as the repair that makes a failed test pass.

For random private UUIDs, compare source/role-labelled identity plus stability,
uniqueness and retirement rules. Public generation is not seeded allocation.
Trusted native `Store::mutate_with_ids` can inject an explicit allocation tape
through the same mutation path; preserve collision candidates and exhaustion
limits. Do not infer a universal nil/collision rule across effect and output
allocators where the existing contracts differ.

## 6. Deliberate exploration, not an unbounded permutation campaign

Start with literal walkthroughs and boundary controls. Then enumerate a **fully
specified finite alphabet** for tiny cases: e.g. up to two source entities,
two ordinary time/value choices, at most six **fully instantiated actions in
total, including parameter choices**, and depth three
(at most `1+6+36+216=259` traces before invalid preconditions are classified).
This is exhaustive only for that published alphabet/depth. Include separate
extreme/empty/overflow probes and actual contract-specific command-order pairs.
Record attempted, classified-invalid, accepted, rejected, checked and truncated
counts; a budget cutoff is incomplete, not exhaustive.

Run the combinatorial core in bounded native fixture memory through the actual
typed mutation/settlement/codec and atomic fixture patch application, where that
avoids thousands of redb opens/fsyncs. This is test infrastructure, not another
writer API; it proves no storage durability or receipt semantics. Real Store,
HTTP, credentials, receipts, concurrency and process recovery get separate
representative controls. Enumerate serial orders without claiming they cover
concurrent schedules. Embedded races need actual barriers/clients; distributed
absence/conflict/retry/unknown-commit schedules remain G7.

Next generate longer seeded, bounded **stateful** sequences: create, update,
rekey, retarget, activate, delete, multi-command repair, reads and deliberate
invalid attempts. Generate useful valid contexts and explicit invalid classes;
do not obtain all coverage by counting random schema errors. Use structural
coverage counters such as zero/one/many affected consumers, both changed roots,
empty/nonempty windows, equal results, ties, cycle classes and reject-after-write.
Stop at a published case/step/work budget. Nightly/stress expansion is optional;
the developer's default stays small and deterministic, not a timing contest.

Keep live reference pools and preconditions in the independent source state;
new parents precede their children, while deliberate invalid references remain
explicit negative cases. A generic schema faker or global constraint solver is
not required. The oracle may rescan and sort small facts (`O(n log n)` for dated
histories and `O(n)` for one window); it should remain simpler than the optimized
engine. Exhaustive sequence count is exponential in depth, hence the small
published alphabet and budgets. Do not optimize away the oracle's independence.

Useful metamorphic relations include independent-operation order, alternative
AVL insertion order, update then inverse where valid, splitting an independent
batch at legal checkpoints, no-op result version preservation, and replay
idempotence. State their preconditions. Same-time split/merge, rounding relocation,
UUID renaming that changes a winner, or changing transaction boundaries do **not**
necessarily preserve meaning. No speculative partial-order reduction may skip
known interacting operations without a justified independence predicate.

## 7. Small developer surface, explanations and replay

**Proposed interface, not an existing command:**

```text
python3 -B tools/verify.py --binary <executable> --out <fresh-directory> --mode walk
python3 -B tools/verify.py --binary <executable> --out <fresh-directory> --mode check
python3 -B tools/verify.py --binary <executable> --out <fresh-directory> --mode explore --seed <integer>
python3 -B tools/verify.py --binary <executable> --out <fresh-directory> --mode replay --artifact <failure.json>
```

`walk` explains the fixed stories and performs their assertions; `check` executes
the named current capability controls; `explore` runs bounded generation and
minimizes a discovered failure; `replay` reconstructs a retained case in a fresh
isolated fixture. Optional `--case` selects a stable scenario. No bespoke REPL,
new parser/DSL, plugin registry, protocol or interactive frontend is required.
Expose ordinary functions for case construction, source evaluation, execution
and comparison so developers can compose them directly; do not invent a second
framework to orchestrate four modes. Prefer the current Python standard library,
Rust test harness and existing `harness.Backend`/stateless client. A property-test
library is justified only if it removes more generator/shrinker code than it
adds and preserves exact replay/artifact semantics; it is not mandatory for V1.

Prepare/reuse native test artifacts once per source/profile with one Cargo owner.
Accept a supplied runtime binary; pin its source/build identity separately from
the native test artifacts. Do not infer correspondence from its filename. If
source/Cargo or a matching native artifact is unavailable, `walk` can still teach
public workflows, but `check` reports missing internal scope as incomplete.
No silently skipped native controls or expensive automatic release rebuild per case.

For each step show the short explanation, ordinary API/CLI action with symbolic
labels and exact wire field types, expected/observed public result, independently
expected dependency/invariant, actual inspect/check comparison and measured work.
Provide JSON output plus a readable Markdown/text summary; use the existing
offline inspector only where helpful. Never claim to observe an internal
execution trace when only final state and counters are available.

A run artifact retains source/model/behavior/store/API identity, binary/native
artifact fingerprints, seed **and full ordered actions**, exact request bytes,
operation IDs/contexts, source-oracle facts, actor/grant changes, native allocator
tape and fault/crash barriers. Write credentials only in owned private fixtures;
reports must not dump tokens, signing secrets or unrelated environment values.
Report the selected seed/coverage budget, current versus reused checks, expected
rejections, work/load/evaluation/dirty-byte counters, mismatch and reproduction
command. Bounded logs and output files must not truncate a failure into a pass.

Distinguish two replay operations. **Logical reproduction** recreates the whole
script in a new isolated store; it obtains new contexts for newly issued intents
and repeats each uncertain request with that new run's original saved plan.
**Exact-byte resume** uses an original plan only against its original compatible
target/context. Never refresh an uncertain plan's context or operation ID to make
an old request attach to a different store. HTTP random private UUIDs are compared
symbolically; native allocation tapes can be byte-reproducible.

Minimize a failure by deleting action spans/commands/unrelated facts and reducing
values, time bounds, ratios and graph size. Replay every candidate against a fresh
oracle and fixture. Retain the same semantic mismatch, relevant preconditions,
CAS/replay intent, identity ties and fault boundary; an unrelated stale-version
or missing-parent failure is not a successful shrink. Keep the original and the
minimized traces. Persist minimized cases as named regressions. Use finite
minimization budgets; a partially minimized failure remains a failure. Distributed
fault-schedule shrinking is not established by serial trace shrinking.

## 8. Ordered implementation checkpoints

| Checkpoint | Concrete deliverable | Acceptance before commit |
| --- | --- | --- |
| V1.1: inventory and literal walkthrough | Map V-C01–15 to exact cases, implement `walk` skeleton and the four small stories; add the minimal quantity fixture only for its identified public gap | Literal values above, truthful public/private explanations, ordinary production mutation path and owned-process cleanup; existing model schemas remain authoritative |
| V1.2: independent core comparisons | Source evaluators, full expected inventories and bounded tiny-state exploration; compose relevant existing native controls | Publish finite alphabets/counts; expected rejection + all-table rollback; deliberate wrong-value/missing/extra-row controls must fail the suite; no implementation code in expected arithmetic |
| V1.3: stateful exploration and replay | Bounded seeded action sequences, coverage counters, failure retention, logical/byte replay distinction and shrinking | Same trace reproduces; injected known defect is detected and reduced without changing failure class; preserve minimized regression and original request/allocation history |
| V1.4: process and cross-component verification | Actual HTTP/authority/page/receipt/CAS races, lifecycle and independent fake-provider scenarios through the same entry point | Named real barriers, crashes and restore controls; no hidden cross-store transactions, no duplicate remote acceptance, no process/secret leaks; all required V-C rows have current executed evidence |
| V1.5: developer closeout | Concise guide, complete capability report, source/build fingerprints, limitations and handoff | One documented invocation produces the explanations and checks; every row has evidence/status, no silent skips; optional expensive historical campaigns are labelled; G6/G7/G8 stay deferred |

Avoid a build per checkpoint when no native code changed; cache and invoke the
same matching artifacts. Reuse existing correct tests/workflows instead of
rewriting all of them. Any genuine bug found gets a small reproducer and focused
fix through the shared core, affected identity/format changes if necessary, then
the relevant checks. Do not introduce a new engine capability just to improve a
coverage percentage: record an unsupported case as deferred. Preserve dated
evidence and the matching old binary/store if a semantic change is necessary.

## 9. Explicit exclusions and continuation prompt

V1 does not implement full accounting, rational FX business rules, new live
providers, managed statistical emissions, selected-parent publication chains,
winner-dependent output topology, arbitrary query planning, passkey/OAuth flows,
subscriptions, populated migration, unbounded retention, distributed storage or
frontend. These are not silently certified by the workshop. Pure rational
arithmetic is already supported; general FX accounting is a different obligation.
The last packaged deployment remains 0.6.0 until a later release gate executes.

Give the implementation agent this goal:

> Read `rebase-next/AGENTS.md`, the top of `CONTEXT.md`, and
> `research/43-example-verification-suite.md`. Implement V1.1–V1.5 as the active
> non-accounting verification goal. Reuse the existing engine, models, native
> controls and process harnesses. Make the walkthrough itself explain each
> command, dependency, expected value, rejection and internal comparison.
> Use independent source models, bounded exploration, exact replay and failure
> shrinking; report incomplete/deferred coverage honestly. Keep one build owner,
> run only justified checks, and commit/push tested checkpoints on the existing
> `main` without another continue prompt. Keep the handoff current. G6 accounting,
> G7 distributed storage, G8 release expansion and frontend remain deferred.

This is the next agent's implementation assignment, not evidence that V1 has
already run. At V1 closeout, stop and report the remaining explicitly scoped
capabilities; do not resume the older open-ended accounting/production goal.

## 10. Preparation verification

This documentation checkpoint checked 200 relative file links across its seven
Markdown files; all resolve. All 77 source/test/tool hashes recorded by G4d-c
still match. The scoped diff contains documentation only and passes whitespace
checks. No Cargo build, native test, database, HTTP/provider process or new
verification-suite execution was required or run. Existing evidence is unchanged.
