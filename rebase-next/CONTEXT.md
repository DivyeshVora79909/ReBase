# Compact context — 2026-10-25

**G7.0–G7.5 complete; next: G7.6 final cross-adapter closeout.**
Continue on existing `main` and commit/push each verified checkpoint. Read
[G7.5](research/50-scoped-coordination-result.md) and its
[evidence](research/evidence/2026-10-25-g75-scoped-coordination.json), then the
[G7 contract](research/45-storage-adapter-plan.md). Source/store/native/effect/API
are 0.16.0 /10 /7 /4 /4; every binding behavior identity advances. No migration.

Immutable Meta, conditionally written Population, UUID record/root/result tokens,
scoped reader/contract cursor epochs and 1,024 independently guarded receipt
slots replace incidental global domain/receipt writes. Archive compares the
complete digest inside cleanup. Authority no-op CAS uses a same-value authority
write to validate FoundationDB reads while preserving its counter and cursors.
Both independent populated-root edits commit with no common application write,
no Meta/Population/header write and no range scan. Exact population changes,
business roots, query partitions and effect counters remain coordination points.

Accepted: 153 distinct native checks across 13 harnesses; 29 real FoundationDB
coordination/lifecycle controls; 58 shared application controls; optimized
secured HTTP (32 competing attempts, eight commits, 24 confirmed conflicts),
thirteen-table rollback/restart/restore, original-ID outcomes and archive expiry.
Four stale native expectations and one authority-initialization fixture were
corrected with their failed trials retained. Formatting, Clippy and default
all-target compilation pass. Earlier population and V1 campaigns were not rerun.

**Exact continuation:** use retained `target/g75-accepted/rebase-next` and the
`g7_coordination`, `g7_application`, `g7_storage` probes there. Run coordination,
application and optimized HTTP on fresh SurrealKV and redb targets, plus the
final shared byte suite on all three adapters. Reuse accepted G7.5 FoundationDB
application/coordination/HTTP evidence unless the relevant source changes.
Publish G7.6 formats, dependencies, exact supported guards, complete-state
recovery and remaining fault gaps; update continuation docs and commit/push.

One Cargo owner, two jobs, incremental off, cache `target/verification-build`.
The owned FoundationDB 7.3.77 server is running for G7.6. Its cluster/client/server
are under `target/g7-environment`; both FDB_CLIENT_LIB_PATH and LD_LIBRARY_PATH
use `target/g7-environment/root/usr/lib`. A feature-enabled executable needs the
native library even for redb. Stop the owned helper at final closeout with
`python3 -B tools/fdb_cluster.py stop`. No application or Cargo process is active.
TiKV, G6, G8 and frontend remain deferred; the last packaged release is 0.6.0.

**Historical G7.4 handoff, 2026-10-24:**

**Paused cleanly after G7.4; G7.0–G7.4 complete. Next: G7.5, then G7.6.**
The user requested review of incoming `643c8f6` and continuation on existing
`main`, with a clean checkpoint handoff for their remaining token budget.
All 90 incoming G7.2 fingerprints match; its 54 raw /51 application checks were
reproduced. G7.3 `376074a` adds real effect facts/inbox/application, authority
repair aborts, both reference races and controlled initialization; expanded
application checks pass 58 FoundationDB /58 SurrealKV /49 redb controls.
Read [the contract](research/45-storage-adapter-plan.md),
[G7.3](research/48-storage-publication-result.md) and
[G7.4 plus exact continuation](research/49-storage-api-result.md).

G7.4 wires explicit backend selection through ordinary CLI/HTTP and fixes RPC
presentation of confirmed storage conflict/abort/limit outcomes. All three real
secured HTTP runs pass 32 competing attempts each, same-ID committed/absent
HTTP-loss reconciliation, SIGKILL/restart with complete eleven-table equality,
fresh restore, archive expiry and reset. Native commit-ack injection and
replicated failover remain untested. Source/store/native/effect/API formats
remain 0.15.0 /9 /6 /3 /3. Last packaged release remains 0.6.0.

**Exact continuation:** implement and verify G7.5 scoped revision/receipt
coordination, then G7.6 final cross-adapter acceptance. No partial G7.5 code is
retained. Paper 49 records the reviewed token/population/cursor/receipt-slot
proposal, ownership boundaries and required real schedules. Global Meta and
receipt header writes still remain; no independent-root scale claim is accepted.
The previous overlapping unfinished local migration was discarded as authorized.
Do not restart accepted G7.0–G7.4 or blindly apply historical numeric fixtures.
Commit/push verified checkpoints on existing `main`; no branches/stashes.

One Cargo owner, two jobs, incremental off, cache `target/verification-build`.
FoundationDB 7.3.77 cluster/client/server are under `target/g7-environment`;
FDB_CLIENT_LIB_PATH and LD_LIBRARY_PATH point at its lib directory. The owned
server is stopped at this handoff; restart with `python3 -B tools/fdb_cluster.py start`.
Read [backend usage](docs/storage-backends.md). No automatic retries; retain the
original operation ID and context for uncertain outcomes. TiKV, G6 accounting,
G8 execution and frontend remain deferred.

**V1.1–V1.5 complete: self-explaining non-accounting verification.**
Read the [workshop result](research/44-workshop-verification-result.md),
[evidence](research/evidence/2026-10-23-v1-workshop.json), and
[run guide](docs/workshop.md). Source 0.15.0 adds a minimal Quantity binding and
ordinary composable verification tools, with no new dependency or wire/store
format. The five existing public catalogs and model identities remain unchanged.

**Accepted checkpoints:** `cba8e0a` fixes terminal publication targets and adds
Source/Scale/Join; `6e323c1` adds V1 walkthroughs, checks, bounded exploration,
replay and the injected-fault probe. These replace partial unverified `924ace0`
as explicitly requested. The shared scheduler uses declared publication targets
rather than fake queries/outputs to evaluate terminal Sources. Existing
non-causal query parents still reject.

Four chapters pass 42 named teaching steps (40 explicit mutations, including
four full-table rollback rejections, plus two service stories). All 15 capability
rows pass 147 Rust tests across 15 native harnesses, plus 16 actual worker and
eight signed-ingress/recovery process cases. The six-action/depth-three profile
checks 258 transitions and all 259 prefixes including empty; its scope is that
finite authored alphabet. A 32-action seeded Quantity run and fresh logical
replay pass. A test-only wrong observation is detected, shrinks from nine actions
to one, and reproduces in a fresh store. Twenty Python controls pass. This is
bounded evidence, not unrestricted scale or all-program correctness.

**Historical V1 stop boundary (superseded only by selected G7 above):**
G6 accounting, G7 distributed storage, G8 workload/release expansion and frontend
remain deferred. Do not invent another gate or restart G4/G5. The last verified
packaged release remains 0.6.0. Source 0.15 is not a new release bundle.
Retained runtime: `target/v1-accepted/rebase-next`; current reports:
`target/v1-check/result.json`, `target/v1-walk/summary.md`,
`target/v1-explore/result.json`, `target/v1-replay/result.json`, and
`target/v1-shrink-probe/result.json`. Credentials/databases stay private and
untracked. The dated evidence records fingerprints and execution limitations.

**Historical V1 starting point:** G4a–G4d and G5a–G5c, source 0.14.0, remain accepted
within their documented bounds. Existing accounting examples and dated evidence
are retained, not removed or expanded. The latest read-only audit matched all
77 G4d-c source hashes and ran seven selection/twelve report oracle controls;
it did not rerun the Rust or HTTP campaigns and does not establish V1 acceptance.

**Historical G4d-c closeout:**

Read the [G4d-c result](research/42-authored-selection-result.md) and
[evidence](research/evidence/2026-10-23-g4dc-authored-selection.json). Source
0.14.0 adds typed LatestObservation (419), query slot 43, greatest complete
`(time, UUID, member slot)` at/before `at`, and the full `(-infinity, at]`
dependency even when absent. Authored Observation members are final before the
shared scheduler evaluates. Managed candidates and selected-parent publications
remain outside this gate. Store 9 /native codec 6 /effect codec 3 /API 3 stay
unchanged. Measurement behavior 3 owns model
`32d95742102bfcb62fff89e0871f90a2c08cc97cf344c7665a2704cb9569871b`.

All 26 selected Rust controls pass, including 27 corrupt inventories. Seven
selection and twelve report oracle controls pass. One optimized HTTP run passes
22 mutations /49 commands (18 commits, four full-table rollbacks) in 2.260 seconds:
zero/one/eight selection, both changed roots, authority, replay, reopen, one
process kill and restore. Four unchanged model identities and complete tables
match 0.13; old measurement rejects without changed physical bytes. Eight prior
report query and derived encodings each remain byte-identical after one source
recreation batch. Both absent and present selectors survive recovery.

One native compilation took 98.441 seconds; native checks took 11.345 seconds.
The single optimized build took 289.328 seconds. First Clippy and the focused
test check passed; no source failures or repeated builds occurred. Only the
root agent works, with one Cargo owner, two jobs, incremental off, debug cache
`target/native-slice/build` and optimized cache `target/g4b-retained-b377b21/build`.
No build, backend or provider process remains after acceptance.

Retained executable: `target/g4dc-accepted/rebase-next`, 28,765,840 bytes,
SHA-256 `46e6e52125cb263dda8a89858a1117f42a5ef963300f0ff71eb4292907485338`.
Reports: `target/g4dc-checks.json`, `target/g4dc-compatibility.json`,
`target/g4dc-selection-http/result.json`. Keep earlier binaries/evidence below.
G5 remains bounded to the fixed fake provider; the last deployment bundle is 0.6.0.

**Historical G4d-b, after published G5c `b65be31`.**
Read [the result](research/41-native-query-consumer-result.md) and
[evidence](research/evidence/2026-10-23-g4db-native-query-consumers.json), then the
[G4d-c contract](research/40-native-query-consumers.md). Source 0.13.0 uses
family-owned `QueryResult`, typed persisted queries and common causal scheduling
for output-free ObservationReport. Empty-window threshold is false. Store 9 /
native codec 6 /effect codec 3 /API 3 are unchanged. Measurement behavior is 2,
model `75c4b8643230b0a69dd6fe443d374e4e05d9c7387ab50cd7950b020b6549a418`.
The four other model identities and their complete application tables match G5c;
old measurement rejects without changed physical bytes.

Thirty-eight selected Rust controls pass, including sixteen corruption cases.
The single optimized HTTP run passes twenty mutations /36 commands (sixteen
commits, four full-table rollbacks), with zero/one/eight selected reports,
authority, replay, one process kill and restore. HTTP takes 2.143 seconds;
the optimized build takes 296.743 seconds. First Clippy and native compilation
pass; no source fixes or repeated builds were needed. A compatible-open physical
byte assumption in the compatibility script was corrected to full application-
table equality; incompatible rejection still requires physical equality.

Retained binary: `target/g4db-accepted/rebase-next`, 28,634,848 bytes,
SHA-256 `535a2cb4a0984fbbedd9fa302b96eaa64ed9bd4fdd5157e1fa1ee6bd26b3da48`.
Reports: `target/g4db-checks.json`, `target/g4db-compatibility.json`,
`target/g4db-reports-http/result.json`. Only the root agent works. No owned build,
server or provider process remains. Use one Cargo owner, two jobs, incremental
off, debug `target/native-slice/build`, optimized `target/g4b-retained-b377b21/build`.
Preserve earlier executables and passed evidence; do not repeat their campaigns.
G4d-c selects the greatest complete `(time, UUID, slot)` authored observation at
or before `at`, with dependency on all `(-infinity, at]` even when absent. Do not
silently treat statistics as quotes or claim managed-candidate readiness.

**Historical G5c: published `b65be31`, following `f44339f`.**
Read [the G5c result](research/39-ingress-recovery-implementation.md) and
[evidence](research/evidence/2026-10-23-g5c-ingress-recovery.json), then the prepared
[G4d-b/c gate](research/40-native-query-consumers.md). Source 0.12.0 owns store 9 /
native codec 6 /effect codec 3 /API 3 and effect-demo behavior `effect-demo-ingress-3`.
Its model is `6114a52f4ad9d59fc067474e7c12a36d09ead2cafe09583ebc25fb150fd2047f`.
The four prior model identities are unchanged; a populated format-8 effect store
rejects without changed physical bytes.

G5c accepts signed bounded ingress, durable deduplication, fact/inbox atomic
consumption, monotone result handling and explicit disabled/delivery/reconcile
modes. Restored stores permit reconciliation and Account repair, never new
Dispatch creation or delivery until clean reset. The prestart-backup HTTP proof
has one remote submission/acceptance and zero restored attempts; empty lookup
stays quarantined. A ready/quarantined row after six lost reconciliation claims
can safely retry observations without regaining submission permission.

Twenty-seven effect and two shared Rust controls pass. Eight final optimized HTTP
scenarios pass in 13.558 seconds, including one process kill, failed inbox writes,
full 256-row inbox, archive/reset fences and delayed blocked-application repair.
The combined native 256 execution /1,024 fact /256 x 8 KiB inbox backup is
6,703,752 bytes. The final optimized build took 280.615 seconds. Final review
required one narrow retry fix; successful earlier runs remain retained, and only
affected native/HTTP checks were rerun. Do not repeat accepted campaigns.

The retained binary is `target/g5c-accepted/rebase-next`, 28,428,808 bytes,
SHA-256 `fa60b6e8f98fdcfa5dc6b3efae23a07312981433cab4924f5cf5eb8cde025872`.
Reports: `target/g5c-checks.json`, `target/g5c-compatibility.json`,
`target/g5c-bounds.json`, `target/g5c-final-ingress-http/result.json`.
No build, backend or provider process is active. Use one Cargo owner, two jobs,
`CARGO_INCREMENTAL=0`, `cargo +1.95.0`, debug `target/native-slice/build` and
optimized `target/g4b-retained-b377b21/build`. Preserve the G5a/G5b executables.

**Historical G5b acceptance.** Published `f44339f` owns source 0.11.0 /store 8 /
native codec 6 /effect codec 2 /API 2. Its 25 affected Rust controls and sixteen
optimized HTTP scenarios include four real process kills, blocked application,
concurrency and actual transport timeout. [The result](research/38-fenced-worker-implementation.md)
and [evidence](research/evidence/2026-10-23-g5b-fenced-worker.json) remain dated.
`target/g5b-accepted/rebase-next` has SHA-256
`66fe7e4582aebb499a35b58cc40ac4c2e62f196e232a87602ba2c84a785bd206`.
G5c supersedes its restored-activation restriction, retaining reconciliation only.

**Historical G5a acceptance.**
The [G5a result](research/37-atomic-intent-implementation.md) and
[evidence](research/evidence/2026-10-23-g5a-atomic-intent.json) record source 0.10.0
/store 7 /native codec 6 /effect codec 1 /API 2, atomic Account/Dispatch intent,
status/cancel and complete storage inventory. All 24 affected Rust tests, eleven
corrupt check/startup/restore controls and the optimized seven-mutation HTTP
workflow pass. The four prior model identities remain unchanged; old format-6
invoicing rejected with physical bytes unchanged. G5a kept provider dispatch
disabled; the accepted G5b result above supersedes that delivery boundary.
Use the
existing debug cache `target/native-slice/build` and optimized cache
`target/g4b-retained-b377b21/build`, one Cargo process at a time, two jobs.
G5a's optimized build took 222 seconds; its HTTP workflow took 1.732 seconds.
Keep `target/g5a-accepted/rebase-next` and `target/g5a-effects-http/` intact.
The binary SHA-256 is `b543aa119740e8c81ceea5cacefb172a9bf518567e0b508ef62aea28b52eb334`.
Reports are `target/g5a-checks.json` and `target/g5a-compatibility.json`.
G5a-G5c are accepted above; later capability gates remain open.

G4c-a/b is published as `b72507c` on `main`. G4d-a source 0.9.0 adds typed
publication inputs, final graph readiness and output-free IssueShare.
[Evidence](research/evidence/2026-10-23-g4d-published-values.json) records 71
affected native tests, 11 Fraction oracle controls and 11 optimized HTTP mutations
(eight commits, three complete rollbacks), with authority/replay/crash/restore.
Store/native codec stay 6; invoicing behavior is 5. Other bindings retain their
0.8 identities and their stores pass complete checks. Old invoicing rejects
without byte changes. The last verified deployment bundle remains 0.6.0.

The user requested tighter time/resource use. One owner runs compilation; reuse
Cargo caches and passed checks. G4c's broad optimized suite took nine minutes;
do not repeat it or the 4,096-source campaign for this narrower change. G4d-a uses
affected native controls, an optimized HTTP workflow and identity/open checks.

**G4c-a/b accepted:**
The [native-index result](research/34-native-index-extension.md) and
[evidence](research/evidence/2026-10-23-g4c-native-indexes.json) record source 0.8.0 /
store+codec 6: one AVL over `Binding::Index`, explicit Standard financial/quote
capabilities and the independent dimensioned measurement family. All 109 Rust
tests pass in debug/optimized builds, with formatting/Clippy, 116 independent
native/local cases, 33 measurement HTTP mutations and 111 invoicing mutations.
Calculation/equipment HTTP runs at 64 and 4,096 sources pass; full 4,096 fanout
still rejects atomically at the unchanged 200,000-unit work limit. Final 4,096
zero/one-selection counters match G4b; larger native envelopes increase bytes.
Cross-host latency is not a performance conclusion. The last packaged release
remains 0.6.0. All work stays on `main`; checkpoint commits remain linear.

The original cloud G4b binaries/stores were absent. A local build from an exported
`b377b21` tree is retained under `target/g4b-retained-b377b21/`, including three
populated fixture stores and a provenance manifest. This is rebuilt local
compatibility evidence, not the original cloud executable.

**G4b accepted at `b377b21`:** source 0.7 / store+codec 5, exact time windows,
augmented reverse routes and final segment-cover dependencies. Its dated
[evidence](research/evidence/2026-10-23-g4b-windows.json) records 99 Rust tests,
116 independent cases, invoicing and both 4,096-source HTTP workflows. Preserve
those claims as evidence for that revision. The last packaged release remains 0.6.

**G4a is accepted:** output-free
validators, calculation-only readers and inactive-query fallback controls pass
80 debug/optimized Rust tests, all 116 independent native/local cases and the
111-mutation invoicing HTTP workflow. Production identities and store/codec 4
are unchanged; copies of both G2 4,096-source stores pass complete checks.
[G4a evidence](research/evidence/2026-10-23-g4a-validation.json) retains execution.
The user now
authorizes preparing and implementing remaining capabilities through small,
explicit APIs. G4a closes output-free aggregate validators; G4b adds exact
reactive windows. Prepare external work alongside core development, then
integrate through a named durability gate. Verify, commit and push checkpoints
on `main` without waiting for another prompt. Preserve accepted releases.

**Previous goal complete: G3d settlement/refund and G3e deployment bundle, 0.6.0.**
The user selected a verified bundle in this environment. The
[release result](research/29-deployment-result.md) and
[evidence](research/evidence/2026-10-23-g3e-deployment.json) own current acceptance.
No external host installation or frontend was in scope.

**Deliverable:** `target/g3e-release/rebase-next-0.6.0-linux-x86_64.tar.gz`,
7,726,619 bytes; SHA-256
`e328c9da75eefaa4678f760e86707422a1b36a5bec5dc5e34231f23209c560f9`.
It pins published source commit `305a7b8`; final acceptance is recorded afterward.
Two exported-source builds outside Git produced identical archives/manifests and
the G3d executable. All 157 source blobs and 159 payload checksums match; changed
and missing file controls reject. The bundle includes source/tools/templates,
with Linux x86_64/glibc 2.38+ requirements recorded in `BUNDLE.json`.

**G3e verified:** extracted calculation fixture/replay/archive workflow, both
64-source calculation/equipment arithmetic/rollback/crash/restore workflows,
111 invoicing HTTP mutations /340 commands (75 commits, 36 complete rollbacks),
18 Python controls, fresh issuer/template setup for all three models and nine
failed-restore controls. Restored template services return the original values
and receipts. Final source checksums pass and all owned servers are stopped.
`target/g3e-release/extracted.json` locates the retained private disposable stores;
reports/logs are preserved beside the archive.

**G3d published as `54b1249`:** Treasury, Payment, linked Refund, complete-time
invoice balance and gross directional claims. [Native evidence](research/evidence/2026-10-23-g3d-settlement.json)
records 76 debug/optimized Rust tests, 116 independent native/local cases and clean
formatting/Clippy. The G3c store rejects with physical bytes unchanged; its matching
binary/store remain under `target/g3c-retained-53ff9e7/`. Crashed files can require
allocator recovery first. New referenced parents precede children; deleted
calculation producer UUIDs remain reserved. Calculation/equipment identities and
store/codec 4 are unchanged; invoicing behavior is `invoice-assessments-2`.

**Publication:** the historical package is published as `305a7b8`. Current Git
HTTPS fetch/push works in this cloud workspace. Keep checkpoint commits linear
on `main`; compare current remote state before pushing and never force unrelated
changes. Historical connector-era references remain under `refs/codex/checkpoints/`.

**Historical next action:** V1.1–V1.5 are accepted in the
[workshop result](research/44-workshop-verification-result.md). The assigned goal
stops here; G6 broader accounting, G7 distribution and G8 release expansion
remain deferred. Earlier executable and acceptance notes below are historical.

G4d's final executable is `target/g4d-accepted/rebase-next`. Reports are
`target/g4d-checks.json`, `target/g4d-shares-http/result.json` and
`target/g4d-compatibility.json`. The initial combined native run contains two
test-assertion failures (internal type tag expected in public values); retain its
passed 58 library/nine invoicing results and the final six-publication/four-share
reruns. Do not rerun successful campaigns just to replace that history.

G4c's final binary is `target/g4c-accepted/rebase-next`. Its final check manifest,
HTTP reports and compatibility result are located by the dated evidence. The
`build/` directory inside `target/g4b-retained-b377b21/` was reused as a Cargo
cache and now contains newer executables; only the binary directly under that
retained directory is the G4b baseline. No cloud partial code was used.

G5 has a concrete [lifecycle gate](research/33-external-effects-gate.md) and
[current integration review](research/35-external-integration-review.md).
Atomic intent now shares `local::mutate_inner`'s transaction in store format 7;
there is no accepted provider support. `Store::publish_native` and tagged receipt
publication are the shared transaction seams. Complete immutable facts, bounded
discovery, restricted application and restore reconciliation at G5b/G5c; never
add a separately committed enqueue or alternate domain writer.
The accepted bundle's
[deployment commands](docs/deployment.md) remain valid. Full accounting, rational
FX, external effects, distributed adapters, larger invoicing populations and
frontend remain unaccepted until their gates execute. The existing bundle is
not general production-capacity certification.

**D1–D6, G1 and G2 complete: reusable compiled bounded backend and developer tools; no frontend.**
**G3a accepted: exact values**, [gate/result](research/25-exact-values-gate.md).
`values::{Rational,Rounding}` supplies bounded exact multiplication, canonical
fraction objects and six explicit rounding modes. All 7,396 Python Fraction
cases match in debug/optimized builds; 63 Rust tests and all 116 independent
native/local cases pass. A test-only binding verifies authenticated HTTP,
derived sums, nine rejected batches with complete rollback, replay and reopen.
G3a also closes positional-array deserialization and maps `inexact` safely over
RPC. Existing production models, identities, store/codec 4 and limits are
unchanged; this is a source checkpoint, not a new full-accounting release.
G3a is committed and pushed as `16514d9`.
**G3b accepted: [typed parent parameters](research/26-parent-parameters-gate.md).**
`ReactiveBinding::Parameters`, `resolve -> Resolved<Parameters>` and explicit
evaluation arguments preserve the final-graph scheduler and old/new direct routes.
Three native tests cover inherited rounding/rates, equal-result dependency
retention, retarget cleanup, both command orders, five whole-state rejections,
replay and reopen. All 66 Rust tests and 116 independent native/local cases pass;
copies of both G2 4,096-source stores pass complete checks. Existing bindings use
`()`, and their model/store identities remain unchanged. No derived/multihop
parameter support or sandboxed purity is implied.
G3b is committed and pushed as `af858b0`.
**G3c accepted: [bounded invoicing](research/27-invoicing-gate.md).** Package 0.5
adds `--model invoicing`: five public/four private contracts, fractional pricing,
dated cumulative tax/tax-on-tax reassessment, linked monetary credits and two
repeatable developer fixtures. Behavior `invoice-assessments-1`, model
`731c9d029a8d4433f279eda2b87c0e734f2ee2c99239c459e8d7600e3689b58f`;
existing model/store identities unchanged. Initial envelope 64/256/512. All 72
Rust tests and 116 independent native/local cases pass. The independent Fraction
HTTP workflow passes 58 mutations /200 commands, including 40 seeded stress
batches, the 64-source boundary, replay/reopen/crash/restore; standalone copied
sources/tools pass with an identical optimized binary. Fixtures prove 11555 → 9244.
**G3d settlement/refund now accepted** on this binding: Treasury, Payment and linked
Refund, Invoice paid/balance and gross directional receivable/payable histories.
No mirrored counterparty ledger. Fully paid 11555 then Credit 2001 + Refund 2311
at time 50, reassessments −200 at 51 /−110 at 52 end with gross/paid/cash
9244, balance 0, R=P=13866. Credit alone or refund delayed to 52 rejects the
historical balance. Invoicing behavior is now 2; calculation/equipment identities
and store/codec 4 remain unchanged.

Cloud verification uses `CARGO_INCREMENTAL=0` after debug incremental cache
filled the 32 GiB workspace. Only generated incremental cache was removed; keep
source/evidence/observations. Check formatting/Clippy before expensive release
tests to avoid repeating optimized compilation for style-only failures.
The user explicitly requests a continuous checkpoint loop: verify, commit, push,
start the next checkpoint without waiting for another command. Keep context here
and in commit messages for switching agents; preserve uncommitted work until read.

The user has authorized autonomous implementation, breaking changes, checkpoint
commits on the existing `main` tree and direct pushes. The
[release checkpoints](research/17-deployable-backend.md) now own continuation.
Preserve ReBase's **power**, not its exact implementation or old APIs. Prefer
small, explicit, stateless functions and mature infrastructure libraries; do not
add a universal DSL/plugin framework or duplicate schemas between runtime/tools.
Carry context in this directory and checkpoint commit messages so another agent
can resume without another whole-repository audit. The [0.4 result](research/24-population-scaling-result.md)
and [deployment guide](docs/deployment.md) own current acceptance. The
[0.2 result](research/18-release-result.md) and [0.3 result](research/21-compiled-model-result.md)
remain dated. Enter a named
future capability gate when new work is requested; do not repeat completed stages.

**G1 accepted: compiled model reuse.** The [goal](research/20-compiled-model-gate.md)
is implemented through G1a/G1b/G1c. `Binding`/`NativeInput` own native model types,
schemas and trusted behavior; `ReactiveBinding` supplies resolved shapes and pure
evaluations. Shared typed staging, codec/store, final-graph settlement, authority,
queries, receipts, HTTP and recovery serve calculation and equipment without
extending the original input enum. `--model equipment` selects sparse contract
and slot codes through the ordinary CLI/client. Source-derived equipment checks
prove 8/2 → 8/4 → 8/7 allocations, role reuse, retargeting and rollback.
Release 0.3 uses store format 3, native codec 3, calculation behavior 2 and
equipment behavior 1; no silent opening/migration of format 2. Forty-six debug
and optimized Rust tests, six client controls, all 116 independent cases and
both real-process workflows pass. See the result for execution and fingerprints.

**G2 accepted: capacity and reactive candidate selection.** The
[acceptance gate](research/22-population-scaling-gate.md) fixes increasing HTTP
populations and correctness/rollback/work requirements. G2a adds operator-only
committed-work diagnostics and a source-arithmetic equipment HTTP probe. At 24
reservations, an edit after every read still selects all 24, performs 1,154
dependency checks and loads 74,610 native bytes. The
[baseline](research/evidence/2026-10-22-g2-baseline.json) preserves source/build
identity and the 16/24-reservation runs. G2b's ordered reverse indexes and compact
prefix-gate graph are now [verified](research/23-indexed-selection-checkpoint.md):
55 Rust tests and all 116 independent native/local cases pass. The unfinished
`7d7e387` implementation was retained after targeted review and strengthened
controls; its unverified snapshot is replaced by the tested checkpoint.
G2c (`3dd8b56`) coordinates the larger model/codec/inventory/recovery envelope.
All eight real HTTP workflows pass at 64/256/1,024/4,096 public sources, with
source-only arithmetic, exact rollback, replay, pages, retargeting, crash/reopen
and verified restore. At 4,096 equipment sources, zero/one selection uses 24
selector visits and 45/54 loaded keys; a 128-producer cascade commits in 77,089
work units. Full fanout has finite measured commit/rejection brackets, not an
unlimited cascade guarantee. Separate 4,096-source authority trials verify
credential revocation, complete indexes and reopening. Fifty-six debug/release
Rust tests, all 116 independent native/local cases, six client controls and
three population-oracle controls pass. A new depth guard rejects malformed tree
chains before unbounded checker recursion.
Separate real HTTP churn also reaches all 16,384 retained roles with 4,096
sources and 8,184 active outputs, then proves overflow bytewise rollback and
receipt absence. Its 129 replacement batches stay below 39,864 work units;
the verified ceiling backup remains below 64 MiB.

The 0.4 identities are store/codec 4, calculation behavior 4 and equipment
behavior 3. Limits are 4,096 public sources, 8,192 outputs and 16,384 retained
role reservations; commands64, returning32, receipts1,024, backup64MiB and
mutation work200,000 remain separate. Earlier stores require their matching
binary. The result owns exact execution/source hashes and coverage limits.

**Continuation after G2:** G3a closes the numeric foundation and G3b passes
declared authored parent parameters into pure evaluation. G3c now implements a
representative invoicing workflow. Follow
[the G3b result and next boundary](research/26-parent-parameters-gate.md), not
another whole-system plan. Arbitrary aggregates/topology,
external effects, distributed conformance, full accounting parity and populations
beyond 4,096 remain separate, unaccepted capabilities. Preserve independent
checks, fixed work limits, explicit native models and stateless tools.

The [parallel release review](research/19-peer-release-review.md) adopts remote
`242a08b`/`1f16278` over overlapping local alternatives. Fresh execution confirmed
39 release Rust tests, six client controls and the full harness. It also found
and corrected an inherited integrity-checker bug: quote member slot 3 was
mistaken for slot 1, causing valid exchange state to fail check/startup/restore.
The mixed causal/FX regression now brings the suite to 40 tests. Model/store/
behavior identity is unchanged; historical D6 evidence remains dated.

D1/D2 are complete: pure principal/DAG scopes, per-operation actor sessions,
separate owner/reader, declared reader selection and atomic reader-index repair,
bounded indexed merging and revocation-aware receipt disclosure. D6 now accepts
the release build at 64 public sources: 128 writes, 1024 concurrent reads,
duplicate/CAS races, process-crash recovery and verified restore. Thirty-nine
release Rust tests and six Python client controls pass. The client avoids loading
TLS trust roots for plain HTTP while retaining normal HTTPS verification.
D5 adds model-driven
fixture plans, a stateless HTTP client, private durable mutation plans and a
real HTTP developer harness (39 Rust tests plus five client fault controls).
See [developer tools](docs/developer-tools.md). D4 adds current-state integrity,
verified backup/restore, reset, stable explicit data identity and fenced receipt
archiving (38 tests). Mutations/status now require the original `context` from
`session.describe`; never refresh an uncertain old request across an archive or
reset. See [storage lifecycle](docs/storage.md). D3 adds authenticated bounded
HTTP `/rpc`, Ed25519 JWT verification, offline issuance and real concurrency /
revocation / timeout tests (34 Rust tests; clean dependency audit). See the
[server guide](docs/server.md). The existing stdio interface remains a trusted
filesystem/operator interface, not an authentication bypass exposed over HTTP.

**Confirmed local-prototype finish line completed.** After `2109687`, the user
chose engine, model tooling, mutation/query API and a demonstrable workflow.
[P1–P4](research/13-local-prototype-plan.md) are complete. Start with the
[current result](research/16-local-prototype-result.md) and
[run/API guide](docs/local-prototype.md), not another whole-system audit.

The binary `rebase-next` provides a bundled prepared model, separate catalogs,
offline/live developer views, exact mutations, durable receipts, bounded public
pages/exists and root publications over redb. Its JSON-RPC transport is local
stdio with a fixed actor/tenant. `demo <new-directory>` runs the causal diamond,
rejections/replay and reopen; it creates a usable store and offline inspector.
The [interface contract](research/14-local-interface-contract.md) owns that scope.

P1–P4 acceptance included 27 Rust tests, 107 native cases / 148 operations and
nine local-adapter cases / 14 operations, plus the executable demo/browser view.
The independent checkers derive complete state and receipts from authored inputs
and explicit allocation history. [Final evidence](research/evidence/2026-10-22-local-prototype.json)
owns current fingerprints and counts. The [P1 result](research/15-causal-native-result.md)
and earlier evidence remain dated. D2/D3 subsequently added bounded transactional
DAG authorization and cryptographic network identity. Arbitrary models,
distributed adapters, effects and a full accounting/UI port remain future gates.

## Purpose and authority

ReBase is a calculation engine for connected, typed facts. The redesign changes
the implementation stack while preserving its mathematical and domain concepts.
The objective is the smallest amount of complex behavior the developer must own:
explicit contracts, composable functions, predictable work and narrow boundaries
that prevent maintenance changes from spreading across unrelated components.

The latest user corrections in the attachment take precedence over earlier
suggestions. Current source takes precedence over historical agent reports.
Sources, fingerprints and topic locations are in [sources.md](research/sources.md).
This review started at ReBase `e5d13b3`, which adds the isolated research to
`a963b25`; MetaSol is a separate repository at `28c6e7f`. Both trees were clean.
The prior GitHub/GitLab checks were October 21 observations, not a fresh pull.

The M3/M5 continuation started clean at `947cc25`, the committed context/audit
packet. It inspected the relevant current query/output sources without another
whole-project audit. Its changes and new research model remain inside this folder.

The October 22 request explicitly keeps work in **research, wireframes and
scenario design before implementation planning**. The [system review](research/06-system-audit.md)
maps documentation, hidden database responsibilities and past failures.
[Contract wireframes](research/07-contract-wireframes.md) define the API/tooling
seams, and the [research workflow](research/08-research-workflow.md) owns the
current gates. Earlier automatic “next: implement” wording is superseded. The
subsequent M contracts supported a bounded implementation plan. The later user
request authorized completing its S1–S5 stages autonomously; those stages are
now accepted. Deferred capabilities remain outside that bounded experiment.

## Meaning to preserve

1. **One stable record identity.** A fact can own roots, contribute through
   multiple slots, consume inputs and validate state. These roles are independent.
   A record can also have no tree role. Physical database tables are optional.
2. **A contract defines obligations.** Strict fields, allowed reference targets,
   immutable dimensions, required participation, calculations and invariants must
   be unambiguous. A compact schema code is the proposed selector; a full class
   hierarchy in a key is unnecessary. Sparse records and selected dimensions do
   not require all possible dimension combinations.
3. **References and memberships are distinct.** A currency reference does not
   imply a currency index. An invoice may validate children without reposting
   their amounts. A payment's contract can require treasury participation.
4. **A root is an ordered projection and publication boundary.** Its identity is
   `(owner record, root slot)`. A member is `(source record, member slot)` with a
   typed business key and deterministic tie breakers. One source may appear in
   several roots or several positions in the same root.
5. **Fixed-width associative summaries maintain rules efficiently.** Count,
   sum, extrema, ordered prefixes, complete-time boundaries, tags and interval
   endpoints are examples. Ordered combination need not commute or have inverses.
   Exact units, nanoseconds, rounding and missing-value semantics are contractual.
6. **Dependencies are declared.** Local fields follow actual dependency order;
   direct referenced fields use reverse routes; ordered reads declare source root,
   operation, bounds, consumed channel and fallback. Slots are fixed by the model;
   record inputs can change their activation, source and bounds.
7. **One dynamic principal DAG.** Tenant, user and group ancestry handles control
   and sharing. Domain reference graphs may have diamonds; each maintained index
   has tree topology, and active calculations must remain causally acyclic. These
   are different graphs, not a restriction that all business relations are trees.
8. **Access and calculation authority differ.** Requested writes and new links
   require client authority. Declared internal repairs and protected derived
   outputs use engine authority. Neither bypasses tenant or invariant checks.
9. **Retain the reader distinction.** The final discussion retracts removing
   `read_by`. Read visibility uses a selected immediate reader principal; write
   authority uses `owned_by`. Reader indexes must enumerate readable candidates.
10. **Execute against one transaction attempt.** Read a consistent snapshot,
    cache touched state, stage changes, settle dependencies, validate and commit
    final dirty values atomically. Retries discard the entire attempt and its
    authorization cache. Raw KV writes bypass the engine's guarantees.
11. **Effects have durable intent.** External delivery follows commit. Inline
    waiting and background dispatch can share the same intent/lifecycle; a due
    time supplies one-shot scheduling. Pure signing grants are a separate case.
12. **Declarations serve tools too.** Derive separate public contracts and full
    developer metadata from one loaded model. Private source/roles do not become
    public through a UI toggle. Keep fixture recipes and appearance/workflow
    choices explicit; bind artifacts and persisted state to model/codec identity.

## Corrections already resolved by the discussion and contracts

| Phrase or hypothesis | Precise meaning |
| --- | --- |
| Compiler becomes runtime | Load and validate declarations once; execute their prepared plans in Rust instead of generated SurrealQL. Compilation and runtime coexist. |
| Current writes commit repeatedly | Current synchronous events run inside an atomic transaction. They issue incremental maintenance statements; the redesign proposes a shared workspace and fewer final dirty writes. |
| Segment/rank/statistics tree are identical | An augmented balanced search tree supplies overlapping capabilities. Median amount needs amount ordering; date ordering supplies date rank. |
| Everything is `O(log n)` | Each balanced path is logarithmic; affected records, memberships, intervals, partitions and DAG closure add work. |
| Monoids remove validation | They preserve enough information to make a declared invariant cheap to check. A nonnegative final sum does not prove a nonnegative history. |
| Validate after every rotation | Check structural conditions immediately; business rules at a settled checkpoint or the final atomic-operation boundary. Incomplete construction can be temporarily invalid. |
| Shared blind write normalizes OCC | A portable guard must have a defined conflict contract, normally a tracked read plus changed write. FoundationDB does not reject concurrent blind writes solely for sharing a key. |
| Stateless token includes a wrapper | Token proves identity and may narrow capabilities. Server-owned plans enforce current authority. Client wrappers cannot enforce a boundary. |
| Request cache solves every revocation issue | Read current permissions in each attempt; protect those reads against concurrent edits. Session revocation remains a separate policy. |
| Fresh authority cancels any overlapping response | Read authorization has a snapshot boundary. FoundationDB read-only transactions do not commit/conflict; response-time revocation needs a separate protocol. |
| Owner partitions cover all reads | False when `read_by != owned_by`. Retain reader partitioning or another complete reader candidate source. |
| K-way merge everywhere | Use it only for several streams sharing the same full order. A single root needs one traversal. |
| A page limit bounds the whole query | Scope discovery and opening K streams require their own budget. An incomplete scope cannot establish a globally first page or exhausted search. |
| Unchanged index key means unchanged query | Residual-filter/projection or policy changes can invalidate a page without a rekey; cursor revisions must cover their promised consistency scope. |
| UUID includes tenant/owner/hierarchy | Keep mutable relationships out of canonical identity. Store a schema code and relations in the record/header; roots provide partitions. |
| Deterministic short hash means unique code | A persisted explicit codebook supplies stable uniqueness. A seed cannot losslessly compress arbitrary growing identities. |
| JSON is necessarily the bottleneck | Parse/validate at ingress, compute using native values and encode at egress/persistence. Profile before claiming a dominant cost. |
| Any ACID backend is interchangeable | Atomic multi-key commit, consistent reads, guard semantics and limits must conform. Raw write batches alone are insufficient. |

## Proposed smallest architecture

The shipped local subset is documented above. The broader architecture below
retains design direction; it does not add capabilities to the accepted prototype.

Use one Cargo package and ordinary modules. One loaded design combines authored
JSON Schemas with separate declarations for references, memberships, queries,
invariants and exposed operations. Ordinary trusted Rust functions supply behavior.
Do not invent a general query language, dependency capture framework, universal
middleware DSL or one package per feature.

Publish the new model's authored schemas unchanged from that model, but do not
assume today's schemas transfer byte-for-byte: current reference patterns contain
SurrealDB table prefixes. UUID-only transport requires an explicit contract edit,
while typed target obligations remain in the declarations.

Rust is the recommended execution core; Serde and `serde_json` handle values;
`jsonschema` compiles reusable validators. `jsonrpsee` plus Tokio can host the
eventual JSON-RPC server; Axum/Tower is optional when broader HTTP routes are
needed. Start storage proof with redb's ordinary serialized writer transactions.
FoundationDB is the proposed distributed adapter, conditional on conformance and
transaction budgets. TiKV and other engines are alternatives, not promised support.

Use stable 16-byte UUIDs and explicit `u16` schema/field/slot codes. Random UUIDv4
matches the latest observation that identity need not order records; UUIDv7 is
available for locality. Leave shorter custom IDs and principal dictionaries until
measurements justify their allocation/collision costs. Keep business payload and
structural slot storage separate without creating another business identity.

Public operations are structured `get`, `page`, `exists`, `mutate` and declared
root reads. An explicit mutation is one atomic unit; a JSON-RPC batch is not.
Queries select registered access paths, typed bounds, allowed predicates and
projections. Unsupported orderings reject. Optional residual filtering has a
visit budget and continuation; exhausted-budget `exists` is **unknown**.

## Production choices still open

- Local mutations now use final settled global validation. Any future independent
  command checkpoints require a separate declared operation. Early failure must
  be conclusive, not a transient deficit.
- Preserve current ordered scalar-reader selection initially. Its first-choice
  rule for incomparable principals is deliberate and is not a union or a universal
  lowest node. Multi-reader sharing requires a separately chosen policy.
- Start linked augmented indexes for the required mathematical operations.
  Ordinary ordered KV prefixes may implement simple enumeration later; they must
  not become undeclared default domain indexes or dictate the portable core.
- General decimal rounding, production timestamp policy and large cascades need
  their own decisions. The prototype fixes i64 time, exact bounded integers,
  revision-bound cursors and declared work/population limits.
- Distributed adapters, cryptographic identity verification, principal graph
  repair, ordered-result-driven topology and external delivery remain outside
  the local prototype. Authored-shape causal settlement is implemented.

## Work completed and continuation boundary

The [feasibility report](research/05-feasibility.md) records the executable Rust
checks and their scope. Standard AVL balance, heap merge and identity mathematics
are established algorithms; their proofs need no broad stress campaign here.
Unusual complete-time summary composition and transactional staging receive
focused checks against independent expectations. The initial October 22 review
verified all 11 executable-source fingerprints and reused the dated results;
that audit did not rerun or expand the proof. All 26 original repository source
fingerprints matched at that audit. Native execution below has since changed
the package.

The [bounded reference fixture](research/08-research-workflow.md#2-the-bounded-reference-scenario)
now specifies one source type, two memberships, a direct rule, dated quotes,
exact expected values and a historical invariant. The scenario register covers
API/tooling and future capabilities separately; its cases are not executed tests.

[M3/M5](research/09-causal-settlement.md) now defines the combined private-output
prefix fixture, a diamond and rejected feedback. Shape is resolved from authored
facts and acyclic direct-scalar inputs before ordered calculation. Old/new routes
discover invalidated work; only the final graph determines causality. Detachment
must cover affected managed outputs and pending predecessors, not just a moved
record's own slots. Query identity survives coincident bounds and zero amounts.

The bounded Python research model checked nine source states and all 36 valid
orders against grouped source arithmetic and literal expectations. It preserved
wrong-order and false-cycle counterexamples, logical inventory controls and
lifecycle rejection predicates. At that stage all 11 Rust proof inputs matched;
its suite was not rerun or expanded by M3/M5. This is not incremental, structural,
authority, UUID-allocation or storage-rollback evidence. General topology driven
by ordered results remains deferred.

[M6](research/10-independent-checker.md) now defines expected source/role
inventories separately from complete raw observation and actual tree walks.
Required empty roots, duplicate identities and disconnected slots are explicit
obligations; exact source scans check every subtree and publication. Valid
alternate shapes pass. Five valid synthetic snapshots passed, 28 invalid-state
controls rejected and two incomplete-scope/budget controls stayed incomplete.
The checker reuses the unchanged M3/M5 source oracle. It does not implement a
native writer, snapshot adapter, direct reverse routes or storage acceptance.

The [M1/M2/M4 plan](research/11-native-slice-plan.md) fixes six source types,
exact integer/UUID bindings, authored commands, separate record/root revisions,
final quote uniqueness and reference deletion rules. It uses linked quote and
financial trees with bounded point-owned reverse lists. A curve edit discovers
all old/new subscribers; minimal interval invalidation is deferred. The plan
separates independent expected state, real raw observation and all-key rejection
snapshots. The [execution report](research/12-native-slice.md) now verifies those
expectations against the actual native state.

**S1–S5 complete:** 68 cases / 93 operations passed the independent checker:
53 commits and 40 rejections. All source/role inventories, actual AVL links,
subtree caches and publications matched. Each rejected operation preserved all
application KV bytes; two controls aborted after actual writes. Old reads stayed
unchanged across all operations and all 68 stores matched after reopening.
Four valid checker controls, 20 corrupt images and two incomplete observations
also behaved as required. Thirteen integrated Rust tests, formatting and Clippy
passed. [Dated evidence](research/evidence/2026-10-22-native-slice.json) owns the
source hashes, commands, counts and limits.

The implementation is a fixed native calculation experiment with a toy actor,
point-owned reverse lists and one embedded writer. The baseline has 33 KV rows.
The original algebra/order/overlay and eight semantic tests are unchanged, but
`Cargo.toml`, `Cargo.lock` and module exports changed; the original 11-input
fingerprint claim is historical. Earlier evidence and Python programs remain
unchanged. No original ReBase/MetaSol code or acceptance suite was modified/run.

That bounded S1–S5 goal was complete at its dated evidence. The later P1–P4 goal
has now added native causal/output lifecycle, prepared tooling, a public local
API, replay receipts and a demo. Use paper 16 and the affected future gate for
new work; do not restart S1 or repeat the broad audit.
