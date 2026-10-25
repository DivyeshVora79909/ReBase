# Working on the isolated redesign

Read `README.md` and `CONTEXT.md` first, then only the paper relevant to the task.
`research/sources.md` locates original claims; `research/source-manifest.json`
fingerprints the inspected inputs. Do not reload all historical transcripts for
a task whose meaning is already recorded. Recheck current source when it matters.

**Active goal: implement G9.0–G9.4, 2026-10-25.** The user explicitly authorized
G9 after G8 closeout and now requests checkpoint pushes to origin/main. This
supersedes the earlier stop/no-push handoff. Root owns Git integration and
pushes; replace the unverified origin tip only with an exact force-with-lease,
then use ordinary linear pushes. Never overwrite unexpected new remote commits.
Read [G9](research/54-composable-developer-tools-plan.md), [current results](research/55-population-tooling-result.md)
and the top of CONTEXT. G9.0 is accepted; G9.1–G9.4 remain. Use the selected
Python orchestration and optional bounded Node value provider, then implement
accepted operation
boundaries; do not build a universal schema or constraint engine. Use Luna leads
and narrow disjoint delegated tasks with explicit tests; root verifies final
integration. One Cargo owner, two jobs, incremental off; reuse G8 evidence.
G6, TiKV, frontend, live providers and million-record expansion remain deferred.

**Latest closeout: G8.0–G8.5 accepted within recorded limits, 2026-10-25.** Read
[the workload/deployment plan](research/52-workload-deployment-plan.md), [the results](research/53-workload-deployment-result.md)
and the top of `CONTEXT.md`. The newly selected G9 goal is above. Do not begin G6, TiKV, frontend, live-provider or
million-record capacity work.

The current tools provide smoke, churn, overload, outage and independent check
commands through `tools/g8.py`; profiles and exact boundaries are in
`docs/workloads.md`. Keep existing APIs, limits and evidence identities. Do not
re-run unavailable historical campaigns or turn paced observations into capacity
claims. Preserve the G8.3 outage boundary: owned local FoundationDB service
recovery, not native commit-ack, replicated failover or disk/power-loss proof.
The earlier G8-only stop and no-push instruction is historical; the active G9
goal above supersedes it.

G9 is [selected](research/54-composable-developer-tools-plan.md), with G9.0 first.
Reuse the existing
client, scheduler/observer primitives and authoritative model metadata.
The resumed environment rebuilt 0.16.0; historical g75/g81 run paths can be absent.
Read the current continuation rather than assume those binaries are available.

**Accepted baseline: G7.0–G7.6, 2026-10-25.** Read
[the final result and stop boundary](research/51-storage-conformance-result.md)
and the top of `CONTEXT.md`. FoundationDB, redb and standalone SurrealKV use
one persistence boundary with executed application and recovery evidence.
TiKV, G6 accounting and frontend remain deferred; G8 implementation is
selected above. The user confirmed that local commits
on existing `main` are enough; G7.5/G7.6 do not require a push.
For future authorized implementation, use small delegated tasks with exact file
ownership, one Cargo owner, cached artifacts and incremental off. Preserve
independent checks and do not accept mock-only distributed evidence.

[G7.5 scoped coordination](research/50-scoped-coordination-result.md) remains
accepted. The disjoint existing-root witness has no common application write
key; population changes, shared roots/query partitions and effect counters
still coordinate. This is not a throughput or capacity claim. Current source/
store/native/effect/API formats are 0.16.0 /10 /7 /4 /4, with no migration.
Reuse accepted evidence without restarting earlier campaigns. The owned test
servers are stopped and retained binaries are under `target/g75-accepted/`.

V1.1–V1.5 remain accepted in source 0.15.0:
[results](research/44-workshop-verification-result.md) and
[guide](docs/workshop.md). Keep this historical source/evidence separate from
the subsequently executed G7 adapter acceptance.

**Historical G3 release: G3d/G3e complete, 0.6.0.** Read
[deployment acceptance](research/29-deployment-result.md) and the
[deployment guide](docs/deployment.md). The selected goal produced a verified
bundle in this environment, with all three models, issuer/template checks,
crash recovery and failed-restore isolation. The subsequent
[capability program](research/30-capability-program.md) is active: first
[G4a terminal validation](research/31-terminal-validation.md) and
[G4b reactive windows](research/32-reactive-windows.md) and
[G4c native indexes](research/34-native-index-extension.md) are accepted source
checkpoints. Source 0.8.0 / store+codec 6 adds the shared native-family tree and
dimensioned measurement model. [G4d-a published values](research/36-value-dependencies-gate.md)
is also accepted in source 0.9.0, with unchanged store/codec 6 and invoicing
behavior 5. [G5a atomic intent](research/37-atomic-intent-implementation.md) is
accepted in source 0.10.0 /store 7 /native codec 6 /effect codec 1 /API 2.
[G5b worker/application](research/38-fenced-worker-implementation.md) is accepted
in source 0.11.0 /store 8 /native codec 6 /effect codec 2 /API 2.
[G5c ingress/recovery](research/39-ingress-recovery-implementation.md) is accepted
in source 0.12.0 /store 9 /native codec 6 /effect codec 3 /API 3. Signed inbox and
reconciliation-only restored activation are verified.
[G4d-b native query consumers](research/41-native-query-consumer-result.md) is
accepted in source 0.13.0, with unchanged store 9 /native codec 6 /effect codec 3 /
API 3 and measurement behavior 2. [G4d-c authored selection](research/42-authored-selection-result.md)
is accepted in source 0.14.0, with the same shared formats and measurement
behavior 3. G4 and G5 are complete within their declared bounds. The earlier
stop after G5 is superseded only by the V1 verification implementation above;
broader accounting and release expansion remain deferred; G7 is accepted above.
Preserve earlier evidence and boundaries below.

The deployable bounded backend and developer-tool goal, excluding frontend, is
complete through D6. Read [the release result](research/18-release-result.md),
[deployment guide](docs/deployment.md) and [checkpoints](research/17-deployable-backend.md).
G1 accepts reusable compiled model execution; G2 subsequently accepts 0.4.0
population and indexed reactive selection. Read
[the population result](research/24-population-scaling-result.md) and
[model authoring](docs/compiled-models.md). Both bundled models use the shared
typed mutation, causal, storage, authority and tooling paths. The enforced
envelope is 4,096 public sources /8,192 active outputs /16,384 retained roles;
the 200,000-unit mutation budget remains. Larger fanout can reject atomically.
Do not repeat accepted G1/G2, raise constants and call that scalability, or
represent these authored workload checks as unrestricted production capacity.
Future work enters a named capability gate; do not restart accepted stages.
Within the user's active scope, commit each verified checkpoint on existing
`main`. G7 is complete; G8 implementation is explicitly assigned above. Do not
automatically start G6, TiKV or frontend.
Keep the current gate and exact continuation at
the top of `CONTEXT.md` so a fresh agent can resume. Preserve capability, not the old
implementation: choose a simpler approach when it satisfies the same contracts.
Small composable ordinary APIs and one authoritative model are the design aim.
G3a accepts [exact values](research/25-exact-values-gate.md), and G3b accepts
[typed authored-parent parameters](research/26-parent-parameters-gate.md), with
source-derived native acceptance and rollback checks. G3c accepts
[bounded invoicing](research/27-invoicing-gate.md), and G3d accepts
[settlement and refund](research/28-settlement-refund-gate.md) on that binding.
G3e accepts a verified 0.6 deployment bundle in this environment, using
copied sources/tools and all three real HTTP workflows with recovery.
Existing calculation/equipment bindings and
persisted formats are unchanged; parameters do not add hidden reads,
published-parent or multihop dependency support.
For constrained cloud verification use `CARGO_INCREMENTAL=0`, preserve evidence,
and run formatting/Clippy before the optimized suite to catch cheap failures.
Do not report full production or old-model parity merely because a server starts.
Storage/model identity now uses an explicit behavior contract, not build bytes.
Bump the affected `Binding::BEHAVIOR` for semantic binding/calculation/causality/
invariant changes (Calculation uses `native_slice::BEHAVIOR_CONTRACT`);
shared semantic changes require bumping every affected binding. Bump store/codec
versions when their formats change. Keep
independent source fingerprints in checkpoint evidence. Mutations/status retain
their original operation context; never bypass archive expiry by refreshing it.

The accepted starting point is a local prototype backed by bounded evidence.
Preserve the difference between intent, proposals, established mathematics and
executed evidence. Update the feasibility report when executable scope changes.

The previous user goal was a usable local prototype. P1–P4 in
`research/13-local-prototype-plan.md` are now complete. Read the current result
in `research/16-local-prototype-result.md` and the runnable instructions in
`docs/local-prototype.md`. Paper 14 fixes the local API/tooling contract; papers
12 and 15 retain earlier native evidence. Do not repeat those stages or infer
production/distributed/full-accounting scope from their completion.
Use `research/08-research-workflow.md` for future gates,
`research/06-system-audit.md` for change impact, and
`research/07-contract-wireframes.md` for broader lifecycle requirements.

Use ordinary Rust modules and trusted functions. Extract a reusable primitive
when concrete uses justify it. Avoid compatibility layers, generic plugin
registries, opaque dependency discovery and protocol-specific business logic.
Keep all build/runtime dependencies inside this directory. Research references
to the original repository are permitted; runtime imports from it are not.

Test an unresolved semantic boundary with a small independent oracle. Stop once
the necessary fact is established. Reusing a known algorithm does not require a
new broad benchmark or duplicating an entire existing acceptance suite.
Use one build owner and a shared Cargo cache per profile. Run affected native
controls and an optimized product workflow when they establish the changed
obligation; a fresh full optimized suite or population campaign is not mandatory
for each gate. Preserve passed evidence and rerun only the checks affected by a
subsequent change or failure. The user explicitly requested this discipline after
repeated compilation dominated checkpoint time.
Read `research/04-implementation.md` and the active research gate before expanding
scope. For docs-only changes, verify links and relevant fingerprints; unchanged
dated proof evidence does not require another database or Rust suite run.

Do not turn the proof's synchronous embedded transaction into the assumed
distributed driver API. Adapter conformance is a semantic requirement. Do not
claim production capacity, exactly-once external effects or universal logarithmic
updates from the proof.
