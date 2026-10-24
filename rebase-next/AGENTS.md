# Working on the isolated redesign

Read `README.md` and `CONTEXT.md` first, then only the paper relevant to the task.
`research/sources.md` locates original claims; `research/source-manifest.json`
fingerprints the inspected inputs. Do not reload all historical transcripts for
a task whose meaning is already recorded. Recheck current source when it matters.

**Active goal: G7 FoundationDB-first storage adapters.** The user authorized
implementation and checkpoint pushes on 2026-10-24. Read the
[G7 contract and checkpoints](research/45-storage-adapter-plan.md) and the top of
`CONTEXT.md`. Implement G7.0–G7.6 with one shared persistence boundary, then
FoundationDB, redb and standalone SurrealKV adapters. TiKV, G6 accounting, G8
workload/release expansion and frontend stay deferred. Commit and push each
verified checkpoint on existing `main`; continue without another prompt.
Use small delegated tasks with exact file ownership, one Cargo owner, cached
artifacts and incremental off. Do not accept mock-only distributed evidence.

G7.0–G7.4 are now accepted within their recorded bounds. The user requested a
clean budget handoff; next is G7.5 scoped revision/receipt coordination, then
G7.6 final cross-adapter closeout. Read
[the latest result/continuation](research/49-storage-api-result.md) before editing.
Global Meta/receipt hot keys remain; do not claim independent-root scalability.
No partial version migration is retained. The current source/store/native/effect/
API formats remain 0.15.0 /9 /6 /3 /3. Preserve earlier evidence.

V1.1–V1.5 remain accepted in source 0.15.0:
[results](research/44-workshop-verification-result.md) and
[guide](docs/workshop.md). Preserve historical source/evidence; adapter
preparation and implementation are not yet backend acceptance.

**Current release: G3d/G3e complete, 0.6.0.** Read
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
broader accounting and release expansion remain deferred; G7 is now selected above.
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
Within the user's active scope, commit and push each verified checkpoint on the
existing `main`. Continue the selected G7 goal; do not automatically start G6 or G8.
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
