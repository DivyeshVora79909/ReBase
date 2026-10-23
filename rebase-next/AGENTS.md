# Working on the isolated redesign

Read `README.md` and `CONTEXT.md` first, then only the paper relevant to the task.
`research/sources.md` locates original claims; `research/source-manifest.json`
fingerprints the inspected inputs. Do not reload all historical transcripts for
a task whose meaning is already recorded. Recheck current source when it matters.

**Current release: G3d/G3e complete, 0.6.0.** Read
[deployment acceptance](research/29-deployment-result.md) and the
[deployment guide](docs/deployment.md). The selected goal produced a verified
bundle in this environment, with all three models, issuer/template checks,
crash recovery and failed-restore isolation. No follow-on implementation gate is
active. Further capability work enters a named bounded gate; preserve earlier
evidence and the explicit capacity/model boundaries below.

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
Continue autonomously through tested implementation checkpoints: commit and push
each coherent checkpoint on the existing `main`, then start the next without
waiting for another "continue". Keep the current gate and exact continuation at
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
Read `research/04-implementation.md` and the active research gate before expanding
scope. For docs-only changes, verify links and relevant fingerprints; unchanged
dated proof evidence does not require another database or Rust suite run.

Do not turn the proof's synchronous embedded transaction into the assumed
distributed driver API. Adapter conformance is a semantic requirement. Do not
claim production capacity, exactly-once external effects or universal logarithmic
updates from the proof.
