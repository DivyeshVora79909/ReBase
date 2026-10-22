# Working on the isolated redesign

Read `README.md` and `CONTEXT.md` first, then only the paper relevant to the task.
`research/sources.md` locates original claims; `research/source-manifest.json`
fingerprints the inspected inputs. Do not reload all historical transcripts for
a task whose meaning is already recorded. Recheck current source when it matters.

The deployable bounded backend and developer-tool goal, excluding frontend, is
complete through D6. Read [the release result](research/18-release-result.md),
[deployment guide](docs/deployment.md) and [checkpoints](research/17-deployable-backend.md).
G1 subsequently accepts reusable compiled model execution in 0.3.0; read
[the current result](research/21-compiled-model-result.md) and
[model authoring](docs/compiled-models.md). Both bundled models use the shared
typed mutation, causal, storage, authority and tooling paths. Their fixed
64-source envelope remains. The next capability is G2: measured population and
reactive-candidate scaling, beginning with a bounded workload/acceptance contract
and then implementation. Do not raise constants and call that scalability, or
restart the completed model-reuse work.
Future work enters a named capability gate; do not restart accepted stages.
Continue autonomously through tested implementation checkpoints and commit each
coherent checkpoint on the existing branch. Preserve capability, not the old
implementation: choose a simpler approach when it satisfies the same contracts.
Small composable ordinary APIs and one authoritative model are the design aim.
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
