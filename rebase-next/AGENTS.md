# Working on the isolated redesign

Read `README.md` and `CONTEXT.md` first, then only the paper relevant to the task.
`research/sources.md` locates original claims; `research/source-manifest.json`
fingerprints the inspected inputs. Do not reload all historical transcripts for
a task whose meaning is already recorded. Recheck current source when it matters.

This is an early local prototype backed by bounded research evidence.
Preserve the difference between intent, proposals, established mathematics and
executed evidence. Update the feasibility report when executable scope changes.

The user confirmed a usable local prototype as the autonomous goal. P1–P4 in
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
