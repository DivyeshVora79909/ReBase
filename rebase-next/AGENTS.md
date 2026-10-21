# Working on the isolated redesign

Read `README.md` and `CONTEXT.md` first, then only the paper relevant to the task.
`research/sources.md` locates original claims; `research/source-manifest.json`
fingerprints the inspected inputs. Do not reload all historical transcripts for
a task whose meaning is already recorded. Recheck current source when it matters.

This is research plus a bounded proof, not an implemented application runtime.
Preserve the difference between intent, proposals, established mathematics and
executed evidence. Update the feasibility report when executable scope changes.

The October 22 phase is contract wireframes and scenario design. Read
`research/08-research-workflow.md` for the active gates before interpreting
“continue.” Do not promote the old next-runtime-slice proposal into current work.
Use `research/06-system-audit.md` for documentation/change impact and
`research/07-contract-wireframes.md` for API, tooling and lifecycle boundaries.

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
