# Working on ReBase Next

Read README.md and the top of CONTEXT.md first, then the current program and only
its relevant companion. Historical evidence remains available through their links.
Keep implementation, dependencies and current tools inside rebase-next/. The
original ReBase is inspiration and research input, not a runtime dependency.

## Current instruction — N5 accepted; complete N6 replacement controls

The user selected a major redesign on 2026-10-25: Node ESM developer functions
composed directly in the standard REPL, replacement of Python and redundant
project CLI parsers, common explicit configuration/capabilities, and a measured
ordered-storage redesign. Rust remains the native engine; normal Cargo and
minimal process/service bootstrap are permitted. Backward compatibility is not
required. Preserve capability and correctness, not old names or language layers.

Read [the program](research/56-node-and-index-redesign-program.md), then
[Node contracts](research/57-node-developer-contract.md),
[storage contracts](research/58-ordered-storage-redesign.md) or
[the inventory](research/59-node-capability-inventory.md) as needed.
Read the [N0 decisions and bounded evidence](research/62-node-foundation-result.md),
[N1 result and boundaries](research/63-node-native-host-result.md),
[N2 result and boundaries](research/65-node-workflow-result.md),
[N3 result and boundaries](research/67-node-population-result.md),
[N4 result and boundaries](research/69-node-experiment-result.md),
[N4 contract and evidence](research/68-node-experiment-contract.md),
[N5 release result](research/71-node-lifecycle-result.md),
[N5 lifecycle and release contract](research/70-node-lifecycle-contract.md),
[frozen native wire](research/60-native-host-contract.md) and
[Node dependency decisions](research/61-node-tooling-contract.md) when changing
the Node/native boundary or continuing N6.
N1 implements Node configuration and the private native host for model catalogs
and redb check/inspection. N2 adds Node workflow composition, owned service and
operator APIs, and bounded adapter lifecycle evidence. N3 adds caller-owned Node
population state and receipt-gated proposals for Equipment and Quantity. N4 adds
bounded workloads, experiments, observations and source-only checking; its
accepted scope and incomplete logical/physical obligations are recorded in the
N4 result. N5's committed-source redb and all-feature packages from `6836c59`
verify outside Git; all 122 Node tests pass with no skips. The extracted redb,
SurrealKV and local FoundationDB lifecycle runs pass with complete cleanup.
See [release evidence](research/evidence/2026-10-26-n5-release.json) for hashes,
failed trials and limits. N6 must complete source/physical checking, signed
ingress and bounded invoicing/IssueShare replacement controls before deleting
Python and redundant CLI paths. Ordered-storage changes remain pending. Follow the
dependency ledger through verified checkpoints; do not ask for repeated routine
permission.

This explicitly supersedes older instructions to preserve Python orchestration,
the Python-to-Node faker bridge, legacy CLI verbs, or the G9 no-next-goal stop.
Never treat older CONTEXT handoffs or dated papers as a competing active goal.
G6 accounting expansion, frontend, live providers, TiKV, populated migrations,
unrestricted million-record capacity and the explanation course remain deferred.
Keep coverage for existing bounded model capabilities.

## Authoring and resource discipline

Use ordinary Rust modules and trusted functions for native semantics; ordinary
JavaScript functions and explicit caller-owned state/handles for developer work.
Reuse one authoritative model/catalog. Avoid compatibility shims, generic plugin
registries, a second workflow/query DSL, hidden dependency capture and duplicate
calculation engines. Add a dependency only for a demonstrated supported capability.
Do not introduce a subprocess merely to wrap a function available in Node.

Apply the user's selected [agent execution mode](docs/agents/README.md):
[subscription](docs/agents/subscription.md) or
[pay as you go](docs/agents/pay-as-you-go.md). Keep the selected model and default
to one agent. Batch independent tool operations without delegating agent work.
The 2026-10-26 user instruction supersedes older Luna/Sol delegation preferences.
Every checkpoint still has explicit inputs, outputs, invariants and acceptance
evidence. If the user later requests delegation, give disjoint file ownership;
workers must not reset, stash, rebase or push the shared tree.

Use one Cargo owner and a shared cache, two build jobs and incremental off in
this cloud environment. Node-only changes with unchanged native hashes need no
new Rust build. Run focused checks for changed obligations; expand only for new
failures or unresolved concerns. Do not restart accepted campaigns by default.
Serialize host benchmarks, use isolated owned stores/namespaces, and clean up
only owned processes. Unavailable historical raw runs stay unavailable evidence.

## Correctness and evidence

One native transaction publishes source changes, indexes, summaries, authority
repairs, receipts and applicable effect intent. Preserve final-graph causality,
exact arithmetic, typed references, equal-time/window boundaries and zero-output
dependencies. Independent checkers derive expected inventories from source facts;
they must not merely call production settlement and trust its cached summaries.

Keep original operation IDs, requests and contexts for uncertain outcomes.
Never infer rollback from timeout, cancellation or not-observed status; never
refresh an expired uncertain plan. Keep private operator methods local and scoped.
Native ownership, restore isolation, archive/reset fencing and effect quarantine
remain obligations even when names/wires change.

Bump affected Binding::BEHAVIOR for binding/formula/causality/invariant semantics
(Calculation uses native_slice::BEHAVIOR_CONTRACT); shared semantic changes affect
all relevant bindings. Bump store/codec identities when persisted formats change.
No implicit migration. Runtime data compatibility uses explicit semantics and
formats, while evidence independently fingerprints exact executed source inputs.

Separate proposals, mathematical arguments and executed evidence. Do not claim
universal logarithmic writes, automatic arbitrary constraints, exactly-once
external effects or production capacity. Physical paging does not prove stable
logical aggregate groups. Multi-process local FDB tests do not prove multi-host
latency. Mark unexecuted obligations incomplete rather than passing mocks.

## Git and handoff

Commit verified checkpoints on existing main and push in linear order. Fetch
before integration and preserve unexpected remote work; ordinary pushes only.
The historical force-with-lease replacement of 1fe6310 is complete and must never
be replayed. Root alone owns commits/pushes and records exact continuation at
the top of CONTEXT. No secret credentials or complete private stores enter Git.

For documentation-only checkpoints verify links, source inventories, consistency
and unchanged executable scope; do not rebuild databases or rerun Rust proofs.
Keep historical JSON evidence/fingerprints immutable and identify new execution
separately. The active tool deletion rules are in N6 of the program.

## Accepted baseline references

- [G7 storage conformance](research/51-storage-conformance-result.md): redb,
  FoundationDB and standalone SurrealKV; source/store/native/effect/API baseline
  0.16.0 /10 /7 /4 /4, with no unrestricted capacity claim.
- [G8 workload and deployment](research/53-workload-deployment-result.md): scoped
  churn, pressure, owned service recovery and extracted source8ddc88f packages.
- [G9 population](research/55-population-tooling-result.md): four operations,
  typed pools, exact saved receipts and isolated tooling at the recorded sources.
- [Research workflow](research/08-research-workflow.md),
  [system audit](research/06-system-audit.md) and
  [wireframes](research/07-contract-wireframes.md) retain the broader contracts.

The current program selects the next work. These references explain accepted
facts; do not reconstruct old tool binaries from stale paths or relabel earlier
acceptance as testing the new Node/storage implementation.
