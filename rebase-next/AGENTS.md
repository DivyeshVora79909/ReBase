# Working on ReBase Next

Read README.md and the top of CONTEXT.md first, then the current program and only
its relevant companion. Historical evidence remains available through their links.
Keep implementation, dependencies and current tools inside rebase-next/. The
original ReBase is inspiration and research input, not a runtime dependency.

## Current instruction — N6 accepted within bounds; S0 measurement baseline next

The user selected a major redesign on 2026-10-25: Node ESM developer functions
composed directly in the standard REPL, replacement of Python and redundant
project CLI parsers, common explicit configuration/capabilities, and a measured
ordered-storage redesign. Rust remains the native engine; normal Cargo and
minimal process/service bootstrap are permitted. Backward compatibility is not
required. Preserve capability and correctness, not old names or language layers.

Read the [current program](research/56-node-and-index-redesign-program.md), the
[N6 result](research/78-node-retirement-result.md), and the
[release evidence](research/evidence/2026-10-26-n6-release.json). N0–N6 are
accepted within their recorded bounds. The accepted N6 source is
`1243168424294728968591d69efbe5d836fd36fd`; both committed-source packages have
1,061 checksummed files and all six models. The extracted Node suite passes 143
tests with no skips; redb, SurrealKV, and local FoundationDB lifecycle runs
pass. The standalone service checks all six models with an empty `PATH`, fresh
JWT/context, SIGTERM drain, restart, and original receipt replay. Details,
package hashes and boundaries are in the N6 result/evidence. The 60-path
retirement ledger, N0 ledger, and historical evidence remain preserved.

Next, start S0 by freezing the trace/workload schema and measurement plan before
choosing an S1 candidate. Define logical and physical reads/writes, bytes, scans,
cache hits, wait dependencies, conflicts and resource measurements; record data
shape, backend, host/cluster/process topology, and cold/warm controls; then run
the same bounded baseline across supported adapters. Reuse accepted correctness
witnesses. Local multi-process FoundationDB is not multi-host evidence. Keep
capacity claims bounded; do not claim unrestricted production capacity. S0's
measurement baseline must precede any candidate or layout choice. Continue
without reopening accepted N6 campaigns or restarting G7–G9.

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
[pay as you go](docs/agents/pay-as-you-go.md). Select models and delegation
based on the actual environment, available tools, limits and task; account for
their total context, retries and integration. Use only capabilities authorized
and exposed by the current client, and do not infer a client restriction from
its billing mode. Every checkpoint still has explicit inputs, outputs,
invariants and acceptance evidence. Give delegated workers disjoint file
ownership; workers must not reset, stash, rebase or push the shared tree.

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
