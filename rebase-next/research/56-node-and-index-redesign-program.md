# G10 — Node developer APIs and ordered-storage redesign

Prepared 2026-10-25. This paper records the original P0 planning checkpoint and
its status at that time. Later implementation and acceptance supersede the
original status entries: [N6 is accepted within bounded scope](78-node-retirement-result.md),
as are S0.0 preparation and [S0.1 instrumentation](80-s0-instrumentation-result.md).
S0.2, S1–S3 and F0 remain. The user requested a stop after the S0.1 commit/push;
the next actionable work on a later continuation is recorded below.
The starting implementation is commit `e7458dc`, source 0.16.0, store 10, native
codec 7, effect codec 4 and API 4. G7, G8 and G9 evidence remains historical
acceptance for its recorded inputs. A Git pull before preparation was already
up to date. Check current origin before each later integration.

## User intent and authority

The user explicitly selected this redesign after the G9 closeout. The user is
experienced in JavaScript and the Node REPL and wants to compose ordinary
functions, inspect returned values, and automate scenarios without learning a
project-specific command language. Preserve the original ReBase's useful power,
not its names, implementation, language mixture or compatibility surface.

At P0, the delivery was detailed planning, reviewed documentation, and a linear
commit/push to main. The later implementation continuation has completed N0–N6;
the design discussion need not be repeated.

The user permits breaking changes and explicitly requests:

- Node JavaScript as the single active developer-tool runtime; remove Python
  from supported development, testing orchestration, generation and packaging.
- Direct ESM imports and ordinary functions with explicit arguments and state.
  No custom REPL, command builder, argument-parser facade or workflow DSL.
- Common configuration, limits discovery and predictable explicit environment
  handling, rather than copied constants and hidden process defaults.
- Supported libraries and standard Node facilities for generation, validation,
  files, processes and cryptography, with custom code restricted to real gaps.
- Automation of model inspection, fixtures, service lifecycle, identity setup,
  population, experiments, independent checking, reporting and releases.
- A rigorous assessment of ordered storage, paging and fewer dependent remote
  reads, including the physical/logical distinction discussed below.

Rust remains the native calculation/storage/server implementation. Cargo,
rustup, npm and the operating system keep their normal interfaces. User-facing
JavaScript passes structured data to Rust; it does not reimplement business
formulas or raw storage writes. The production Rust server must not acquire a
Python or Node dependency just because developers use Node tooling.

This supersedes earlier instructions to preserve Python orchestration, the
Python-to-Node faker bridge and all legacy project CLI verbs. The older papers
remain descriptions of their accepted releases, not compatibility obligations.
The previous mathematical cautions also remain: do not turn an unproven idea
into a logarithmic complexity or distributed-performance claim.

## Canonical companion contracts

Read this program first, then the relevant companion only:

| Document | Owns |
| --- | --- |
| [Node developer contract](57-node-developer-contract.md) | Proposed function surface, native boundary, configuration, exact values, ownership and population |
| [Ordered-storage contract](58-ordered-storage-redesign.md) | Physical pages versus logical summaries, algorithms, experiments, complexity and transaction obligations |
| [Capability inventory](59-node-capability-inventory.md) | Existing tool families, semantic replacement coverage and deletion obligations |

If these disagree, resolve the ambiguity in a recorded decision before changing
an executable interface. The checkpoint graph in this document owns ordering
and status. Companion examples are proposals; existing guides remain the source
of runnable commands until their replacement checkpoint passes.

## Architecture decisions already made

1. Use plain Node ESM JavaScript. JSDoc or generated declarations may help
   discovery; do not require a TypeScript transpilation pipeline to use the REPL.
2. Use one authoritative compiled model and exported metadata. Rust owns schema
   and native semantics. JavaScript prepares validators/generators from those
   exports. A JavaScript config does not make arbitrary executable models loadable.
3. Separate pure transformations from owned resources. Pure functions receive
   values; processes, sessions, streams and mutable generation state are explicit
   handles. Avoid global configuration, credentials, RNGs or implicit sessions.
4. Keep one native mutation/validation path. Remote authenticated operations and
   trusted local operator operations have different capabilities; the latter
   must not become public HTTP methods merely to simplify tooling.
5. Return useful objects, iterables or strings. Use `node:fs/promises` for normal
   file writing. A dedicated function is justified for a real semantic boundary,
   such as private write-once plans or verified atomic backup publication.
6. Build process adapters with argument arrays and structured IPC, never shell
   strings. A minimal Rust process bootstrap is acceptable. Maintaining one CLI
   verb for every domain function is not the target architecture.
7. Preserve independent expectations. Replacing Python does not authorize an
   oracle that calls the engine's own calculation or trusts its cached totals.
8. Use page and tree automation through defined algorithms. A database cannot
   automatically split application-defined arrays inside opaque values. Packing
   values may lower key overhead and increase rewrite bytes at the same time.

## Scope and explicit deferred work

In scope: all active ReBase Next developer operations and their checks; discovery,
structured local operation dispatch, lifecycle, generation, experiments, output
rendering, package preparation and isolated acceptance; normalization of settings;
instrumentation and a selected, justified ordered-storage improvement.

Retain coverage for all six existing compiled models, including bounded invoicing,
without expanding their accounting business scope. Equipment, Quantity and
Measurement supply small non-accounting examples; effect-demo retains the fake
provider lifecycle. These examples must remain usable as ordinary compositions.

Deferred: broader G6 accounting, frontend, live provider integrations, TiKV,
populated-store migration and unrestricted million-record engine capacity. A
large standalone index experiment is allowed only with an explicit distinction
from the application's accepted limits. The explanation-course checkpoints are
also deferred; concise executable examples and API reference remain required.

## Checkpoint graph and current status

P0 is this documentation delivery. **Twelve implementation checkpoints remain:**
N0–N6, S0–S3 and F0. All were pending at P0; the preparation ledger below tracks
subsequent acceptance. A completed planning packet
does not count as executed acceptance for any of them.

```text
N0 → N1 → N2 → N3 → N4 → N5 → N6 → F0
     N1 → S0 → S1 → S2 → S3 → F0
                         N5 → S3
```

The arrows show acceptance dependencies, not a prohibition on independent
research or drafting. S0 execution follows N1's common configuration/capability
contract so measurements have stable identities. N3 and N4 owners can develop
disjoint modules in parallel after N2, but N4 acceptance includes N3 reuse.
N5 acceptance includes N4's independent checks. S3 uses N5 release functions as
well as S2's engine result. F0 accepts one integrated source/artifact identity.

| Gate | Exact deliverable | Required acceptance and stop point |
| --- | --- | --- |
| N0 | Confirmed capability/deletion ledger and Node dependency decision | Every active Python tool, helper, test and executable research experiment has a replacement, merge or documented retirement. Select supported Node baseline from upstream support status, a lockfile and schema dialect; do not infer stable/LTS from the highest version string. Freeze N1 wire/ownership fixtures. Stop at a reviewable contract and focused feasibility witness. |
| N1 | Shared resolved configuration, capabilities and structured native host boundary | **Accepted:** [N1 result](63-node-native-host-result.md) and [evidence](evidence/2026-10-25-n1-native-host.json). Native process dispatch takes objects; one authority for schemas and hard limits; explicit precedence and secret handling; unknown settings fail. Bounded framing, clean shutdown, invalid config with no side effects, wrong-target fences, exclusive redb ownership and private/public separation pass within the result's stated boundaries. |
| N2 | Node session/client, model and operator composition | **Accepted within bounded scope:** [N2 result](65-node-workflow-result.md) and [evidence](evidence/2026-10-25-n2-node-workflow.json). Ordinary Node ESM composition, scoped service/identity and lifecycle controls pass; supported adapters and execution limits are recorded there. |
| N3 | Node population and scenario functions | **Accepted within bounded scope:** [N3 result](67-node-population-result.md) and [evidence](evidence/2026-10-25-n3-population.json). Four ordinary functions compose bounded proposals with explicit typed pools, callbacks, saved plans and receipt-gated advancement. Real Equipment and Quantity trajectories and the O(pool-size) custom-selector boundary are recorded; no global-validity claim is made. |
| N4 | Node experiments, observation and independent verification | **Accepted within bounded scope:** [N4 result](69-node-experiment-result.md) and [evidence](evidence/2026-10-26-n4-node-experiments.json). The 95-test N0–N4 suite and focused independent review pass. Ordinary workloads, bounded observation, source-only Equipment/Quantity/Measurement checks, and real Equipment/Quantity receipt-progress trials are recorded. Measurement query results/selected identities, equal-time mixed-sign Equipment prefix extrema, and physical tree structure remain explicitly incomplete. N5 typed-backup checking and N6 physical snapshots/deletion remain owed. |
| N5 | Node storage/service/release lifecycle | **Accepted within bounded scope:** [result](71-node-lifecycle-result.md) and [release evidence](evidence/2026-10-26-n5-release.json). Committed-source packages, 122 extracted Node controls, six-model physical checks and redb/SurrealKV/local FoundationDB lifecycle pass. Current bootstrap remains the private host; removal of the older service parser and the standalone structured service bootstrap belong to N6. |
| N6 | Python and redundant CLI removal | **Accepted within bounded scope:** [result](78-node-retirement-result.md) and [release evidence](evidence/2026-10-26-n6-release.json). The 60 inventoried Python paths and four bridge auxiliaries are retired; final committed-source packages and extracted Node/native workflows pass. Source, model, adapter, lifecycle, and capacity boundaries are recorded in the result. This does not complete G10. |
| S0 | FoundationDB and embedded access baseline | First freeze the trace/workload schema and measurement plan for logical/physical loads, wait dependencies, bytes, cache hits, scans, writes, conflicts and resource use. Record data shape, host/cluster/process topology, and cold/warm controls; then execute the baseline on supported adapters without changing semantics. Reuse existing correctness witnesses. Local multiple processes are not a multi-host network benchmark. |
| S1 | Bounded alternatives trial and selected layout decision | Do not choose a candidate before the S0 workload and measurement limits are recorded. Compare the baseline with small transaction-local batching/cache changes and a justified paged/stable-partition candidate. Validate correctness independently before timing. Define thresholds before candidate results. Account for rewrite bytes, conflicts, structural metadata and rank/select costs. Select the smallest maintainable design meeting the evidence; retaining AVL is a valid measured decision. |
| S2 | Selected ordered-access implementation | Implement only the S1 decision, adapt independent structural checking and retain atomic mutations/receipts/authority. If encoding or meaning changes, bump identities and reject incompatible stores; do not silently migrate. Physical page changes must not become false business dependencies. Record algorithms, bounds and changed public/private capabilities. |
| S3 | Cross-adapter and latency acceptance | Verify the selected implementation on redb, standalone SurrealKV and FoundationDB; compare complete logical outcomes, rollback, query/replay and lifecycle. Run affected N5 extracted checks. Record real multi-host results if infrastructure exists; otherwise mark that claim incomplete and record its exact required run. No synthetic delay result may be promoted to distributed capacity. |
| F0 | Integrated developer experience, deletion and source/artifact handoff | From a clean source export, import the Node entry point in a standard REPL/script and complete model → owned service → fixture/population → mutation/query → inspection → experiment → check → backup/recovery → package workflow. Verify source/artifact/format identities and no Python/custom CLI dependency. Publish supported/deferred/blocked claims, hashes, results, cleanup and a next-action handoff. |

Each row can be split into small commits without inventing additional completion
claims. Do not mark a gate accepted on implementation alone; include the specified
counterexamples and evidence. Do not repeatedly ask the user to say "continue"
between authorized implementation gates. Stop only for a material unavailable
prerequisite, an unresolved correctness contract, or the user's stop instruction.

## N0 output required before parallel implementation

N0 must produce a compact decision record, not another open-ended planning phase:

- Baseline hashes and actual currently runnable artifacts; identify missing
  historical raw data explicitly rather than regenerating old evidence silently.
- A ledger mapping every file in [the inventory](59-node-capability-inventory.md)
  to an owned capability and a deletion/replacement checkpoint.
- Proposed exports frozen for N1/N2 with examples accepted by syntax/type checks;
  names can change before implementation, but only one naming scheme survives.
- The private native protocol: model/store selection, framing, versioning,
  request/result/error shapes, maximum sizes, capability scope and resource
  ownership. Select an extension of existing Rust functions/dispatch; do not
  wrap all historical CLI verbs or add another calculation engine.
- Library and Node support decisions: validator dialect/custom annotations,
  faker behavior, duplicate-key JSON policy, exact arithmetic, seed semantics,
  abort/resource limits and installation outside the checkout. Tests must cover
  semantic differences between Python and Node, not just matching happy outputs.
- A configuration registry listing each setting's owner, default, unit, allowed
  range, override policy, secret treatment and source of authoritative limits.

Do not build a whole generic config framework. A few schema-checked objects and
explicit resolver functions are sufficient. Reuse native public/developer model
metadata; new operator config metadata should originate beside its Rust types.

## Configuration and resource invariants

There are three distinct kinds of limits. The resolved context must explain all
three without duplicating policy across every script:

1. **Native/storage capabilities:** encoding widths, model inventory ceilings,
   FoundationDB key/value/transaction/snapshot restrictions. These are not lifted
   by setting an environment variable.
2. **Operator policy:** admission, work/query budgets, timeouts, package and
   backup bounds within supported capabilities. Native code validates enforcement.
3. **Experiment choices:** rates, concurrency, duration, seed, population shape,
   sampling and artifact retention. Preflight verifies their combined feasibility.

Ordinary modules do not read environment variables during import. A caller may
pass an allowlisted environment snapshot to the resolver. Precedence is explicit
options over explicit environment over documented defaults. Omitted is different
from null/zero/false; reject unknown fields and incompatible backend settings.
Expose effective values and provenance with secrets redacted. Do not persist
tokens or private keys in shared reports, fingerprints or default REPL inspection.

Distinguish environment needed by native libraries/toolchains from application
configuration. Dynamic library search, Cargo cache/feature inputs and the FDB
cluster file remain explicit host prerequisites. No fabricated portable Node
memory/RSS guarantee replaces POSIX resource limits from the previous provider.
If the replacement has different containment, document and verify that exact
boundary. Node-to-Node bounded workers are acceptable when justified; a permanent
Python launcher is not.

## Required semantic preservation

Breaking interfaces does not permit weakening the following obligations:

- One transaction publishes input, exact calculations, indexes, authority-related
  repair, operation receipt and applicable effect intent together.
- Parent/reference validity, tenant separation, public/private distinction and
  final-graph causality remain authoritative in Rust. Zero contributions still
  carry dependencies; empty/absent is never invented as a successful zero.
- Saved intents retain their operation ID, original context, target and content.
  Timeout, cancellation and missing observations do not imply rollback. No
  automatic replacement intent, silent archive or expired-context refresh.
- Opaque record tokens, root tokens, cursor digests, graph revisions and effect
  fences keep their distinct meanings. Never manufacture them from a local clock.
- One owner for an embedded store; local operator methods do not bypass live
  server ownership. Restores are create-only and independently verified. Reset
  and archive explicitly fence identity/receipt generations as currently defined.
- Provider facts, quarantine/reconciliation, lease fences and captured authority
  retain their meaning. A Node fake provider is evidence, not a live integration.
- Histories, inclusive/exclusive bounds, equal-time groups, multiple slots and
  non-invertible summaries remain correct through any index transformation.

## Delegation and economical execution

The 2026-10-26 user instruction supersedes the earlier model mix. Use the
selected [agent execution mode](../docs/agents/README.md), the current model
and one agent. Batch independent tool operations; do not launch subagents to
optimize usage. The delegation rules below apply only if later requested.

Every delegated task must name: allowed files, starting source identity, required
reads, inputs/outputs, forbidden shortcuts, acceptance cases, evidence destination,
and handoff fields. Root owns Git/pushes; workers never reset/stash/rebase shared
state. Source mutations and verification on shared fixtures require an execution
lease. Use distinct disposable namespaces and directories, explicit process PIDs
and `finally` cleanup. Do not kill processes owned by another task.

Parallel lanes after contract freeze: client/config, population, independent
oracles and experiment/reporting can have disjoint owners. Native protocol and
storage changes share a coordinated Rust owner. Only one Cargo owner runs builds,
with two jobs and incremental off in this cloud environment. Reuse unchanged
native artifacts when hashes match; Node-only changes do not require repeated
full native builds. Serialise host benchmarks to avoid contaminating timings.

Prefer a small informative counterexample or affected test set over repeating
complete accepted campaigns. Retain source fingerprints and failed-trial context.
A Node port needs fresh acceptance for changed tools; copying Python's pass flag
or calling Python from Node is not acceptance. Final release verification is
performed on the actual exported artifact rather than the source workspace.

## Evidence, integration and handoff contract

For each accepted checkpoint, retain source identity, environment/tool versions,
commands or function calls actually executed, test counts/results, output hashes,
resource observations, failed trials, unresolved boundaries and cleanup state.
Record `passed`, `failed`, `incomplete` and `unsupported` distinctly. Do not
write an empty success report when optional infrastructure was absent.

Commit a checkpoint on existing main after focused verification, with a message
stating capability and boundary. Fetch before pushing; preserve unexpected remote
commits through linear integration. Use ordinary pushes. The old replacement of
partial tip `1fe6310` is historical and must never be repeated by this program.
Update the top of CONTEXT and the ledger after each checkpoint. A handoff names
one exact next action, file owners, live processes, reusable artifacts and blockers.

The final node-only developer guide must be demonstrable with ordinary imports,
values and `await` in Node. Keep explanatory comments near examples. The public
surface should add a function only where it owns a reusable obligation: protocol
identity, transactional lifecycle, constrained generation, bounded execution,
independent checking or verified packaging. Native filesystem operations and
simple object manipulation remain ordinary JavaScript.

## Preparation ledger

| Checkpoint | Status at this delivery |
| --- | --- |
| P0 — current program, three companion contracts and navigation | Prepared; [documentation verification](evidence/2026-10-25-g10-preparation.json) records checks and fingerprints, not runtime acceptance |
| N0 | Accepted: [contracts and dependency feasibility](62-node-foundation-result.md); no native host/API implementation claimed |
| N1 | Accepted: [Node/native host result](63-node-native-host-result.md) and [evidence](evidence/2026-10-25-n1-native-host.json) |
| N2 | Accepted: [Node workflow result](65-node-workflow-result.md) and [evidence](evidence/2026-10-25-n2-node-workflow.json) |
| N3 | Accepted: [Node population result](67-node-population-result.md) and [evidence](evidence/2026-10-25-n3-population.json) |
| N4 | Accepted within bounded scope: [result](69-node-experiment-result.md) and [evidence](evidence/2026-10-26-n4-node-experiments.json) |
| N5 | Accepted within bounded scope: [result](71-node-lifecycle-result.md) and [committed-source release evidence](evidence/2026-10-26-n5-release.json) |
| N6 | Accepted within bounded scope: [result](78-node-retirement-result.md) and [release evidence](evidence/2026-10-26-n6-release.json) |
| S0.0 | Checked preparation: [frozen bounded contract](79-s0-baseline-contract.md) |
| S0.1 | Accepted within scope: [instrumentation result](80-s0-instrumentation-result.md) and [evidence](evidence/2026-10-27-s0-instrumentation.json) |
| S0.2, S1–S3 | Pending; no layout selection or performance claim |
| F0 | Pending |

To continue: read AGENTS, the top of CONTEXT, and the
[S0.1 result](80-s0-instrumentation-result.md). S0.2 needs a committed-source
optimized pilot and an explicitly bounded campaign before evaluating any S1
candidate. The focused report-size projection exceeds 64 MiB at 30 repetitions per action;
freeze any fragmentation revision and exact coverage checks before the campaign.
Keep the bounded claims and dependencies above; do not restart G7–G9 or begin G6.
