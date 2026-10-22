# Usable local prototype result

**P1–P4 complete, 2026-10-22.** This fulfills the user's confirmed finish line:
a runnable local calculation engine, model/developer tooling, mutation/query API
and demonstrable workflow with independent checks. The
[run/API guide](../docs/local-prototype.md) is the operational entrypoint.
[Final evidence](evidence/2026-10-22-local-prototype.json) owns fingerprints,
commands, artifacts and verification scope. This is a local prototype, not
production acceptance of the broader redesign.

## What is built

| Stage | Implemented boundary |
| --- | --- |
| P1 | Native authored-shape causal closure, strict-prefix readers, required private outputs, final dependency ordering, zero feedback rejection, lifecycle/identity reservations and complete-time history rules. The earlier [P1 result](15-causal-native-result.md) remains dated. |
| P2 | Twelve authored input schemas and explicit trusted declarations; prepared validators and dependency order; reference/root/member/query/publication checks; separate public and full developer catalogs; explain/validate and an offline model view. |
| P3 | Reusable redb adapter, fixed local actor/tenant, exact create/update/delete/get, public identity index, durable operation receipts, authenticated revision-bound cursors, bounded page/exists and declared root reads. Strict JSON-RPC runs over local stdin/stdout. |
| P4 | `demo <new-directory>` uses the public operations to build and edit a causal diamond, demonstrate rejection/replay and reopen. It retains a usable store, catalogs, transcript and self-contained HTML inspector. The actual binary also passes a process/restart client check. |

Ordinary Rust modules own the boundaries: `model`, `local`, `query`, `rpc`,
`demo` and `inspector`, alongside the accepted native arithmetic/workspace/tree
modules. There is no second query language, plugin registry, frontend server or
legacy compatibility layer. The parent repository's broad `bin/` ignore rule is
overridden locally so `src/bin/rebase-next.rs` is included in a fresh checkout.

## Executed acceptance

| Check | Result |
| --- | --- |
| Original native corpus on final sources | 68 cases / 93 operations; 53 commits, 40 unchanged rejections, 68 equal reopens |
| Native causal corpus on final sources | 39 cases / 55 operations; 38 commits, 17 unchanged rejections, 39 equal reopens |
| Real local adapter, independent four-table checker | 9 cases / 14 operations; 11 commits, 3 unchanged rejections, 9 equal reopens; every successful operation replays unchanged and rejects different content |
| Rust suite | 27 tests pass, including prepared-model/schema agreement, input framing, private-state protection, cursor scopes, bounded exhaustion, exact values, receipts and the process CLI |
| Physical adapter aborts | Aborts after partial engine/index writes and after receipt/header writes preserve all four application tables; old snapshots remain unchanged |
| Independent checker controls | Native: 32 invalid-state and two incomplete controls. Local adapter: six invalid-state and one incomplete control |
| Code checks | Locked build, formatting and Clippy with warnings denied pass |
| Usable demo | Fourteen public sources, five private outputs, two durable receipts; A/Left/Right/Final move from 30/60/90/150 to 20/40/60/100; reopening preserves state |
| Developer artifact | Generated inspector renders in headless Chromium; reviewed desktop screenshot retained with the local demo |
| Isolated Git snapshot | All 49 execution/packaging input hashes match a fresh Git tree archive; its locked binary build and demo/reopen pass with the same model identity |

The independent local checker uses the unchanged authored causal fixture and
explicit allocator inputs. It derives expected private IDs from allocation
history, not the observed role maps. Native verification independently checks
every record/query/reference/root/member and rescans every actual subtree.
The adapter checker additionally derives public index membership, canonical
request hashes and permitted settled receipt results. It observes all native,
public-index, operation and runtime-header rows. Unknown/missing inventory is
not silently accepted.

The CLI tests run the built executable from a separate temporary directory,
verify offline export creates no store, run the demo, refuse an existing output
directory, then edit/query over actual stdin/stdout and replay after process
restart. The retained demo is for use/review; the temporary acceptance stores
are removed. Raw observations contain privileged disposable test-state material
and stay ignored under `target/`, outside the public API and normal inspector.

## Deliberate limits

The prepared design is a bundled **compiled** model, not an arbitrary user model
loader. Schemas are self-contained Draft 2020-12; native bindings enforce exact
transport/range rules beyond JSON Schema. Model identity covers the resolved
declarations/schemas and a conservative source/dependency fingerprint of the
core. It covers behavior bodies rather than function names alone. Presentation
HTML/CSS and source-location labels do not determine that identity.

Local receipts retain up to 1024 operations without eviction. Record/role/work
limits remain explicit. The only public record-list order is ascending UUID;
there is one complete local reader path, with optional declared scalar equality.
Any new committed mutation invalidates cursors; receipt replay does not. Root
publications include declared private contributions without exposing private
occurrence identities. The fixed local context has no revocation/session API.

Production principal DAG/reader repair and authentication, distributed adapter
conformance, arbitrary ordered-result-driven shape, external effects/providers,
general decimal rounding, migration/restore, large export, a complete accounting
model and frontend port remain separate gates. No throughput/capacity claim,
destructive storage-fault campaign or distributed concurrency claim is made.
The original ReBase/MetaSol implementations and acceptance suites were untouched.

The confirmed prototype goal is complete. Future work starts from a new concrete
capability and its owning gate, without repeating the historical whole-system
audit or treating this local result as production authorization.
