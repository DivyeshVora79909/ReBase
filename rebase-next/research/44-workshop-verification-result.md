# V1 workshop verification result

**Accepted 2026-10-23, source 0.15.0: V1.1–V1.5 complete.**
The [prepared plan](43-example-verification-suite.md) is now implemented through
ordinary production paths. [Dated evidence](evidence/2026-10-23-v1-workshop.json)
records exact names, fingerprints, reports, limits and corrections. The
[workshop guide](../docs/workshop.md) is the developer entry point.

## What runs

Four self-explaining chapters use separate disposable stores: equipment
allocation/history, sensor windows/latest selection, a tiny exact quantity
chain/diamond, and service quota with the existing fixed fake provider. They
share the engine and ordinary client. They do not share records or transactions.
Every authored step saves its command, independent expectation, observed public
values, private inspection/check and measured work. Counters are totals, not a
claim to observe intermediate execution order.

`walk` checks and explains those chapters. `check` adds fingerprint-bound native
harnesses and actual HTTP/worker/ingress recovery controls. `explore` runs a
bounded seeded Quantity profile; `replay` recreates its logical actions with new
contexts, then preserves each new run's exact repeated intent. Missing, stale,
zero-test or ignored native evidence remains incomplete; failed evidence fails.
The tools use ordinary functions, the Python standard library and existing
Backend/client/oracles. No new dependency, solver, parser or engine was added.

## Native addition and repaired partial work

Quantity has Source 101, Scale 205 and Join 309, at most 16 public records and
absolute publications at most 10^18. It has no private outputs or query/root
workaround. A declared publication target now participates in shared settlement
even if it is a terminal authored value. Parents declaring non-causal queries
still reject. This fixes the partial model's preparation failure and schedules
Source before dependent consumers. The five previous public catalogs and model
identities compare equal. Store 9/native codec 6/effect codec 3/API 3 are unchanged.
Only the new model needs behavior identity `quantity-flow-1`.

The unverified partial `924ace0` was replaced, as requested. `cba8e0a` contains
the native fix and model; `6e323c1` contains V1 tools and executable checks.
Historical evidence and original ReBase remain untouched.

## Executed acceptance

- Four chapters: **42 teaching steps**, including 40 explicit mutations
  (36 commits/four complete application-table rollback rejections) and two
  independently journal-observed service stories.
- **147 Rust tests across 15 harnesses**, zero failures/ignored tests. Each
  artifact is bound to source/model-schema hashes; exact test names are recorded.
- Six concrete actions through depth three: **258 transitions/259 prefixes**
  including empty, 129 accepted and 129 rejected. A real Store restores authored
  state between branches; receipt history and record versions keep advancing.
- **32 seeded actions**: 16 accepted mutations, 12 expected rejections and four
  exact same-target replays. Fresh logical replay also passes all 32 actions.
- **16 worker + eight signed-ingress/recovery cases**, including real kill
  barriers, lost responses, blocked application repair, stale fencing, independent
  provider acceptance and pre-acceptance-backup restore quarantine.
- **20 Python controls** cover oracle literals, wrong/missing/extra observations,
  incomplete/stale/failed evidence, setup cleanup, failure-class preservation and
  model-bound replay. Formatting and all-target Clippy pass.
- A deliberate **test-only wrong observation**, against the real correct HTTP
  engine, is detected, reduced from nine actions to one and reproduced in a
  fresh store. The named probe retains original/minimized artifacts and plans;
  it is not an engine failure.

## Current capability map

A harness runs once and can support several rows. Counts above sum distinct
harnesses, not repeated map references. Exact cases and fingerprints are in the
evidence; private run directories retain plans, logs and raw observations.

| Obligation | Status | Current evidence |
| --- | --- | --- |
| V-C01 | passed-current | exact_values, model_contract, quantity, lib |
| V-C02 | passed-current | equipment, measurement, quantity |
| V-C03 | passed-current | native_tree, lib |
| V-C04 | passed-current | lib |
| V-C05 | passed-current | equipment, lib |
| V-C06 | passed-current | lib, routes |
| V-C07 | passed-current | quantity, workshop_exhaustive, lib |
| V-C08 | passed-current | equipment, measurement, lib |
| V-C09 | passed-current | measurement |
| V-C10 | passed-current | measurement, lib |
| V-C11 | passed-current | access_control, equipment_http, network_api |
| V-C12 | passed-current | local_api, semantics |
| V-C13 | passed-current | local_api, network_api, storage_lifecycle + worker/ingress |
| V-C14 | passed-current | lib, storage_lifecycle + worker/ingress |
| V-C15 | passed-current | lib, storage_lifecycle, native_tree |

## Cost and limits

Independent oracles deliberately scan small authored lists/graphs using plain
integer/rational arithmetic. Production updates use the existing linked indexes
and affected-dependency scheduler; work grows with affected records, memberships,
paths and scope discovery, not a universal constant or single logarithm.
Finite sequence count grows exponentially with depth, which is why the profile
is explicitly six actions/depth three. Seeded exploration covers only Quantity;
the other chapters have literal and native/process controls, not a claim of
randomly exploring every supported feature combination.

Shrinking currently deletes action spans under a replay budget. Scalar, graph,
and distributed fault-schedule minimization are not established. An unreproduced
failure stays failed with its original trace. Final parser-only changes reparse
retained logs and pass focused controls; they do not rerun successful native or
provider checks. Evidence distinguishes earlier failures and accepted counts.
One build owner used two jobs and disabled incremental compilation. The initial
optimized partial build was rebuilt after the compiler/scheduler fix; accepted
native tests used the same cache. This is verification, not a throughput or
million-record scalability campaign.

## Continuation

The assigned V1 goal is complete. **G6 accounting, G7 distributed storage,
G8 workload/release expansion and frontend remain deferred.** Existing bounded
invoicing stays available; no broader accounting port was started. Live adapters,
managed statistical outputs, selected-parent publication chains, arbitrary
queries and unbounded retention are not certified here. The last packaged
release remains 0.6.0; source 0.15 is not a newly accepted release bundle.
Do not automatically begin another gate.
