# Review of the parallel 0.2 release

Reviewed remote commits `242a08b` and `1f16278` on 2026-10-22 against their shared
D4 base `4cf5e7e` and the local alternative work. Adopted the remote D5/D6 release
on the existing `main`, preserving its stateless client, durable explicit plans,
UUIDv5 fixture namespaces and deployment/workload harness. The alternative local
fixture/deployment implementations were set aside, avoiding duplicate APIs and
an unnecessary ownership/model-contract change. Local recovery state was saved
before replacing that work; it is not part of the adopted release.

## Verified claims

All 48 source fingerprints in the peer's D6 evidence match its committed files.
A fresh source archive passes all 39 optimized Rust tests, all six Python client
controls and the full default public-process harness: 128 atomic moves, 1024
concurrent reads, duplicate/CAS races, revision 133, crash/reopen, receipt replay
and restored-service checks. These are newly executed results, rather than only
inspection of the other agent's report. The independently checked native history
corpora at D4 remain applicable: the peer changed tools and release metadata,
not calculation/binding/storage/authority semantics.

## Confirmed inherited defect and correction

The earlier current-state integrity checker expected a quote node at `(quote,1)`.
The engine and declared model correctly store it at `(quote,3)` in curve root
`(curve,1)`. Member slots and root slots are different identities. A minimal
public create of one curve and one valid quote commits, but `check` then fails
with `corrupt_state: extra node`; HTTP startup and verified restore also reject
that otherwise valid store. The peer's causal-only fixture did not exercise it.

Corrected the checker expectation to slot 3. The regression combines the peer's
causal fixture with dated FX postings, covering all ten public contracts and
27 total records including five managed outputs. Literal native/reporting totals
are 16/54. Editing the early rate yields 74 reporting units while the later-rate
posting version remains unchanged. Complete integrity, byte-equal backup/restore
and network router startup now accept that mixed state.

The focused fix changes no authored data, native binding, calculation, persisted
layout or engine invariant. The D4 model/store/behavior identities remain intact.
The correction and regression bring the integrated suite to **40 Rust tests**;
the peer's original evidence stays dated. Current verification and hashes are in
[review evidence](evidence/2026-10-22-peer-release-review.json).

## Scope still matters

The release is a deployable bounded embedded service with a compiled model and
a 64-source cap. The fixture tool remaps one authored bundled recipe; it is not
an arbitrary model/constraint generator or automatic dependency-order planner.
Other ordered command drafts can be composed explicitly through the ordinary
client. Full ReBase capability, general model authoring, larger whole-backend
workloads and accounting/distributed/effect gates remain future work as listed
in [the release result](18-release-result.md). Public deployment/TLS provisioning
and the other agent's original packaged binary were not available for direct
verification here; source builds and the actual local HTTP process were tested.
