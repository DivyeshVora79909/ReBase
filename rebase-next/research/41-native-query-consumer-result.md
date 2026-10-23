# G4d-b: typed native queries and observation reports

**Accepted in source 0.13.0, 2026-10-23, after published G5c `b65be31`.**
The [dated evidence](evidence/2026-10-23-g4db-native-query-consumers.json) records
the native/HTTP controls, retained executable, source hashes and compatibility.
The [owning gate](40-native-query-consumers.md) fixes report semantics and the
separate authored-selection follow-up. Earlier accepted checkpoints remain dated.

## Implemented behavior

`NativeIndex::QueryResult` gives each compiled family its own formula value.
`Query<Index>`, storage validation, native inventories and the common causal
scheduler all use that type. Standard retains `i128` and its canonical decimal
wire. Statistics supplies its strict native Summary; JSON projections remain
at the public boundary. Family functions validate query operation, phase,
channel and result, without a global statistics variant or second reactive loop.

The financial fast prefix remains explicit, as do nonnegative terminal validation
and managed financial output construction. Measurement reads only staged authored
observations. The port does not establish readiness for managed statistics,
arbitrary predicates or selected-parent publication chains.

ObservationReport (contract 307) declares Instrument, exact TimeRange, unit and
integer threshold. Query slot 31 reads native statistics from Instrument root 7.
It publishes count, optional extrema, unit and whether a nonempty window's minimum
meets the threshold. Empty means count zero, absent extrema and false. A direct
Instrument-unit registration survives emptiness and equal results, as does the
query's entire declared dependency window. Changes use distinct old/new times and
original/staged routes; final membership and unit checks precede evaluation.

Reports own no root, membership, role or private output. Parent deletion rejects
surviving references. Reader inheritance and the existing explicit Read policy
apply to the materialized report. The bound remains 64 total public sources and
200,000 work units per mutation. [The guide](../docs/native-indexes.md) includes
the fixture, authored/derived wire and developer workflow.

## Native acceptance

All 38 selected Rust controls pass. Five report controls take 4.37 seconds; their
corruption control checks sixteen distinct mutations through complete check,
server startup, CLI check and verified restore. These include wrong result/binding,
stale result/derived values, exact bounds, misbound direct/subscriber routes and
missing query/direct/subscriber rows. Failed restore publishes no destination;
checks leave existing table bytes unchanged.

Reports cover nine window shapes, threshold equality, negative values, empty and
all-deleted windows, equal-result rekeys, root moves, first insertion, both command
orders of unit/retarget repairs and full-table rollback after staged member edits.
A measured finite-budget attempt fails after staging with no table or receipt
publication. A successful report never allocates a private identity.

Twenty-nine affected shared controls pass in 8.95 seconds: financial windows,
terminal repair, authored parameters, published-value diamonds/cycles, native
inventories and scalar query wire. Four existing measurement controls pass in
1.10 seconds, preserving its 64-source envelope and full-population replacement
in either command order. The unchanged algebra enumeration was not rerun.
The independent Python integer oracle passes twelve literal controls.

The first all-target Clippy check passes in 24.698 seconds. One native build
takes 122.004 seconds. Each Cargo invocation uses two jobs, incremental off,
Rust 1.95.0 and the retained profile cache; successful tests are not repeated.

## HTTP, compatibility and retained evidence

The single optimized build took 296.743 seconds. Its HTTP workflow passed twenty
mutations /36 commands: sixteen commits and four complete-table rollbacks, in
2.143 seconds. The workflow compares every public result against an independent
integer source oracle. Zero, one and eight selected reports produce exactly zero,
one and eight causal evaluations. It also exercises retargeting, first insertion,
all-members-deleted identity, equal-result version preservation, both unit-repair
orders, authority, replay, reopen, one real process kill and verified restore.
The final thirteen public sources have eight queries and no private outputs.

Source 0.13.0 retains store 9 /native codec 6 /effect codec 3 /API 3. Measurement
behavior is `dimensioned-measurements-2`, model
`75c4b8643230b0a69dd6fe443d374e4e05d9c7387ab50cd7950b020b6549a418`.
Calculation, equipment, invoicing and effect-demo identities match G5c. Populated
old stores pass complete source checks, including eighteen financial queries and
retained signed inbox data, with identical full application-table payloads.
A populated old measurement store rejects with identical physical SHA-256.

The first compatibility script incorrectly required physical equality after a
successful compatible redb open. Such an open can change maintenance bytes;
the corrected control compares every application table instead, while retaining
physical equality for the rejected incompatible open. The initial observation
is retained in the evidence. It required no source fix, rebuild or native rerun.

The retained binary is `target/g4db-accepted/rebase-next`, 28,634,848 bytes,
SHA-256 `535a2cb4a0984fbbedd9fa302b96eaa64ed9bd4fdd5157e1fa1ee6bd26b3da48`.
Reports: `target/g4db-checks.json`, `target/g4db-compatibility.json` and
`target/g4db-reports-http/result.json`. Seventy-six source/test/tool files have
independent hashes. Earlier binaries and accepted campaigns remain preserved.

Continue G4d-c from the owning paper's greatest-complete-key authored selection
and complete `(-infinity, at]` dependency, including absence. Keep Standard's
quote lookup distinct from typed authored-observation selection. Reuse this
query port and the existing tree's ordered predecessor traversal.
G4d-c and G6–G8 remain open; the last deployment bundle remains 0.6.0.
