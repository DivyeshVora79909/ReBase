# G4d-c: latest authored observation

**Accepted in source 0.14.0, 2026-10-23, after published G4d-b `3a51948`.**
The [dated evidence](evidence/2026-10-23-g4dc-authored-selection.json) records
source hashes, checks, the retained executable and compatibility. The
[owning contract](40-native-query-consumers.md) fixes the candidate universe and
dependency domain. G4 and G5 are now accepted within their declared bounds.
The user requested stopping here; G6, G7 and G8 remain deferred.

## Implemented behavior

LatestObservation (contract 419) declares Instrument, exact `at` and unit. Query
slot 43 reads Instrument root 7 through the common causal scheduler. Its optional
native result contains identity, member slot, time, unit and value. The greatest
complete `(time, UUID, member slot)` at or before `at` wins. Equal payloads with
different identities remain different results. Absence is explicit `null`.

The dependency is the entire `(-infinity, at]` window, even when absent. First
insertion, nonwinner edits, winner replacement/deletion, rekeys and root moves
use the existing original/final invalidation paths. Nonwinner edits can evaluate
without changing the materialized record version. Direct Instrument-unit
dependencies survive empty results; joint retarget/unit repairs use final state.
There are no selector roots, memberships, private outputs or reservations.

`Selected<Index>` is an attempt-local native occurrence. The shared tree extracts
its existing ordered predecessor traversal as `last_at_or_before`; quote reads
retain their explicit capability check. A family hook projects an occurrence
into its typed query result. Native query support is checked separately from
public root-read names, so statistics does not advertise a quote read.

Measurement uses closed, disjoint summary and optional-selection variants.
Report summary/derived bytes remain unchanged. The complete checker independently
reconstructs winners by a plain maximum over authored memberships and compares
query, direct and subscriber inventories. Authored Observations are the entire
candidate universe. Managed candidates, selected-parent published values and
winner-dependent topology are not established by this gate.

## Acceptance and resource use

Twenty-six selected Rust controls pass: thirteen measurement/report/selection
controls, twelve affected shared controls and one quote predecessor control.
These include exact i64 extremes, complete member-slot ties, both command orders
of retarget/unit repair, finite work exhaustion and full-table rollback.

The corruption control has 27 cases across complete check, server startup, CLI
check and verified restore. Semantic selection mutations use typed native
encoding and pass local decoding before rejection, including false absence with
an existing candidate, wrong identity/time/slot/value, bounds and derived values.
Invalid variants/bindings and missing queries/routes also reject. Failed restores
publish no destination, and rejected checks preserve the application tables.

Seven literal Python selection controls and the twelve existing report oracle
controls pass. One optimized HTTP workflow executes 22 mutations /49 commands:
18 commits and four complete-table rollbacks in 2.260 seconds. It compares all
records and roots against authored facts, measures zero/one/eight evaluations,
and confirms both affected roots evaluate on a move. Materialized Read policy,
denied new references/retargets, replay redaction, reopening, one process kill
and verified restore pass. Final state retains one report, one present selector
and one absent selector: eight public sources, three queries and no outputs.

One Cargo owner used two jobs, incremental off and the retained profile caches.
All-target Clippy took 19.668 seconds; the focused check after improving corruption
controls took 1.231 seconds. One native compilation took 98.441 seconds; native
checks took 11.345 seconds. One optimized build took 289.328 seconds. No source
failure or repeated build occurred. The unchanged algebra enumeration, full
optimized suite and 4,096-source campaigns were not repeated.

## Compatibility and stopping point

Source 0.14.0 retains store 9 /native codec 6 /effect codec 3 /API 3. Measurement
behavior is `dimensioned-measurements-3`, model
`32d95742102bfcb62fff89e0871f90a2c08cc97cf344c7665a2704cb9569871b`.
Calculation, equipment, invoicing and effect-demo retain their 0.13 identities.
All four populated stores pass complete checks with identical application-table
payloads, including eighteen financial queries and retained signed inbox data.
A populated 0.13 report store rejects with identical physical bytes.

One compatibility batch recreates the thirteen prior report sources through the
new public API. All eight complete native query encodings and eight derived
report encodings are byte-identical to the retained 0.13 backup. This is a
separate compatibility control, not another report acceptance campaign.

Retained executable: `target/g4dc-accepted/rebase-next`, 28,765,840 bytes,
SHA-256 `46e6e52125cb263dda8a89858a1117f42a5ef963300f0ff71eb4292907485338`.
Reports: `target/g4dc-checks.json`, `target/g4dc-compatibility.json`,
`target/g4dc-selection-http/result.json`. Seventy-seven source/test/tool files
have independent hashes. Earlier accepted executables and evidence are retained.

Measurement remains bounded to 64 public sources and 200,000 mutation work
units. G5 acceptance remains for the fixed fake provider. The last verified
deployment bundle remains 0.6.0. Stop the broader capability goal after this
checkpoint's publication; G6–G8 require a new user instruction.
