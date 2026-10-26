# N6 — Node tooling retirement checkpoint

Status: **final N6 implementation verified locally; release acceptance pending.** The working
tree now includes structured native `host` / `serve` bootstrap and retirement of
the 60 Python paths inventoried at N0 plus four obsolete schema-values bridge
files. This is prepared implementation, not N6 acceptance. The retirement ledger
records each exact retired path, its pinned source SHA-256, concrete current
Node/native controls or dated historical basis, and an explicit claim boundary.
The bootstrap behavior and acceptance matrix
are specified in the [N6 native bootstrap contract](76-native-bootstrap-contract.md).

The [bootstrap evidence](evidence/2026-10-26-n6-bootstrap.json) records the
independent 64-file Git hash check, all 297 current-control references, preserved
historical evidence, native checks and 141 passing Node tests. Final package
contents and extracted workflows remain an acceptance gate.

The baseline is pinned at [`0d0601187c79d430f8d7ed41674f53e9905af75f`](https://github.com/DivyeshVora79909/ReBase/tree/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next),
resolved from the requested short revision `0d06011`. The original N0 ledger
and all dated `research/evidence/*.json` remain unchanged. Each retired historical
Markdown hyperlink that directly targeted a removed path now points to that
path's immutable GitHub blob at the pinned commit.

The current replacement controls include Node client saved-plan and unknown
outcome tests; N3 population receipts; N4 source oracles, bounded workload and
observation checks; N5 lifecycle, FDB ownership and extracted release checks;
and accepted N6 signed ingress, private effect retry, complete backup and
IssueShare controls. Invoice and share behavior remains the bounded accepted
Node/native contract; the old Fraction campaign is retired without adding a
second arithmetic engine.

Historical G7/G8/G9 campaign records and experiment sources remain available as
dated evidence and pinned Git objects. The retained native corpus supplies
concrete controls alongside the named Node subsets: `tests/exact_values.rs` and
`examples/exact_values.rs` cover exact rational behavior; `tests/invoicing.rs`,
`src/parameter_tests.rs`, and `src/publication_tests.rs` cover current compiled
Calculation behavior; `tests/native_tree.rs` and `examples/native_slice.rs`
cover native tree/raw-KV obligations; and `src/window_tests.rs` with
`tests/measurement.rs` cover compiled windows. Retiring the Python M3/M5, M6,
native-slice, and reactive-window implementations records historical
implementation retirement, not full Node parity. The current Node typed-tree
checker does not replace the old full non-tree KV, report, or matrix engines.
Native Equipment, Measurement, integrity, and access tests preserve named
population/access controls; historical capacity and measurement evidence is
not rerun or widened into a new general capacity claim.

The four bridge auxiliaries removed are `tools/requirements-population.txt`
and `tools/schema-values/{generate.mjs,package.json,package-lock.json}`. The
scoped `tools/node/` package owns the current Node dependency boundary.

See [`n6-retirement-ledger.json`](fixtures/n6-retirement-ledger.json) for all
60 Python rows and the four auxiliary paths.

Root's exact pending acceptance is to verify all 60 unique paths and four
auxiliary paths against the pinned source and recorded SHA-256 values; verify
replacement references, historical links, package contents and service
templates; then run the native host/service checks in the
[bootstrap contract](76-native-bootstrap-contract.md) and the final Node suite
and package checks from a clean source export and extracted release. Demonstrate
the ordinary Node workflow and minimal native bootstrap without Python or the
retired project CLI parsers. Record hashes, outcomes, cleanup and bounded claim
limits as new evidence. Keep N6 pending until root accepts that evidence. These
controls remain bounded and make no unrestricted-capacity claim.
