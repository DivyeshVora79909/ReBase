# N5 — Node storage, lifecycle and release result (draft)

Status: **N5 implementation tested; release acceptance pending**. Prepared
2026-10-26. The Node 24.22.1 prebuild suite passed 122 tests, with no failures
or skips. Focused independent review and N5 module review passed; real backup
checks cover all six compiled models. Root's committed-source release build,
extracted verification, and released-artifact adapter runs remain pending.
The exact command and retained output are recorded in [N5 evidence](evidence/2026-10-26-n5-node-lifecycle.json) and its [prebuild log](evidence/2026-10-26-n5-node-prebuild.txt).

The local continuation built both locked release variants from `8a723b7` and
verified their extracted manifests, checksums and six-model catalogs. Running
the complete suite outside Git exposed a cloud-only npm cache path, a historical
binary hash embedded in the N4 controls, and process-start timing assumptions.
The corrected tests use owned temporary caches, the supplied or package-manifest
binary identity, and an observed configuration side effect before cancellation.
All 122 controls now pass with no skips against the new redb binary, using
`node --test --test-concurrency=1 test/*.test.mjs`; the raw output is retained in
[the portability run](evidence/2026-10-26-n5-portability.txt). This is test-source
verification, not acceptance of the corrected extracted release. Packaging that
committed correction and the released-artifact adapter runs remain owed. Native
sources and dependency locks did not change.

Root also completed a managed FoundationDB 7.3.77 ownership witness: it started
one local server, bootstrapped the cluster, passed a write/read/clear probe and
status command, then stopped the owned process. The retained result records PID
19102 and confirms it stopped. This validates local process ownership and a
single-process cluster probe; the status output reports other health metrics
as unavailable. It is not an application adapter, general readiness, or
multi-host acceptance run. See [the retained witness](evidence/2026-10-26-n5-fdb-owner-real.json).

N5 composes existing N2 ownership and lifecycle APIs and adds independent
physical-tree verification over a complete native backup, a durable local fake
provider fixture, managed test infrastructure, and release packaging and
verification functions. APIs include `checkBackupStructure`,
`startFakeProvider`, `openFdbEnvironment`, `prepareReleaseSource`,
`describeReleaseBuild`, `packageRelease`, and `verifyRelease`. The worker report
records 21 focused controls across structural corruption and six-model native
snapshots, fake-provider behavior (including held-request limits and
post-close rejection), managed FDB ownership (including spawn, concurrent
start, command-output/timeout and owned-stop controls), and effect-demo
recovery/lifecycle fences.

The backup checker validates bounded backup bytes and the envelope digest,
typed KV keys, and recursively ordered serde fields for root/node rows. Other
native values are limited to strict UTF-8, duplicate-free compact JSON; the
checker does not claim full native-codec canonicality for them. It checks tree
reachability and links, AVL heights and balance, spans, in-order links, and
independently folded Financial, Quote, and Statistics summaries. It can also
compare expected source-derived membership; when that input is omitted, its
result says `sourceMembership: "not_evaluated"`. This is
N5's new physical structural check; N4's older Python source-only checker did
not check tree topology. Measurement query-result and selected-identity checks,
and equal-time mixed-sign Equipment prefix extrema remain separately
incomplete pending final independent evidence.

The release API separates a committed-source export, a locked Cargo build
description, receipt-bound package creation, and verification from an extracted
directory. Four focused release controls reportedly pass, including a positive
package fixture that uses an N2 binary; this does not count as an actual release
build or extracted committed-source acceptance. Root still owes the real
locked release build, retained build receipt/log, package hashes, verification
outside the checkout, and the planned redb, SurrealKV, and FoundationDB runs.
The root reports no remaining `rebase-next` or `fdbserver` processes after the
prebuild and ownership runs; the final release run must record its own cleanup.

N5 acceptance will be bounded by the exact committed source, built artifact,
available adapters, and retained runs. A local fake provider establishes only
its documented single-process, single-writer fixture behavior. Keep N4's
remaining logical source-check obligations visible unless the final independent
evidence closes them; native `store.check` is not an independent structural
oracle.
