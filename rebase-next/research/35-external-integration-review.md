# External integration review against the accepted local engine

**Prepared 2026-10-23 against `b377b21`; implementation unaccepted.**
[G5](33-external-effects-gate.md) remains the owning contract. This review
locates its implementation seams while [G4c](34-native-index-extension.md)
replaces the active index representation. It supplies no alternate runtime.

## Verified starting point

The inspected `local.rs`, `mutation.rs`, `security.rs`, `lifecycle.rs`, `rpc.rs`,
`server.rs` and `binding.rs` match the compiled-source fingerprints in
[G4b evidence](evidence/2026-10-23-g4b-windows.json). The existing mutation path
already owns the required atomic transaction; external work should extend that
path. Its current order is operation-context validation and receipt replay,
authorized settlement, reader repair, staged native/public/reader-index writes,
receipt/header writes, then commit. Return values appear only after commit.

The standalone command `python3 -B research/experiments/effect_lifecycle.py`
was rerun once: **14 logical expectations passed; 24 unsafe controls rejected**.
Its SHA-256 is
`bb294f3cba29eef8d5386ba78ebe4d49e2663ee331787984550a0157109ae369`.
It establishes no redb durability, real clock, HTTP, cryptographic or capacity
result. Its logical expectations should become controls at the real integration
boundaries, not a second engine to maintain.

## Staged implementation map

| Checkpoint | Existing seam and concrete change | Minimum new acceptance |
| --- | --- | --- |
| G5a: typed intent | Add experimental `effect-demo` through ordinary `Binding`, CLI/model selection and fixtures. Freeze one execution/request from the final authorized Dispatch creation. Keep current source UUID correlation separate from execution UUID and provider key. | Account 12 becomes 10 and creates Dispatch 3 in one receipt-bearing mutation; aborted settlement or later write failure leaves neither change nor intent. Replay at capacity creates no second intent. |
| G5a: shared mutation publication | Narrowly extract the transaction-owned staging/publication work from `local::Store::mutate_inner`. Keep `mutation::settle_authorized`, terminal invariants, reader repair, public/reader index publication and work limits shared. Prepare intents before `Attempt::finish`, then publish private intent rows before the existing receipt/commit in that same transaction. | Inject failures after actual native, intent, due-index, counter and receipt writes; compare every application table and receipt absence. Check accepted/rejected return values through authenticated RPC. |
| G5a: checked durable inventory | Add checked execution/due/fact/inbox tables and a separate effect-runtime header. Extend `local::check_tables`, `observe`, opening checks and model integrity. Derive due rows, counters and retained identities independently from executions/facts. | Orphan, duplicate, malformed, mismatched-version and missing-index controls fail startup/check/restore. Fill 64 unresolved and 256 retained executions, preserve reserved result capacity and reject overflow atomically. |
| G5a: status and cancellation | Extend `rpc::dispatch` and model capabilities together. Status uses current Account reader visibility; cancellation uses current Update authority plus requester/admin policy, revision CAS and normal receipt context. | Wrong reader/requester/epoch, stale revision, replay/content conflict and archive-expired context controls. No worker token or arbitrary result patch enters public RPC. |
| G5b: fenced execution | Add ordinary claim/start/finish/reconcile functions owning short redb transactions. Resolve captured requester/epoch in each claim/start transaction. Run the bounded poller under server lifecycle and call a separate fake HTTP journal only after confirmed start commit, outside all transactions. | Real process kills around start, remote acceptance and fact commit; stale/duplicate claim losers do no new provider work; count HTTP calls separately from accepted actions. Cancellation after start and empty lookup remain uncertain. |
| G5b: fact application | Commit validated immutable provider facts first. Build the one permitted typed Account balance command and apply through shared settlement with restricted internal authority. Atomically record fact application alongside domain writes. Persist `blocked` only after a rejected attempt rolls back. | Success at balance 2 retains the fact and rejects subtraction of 3. Authorized repair to 5 and explicit retry yields 2 once, without another remote submission. Revocation after start cannot erase the fact. |
| G5c: durable ingress | Add one static fake-provider route to `server::router` with its own bounded raw body/deadline and exact-byte HMAC verification. Commit deduplicated inbox receipt before ACK; consume it into facts independently of domain application. | Invalid signature/timestamp/body, conflicting event ID, lost ACK, storage-full retry, duplicate and out-of-order delivery. A failed inbox write never ACKs. |
| G5c: recovery and operators | Extend `lifecycle::backup`, restore inventory and temporary-store checking, reset and receipt archive. Restore unresolved work with new activation, dispatch disabled and reconciliation quarantine, including backups predating provider start. | Independent provider already accepted before restore: reconcile without resend. Stop old workers; prove old activation rejection, blocked reset and archive retention of all effect evidence. Check complete bounded backup size. |

## Correctness choices to settle during G5a

The existing `Settled` result does not expose the final authored change set.
Choose a small typed preparation result or a bounded view of the finalized
attempt; do not regenerate intent from command order, intermediate state or an
after-commit callback. The execution's generated time/identity must be frozen
once, and operation replay must precede allocation or capacity charging.

The current public `ReceiptValue<B>` stores a record-mutation result.
Cancellation needs an explicitly tagged receipt result or a checked separate
typed receipt shape under the same operation identity/context contract. Choose
and version that representation before storing the first cancellation receipt;
do not reinterpret its bytes as a record mutation on replay or archive.

`security::write_authority` checks the current Store session actor/epoch.
A server bootstrap Store is not the captured requester's authority. Claim/start
must load the captured requester and epoch within their write transaction.
Fact application needs a narrowly scoped internal authorization function whose
only output is the compiled balance change; `trusted=true` is not sufficient
authority because that flag also opens fixture visibility.

The current complete inventory allows exactly four unsecured or six secured
tables, and `local_runtime` allows exactly one header row. Lifecycle restore
also hardcodes those names and row types. New tables require coordinated changes
through every observation/check/restore surface; allowing arbitrary extras would
hide corrupt or omitted state. G5a must leave restored dispatch disabled until
G5c's quarantine behavior is implemented and verified.

The 1,024-fact ceiling and 8 MiB private budget require real reserved capacity
accounting, including checked encoded lengths, indexes and diagnostic bytes.
Deduplicated facts/inbox events cannot consume another reservation. A blocked
first due row, backdated insertions and restart must not starve later work;
test the captured-cutoff/full-key sweep rule with the actual persisted cursor.

An unknown start commit, lost HTTP response and unknown finish commit are three
different reconciliation boundaries. Local lease fencing cannot stop a paused
remote call. Contradictory terminal provider observations must remain evidence,
never overwrite success or reopen ordinary submission. Application status is
independent of remote phase; application failure cannot request another send.

Allocate identities from the state accepted immediately before G5: the current
plan expects G4c store/native codec 6, followed by G5 store 7/effect codec 1 and
API 2. Native codec 6 can remain only if its bytes and meaning do. Review actual
intervening changes before assigning versions or bumping binding behaviors.

## Efficient local verification setup for G4c

Run Cargo with `rebase-next/` as its working directory. Its pinned
`rust-toolchain.toml` selects installed Rust/Cargo **1.95.0**; the parent directory
defaults to 1.83.0. Python 3.12.8 and OpenSSL 3.0.13 are available. Set
`CARGO_INCREMENTAL=0` and use one shared target directory to avoid competing
builds. Formatting and Clippy precede optimized acceptance:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --release --all-targets
```

For the shared representation port, rerun the three existing observation
producers (`native_slice`, its `causal-slice.json` fixture and `local_acceptance`)
and their independent `native_slice.py` / `local_prototype.py` readers against
the newly emitted paths. G4c changes their codec obligation, so old output paths
are not new evidence. Retain the G4b exact-window tests and representative work
controls. Run the selected-model HTTP workflow once against the accepted final
binary, then add G4c-b's measurement workflow when implemented. Do not restart
the original ReBase or full release-packaging campaigns for this port.

The historical G4b evidence names `target/g4b-accepted/rebase-next`, but that
artifact and the `target/g4*` outputs were absent in this local checkout at review
time. Rebuild and retain the committed G4b baseline before overwriting build
outputs, using a source export without another branch. Record its new local
fingerprint separately from the historical cloud executable and use fresh
disposable matching stores for the incompatible-format rejection control.
