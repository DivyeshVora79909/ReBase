# G5c: signed ingress and restored reconciliation

**Accepted in source 0.12.0, 2026-10-23, following published `f44339f`.**
The [evidence](evidence/2026-10-23-g5c-ingress-recovery.json) records the native
controls, independent provider workflow, identities and retained development
runs. The [G5 lifecycle gate](33-external-effects-gate.md) owns the contract;
[G5a](37-atomic-intent-implementation.md) and [G5b](38-fenced-worker-implementation.md)
retain their earlier acceptance. The overall capability program remains active.

## Implemented behavior

The one `/effects/fake` route reads at most 8 KiB within two seconds, verifies
HMAC-SHA-256 over exact raw bytes and canonical account/event/timestamp headers,
and checks five-minute skew before parsing typed JSON. Operator secret files
stay outside the store and model inputs. Unknown execution, invalid binding,
signature and conflicting event content reject. A durable identical event ACKs
without another row, including at capacity; storage/unknown-commit/capacity
failure never produces a positive ACK.

Checked inbox rows retain raw body/hash, normalized native outcome, frozen
request/store binding and consumption revision. Inbox consumption and provider
fact publication share a transaction; ordinary domain application remains
separate. Due and stable-key inbox turns alternate at sixteen visits. Cursors
advance past consumed or blocked rows and wrap after activation. Idle scans
avoid metadata writes when no work remains. Older pending events preserve
terminal application state and blocked diagnostics.

Worker mode is explicitly `disabled` (default), `delivery` or `reconcile`.
Restored stores allow only reconciliation and ordinary Account repair; new
Dispatch creation and delivery activation reject until a clean reset. Empty
lookup never authorizes a submission, including from a prestart snapshot.
Repeatedly lost reconciliation claims can be retried by the offline operator
without clearing quarantine or replenishing submission attempts.

Reset requires a stopped worker and no unresolved execution, unapplied success
or pending inbox row. Consumed evidence permits clean reset. Receipt archiving
preserves all effect tables. Reset rotates store/activation and credential epochs;
old contexts, claims and execution hints cannot attach to a reused public source.
No retention/pruning, abandonment switch, migration or provider force-ready API
was introduced. See the [operator guide](../docs/external-effects.md).

## Executed acceptance

Twenty-seven effect controls pass, plus two shared terminal-repair controls:
29 distinct Rust tests. The original affected run took 21.45 seconds of test
execution. Final review extended the prestart test with six successive lost
reconciliation claims and safe operator retry; it passed in 0.44 seconds.
Three repair controls passed in 0.99 seconds. Formatting, all-target Clippy and
final diff checks pass. No full optimized Rust or population campaign was rerun.

Native controls cover exact signature/skew/size boundaries, duplicate JSON keys,
real failed inbox writes, atomic rollback after fact/inbox/index/row publication,
stale completion fencing, delayed success/pending/conflicts, blocked repair,
activation bounds, compiled action-version mismatch and corrupt restore isolation.
A combined store has **256 retained executions, 1,024 facts and 256 inbox rows,
each with an 8 KiB raw body**. A capacity-blocked first event does not starve
later rows. Complete check and restore pass; the backup is **6,703,752 bytes**
and accounted private bytes are **3,133,729**.
These are actual count/raw-size boundaries, not a general production-capacity claim.

The final optimized HTTP workflow passes **eight scenarios**, six successful
record mutations /eleven commands and one rejected quarantined mutation. It
uses a separately running provider with its own SQLite journal. Signature,
malformed/bound payload, oversized body and actual two-second read timeout reject.
An actual failed inbox insertion returns 503; retry confirms no row committed.
A discarded ACK body, duplicate delivery, conflicting content, out-of-order
pending event and process kill after durable inbox acceptance retain correct state.
The blocked success remains durable at balance 2; repair to 5 and retry gives 2
once with one provider submission/acceptance.

The HTTP inbox actually reaches 256 rows, keeps 251 pending with the worker
explicitly disabled, rejects overflow and ACKs a retained duplicate. Full backup,
restore, archive preservation and reset rejection pass. A separate backup is
verified to contain no provider-start marker and zero submission attempts. The
old process then obtains remote success and stops. Its restored predecessor
rejects delivery, activates reconciliation and reaches balance 9 with **one total
remote submission and acceptance**. A second, never-started execution receives
an empty lookup and stays quarantined/uncertain with zero submissions. A clean
reset rejects the old context, credential epoch and webhook after source reuse.

## Identity, timing and continuation

Source 0.12.0 uses store 9 /native codec 6 /effect codec 3 /API 3. Effect-demo
behavior is `effect-demo-ingress-3`, model
`6114a52f4ad9d59fc067474e7c12a36d09ead2cafe09583ebc25fb150fd2047f`.
The action/provider identities remain `fake-units-1` /`fake-account-1`.
API 3 replaces the status boolean with `worker_mode` and declares the disabled
default. Calculation, equipment, invoicing and measurement identities match G5b.
A populated, clean format-8 effect store rejects without changed physical bytes.

The retained final executable is `target/g5c-accepted/rebase-next`,
28,428,808 bytes, SHA-256
`fa60b6e8f98fdcfa5dc6b3efae23a07312981433cab4924f5cf5eb8cde025872`.
The final optimized build took 280.615 seconds;
the final HTTP workflow took 13.558 seconds. The first build and
workflow also passed (278.902 /13.959 seconds).
Review found the narrow ready/quarantined retry gap; that change justified one
new build and the affected reruns. Earlier successful evidence remains in
`target/g5c-before-review-*`, `target/g5c-before-retry-review/`,
`target/g5c-effect-tests.log` and `target/g5c-ingress-http/`.

Final reports: `target/g5c-checks.json`, `target/g5c-compatibility.json`,
`target/g5c-bounds.json` and `target/g5c-final-ingress-http/result.json`.
All owned backend/provider processes are stopped. Preserve the G5a/G5b binaries
and evidence as well. Continue [G4d-b native query consumers](40-native-query-consumers.md)
on `main`, with one Cargo owner, two jobs and the retained per-profile caches.
G4d-c selection and G6-G8 remain open; the last packaged deployment is still 0.6.0.
