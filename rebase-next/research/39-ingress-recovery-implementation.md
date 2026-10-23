# G5c implementation entry

**Prepared after accepted G5b, 2026-10-23; ingress/restored activation unaccepted.**
The [G5 lifecycle gate](33-external-effects-gate.md) owns the contract. Start from
source 0.11 /store 8 /native codec 6 /effect codec 2 /API 2. Preserve the G5b binary,
independent provider journal and evidence. No accepted campaign needs repetition
without a changed obligation. Stay on `main` with one Cargo owner and retained
debug/optimized caches.

## Next implementation

1. Add the one static fake-provider ingress route. Bound raw body to 8 KiB and
   its read deadline before parsing. Verify exact bytes, account/event identity,
   signed timestamp with five-minute skew and HMAC using the existing mature
   HMAC/SHA-256 library. Secrets are operator configuration, never model input or
   persisted raw authorization data. Normalize only after verification.
2. Persist a checked inbox row keyed by account/event UUID, with execution and
   body hash. Identical duplicates ACK from the durable row; identity/content
   conflicts reject. Unknown executions reject. Capacity/storage failure is
   retryable and never ACKs. Extend the 256-row, 8 MiB accounting and complete
   inventory to include inbox, keys and sanitized diagnostics.
3. Discover inbox independently from wakeups through stable row identities and
   bounded cursor progress. Commit consumption and `worker::record_fact` in one
   transaction; domain application follows the existing separate fact path.
   Older pending events do not regress success; contradictory terminal facts
   remain conflict evidence. Recheck blocked diagnostics and applied revisions.
4. Introduce explicit reconciliation-only activation for restored quarantine.
   Rotate activation and invalidate leases; retain all execution/provider keys.
   A prestart backup cannot authorize submission, including after empty lookup.
   Confirmed provider success may apply through the ordinary engine. Keep normal
   submission blocked for quarantined rows; provide no force-ready override.
5. Extend reset/backup/archive and checked runtime formats coherently. Reject
   reset with active worker, unresolved execution, unapplied success or pending
   inbox. A clean reset rotates store/activation identity and rejects old claims,
   receipts and hints. Do not introduce retention/pruning or implicit migration.

The new inbox/runtime bytes require a new explicit store/effect identity. Source
0.12 /store 9 /effect codec 3 are available if no intervening checkpoint owns them.
Unchanged native codec stays 6; review affected compiled behavior/API meaning
before assigning versions. Other model identities should remain unchanged.

## Focused acceptance

Use explicit-clock native controls for signature/skew boundaries, dedup/conflict,
capacity reservation, actual-write rollback, monotone facts, bounded discovery,
quarantine and reset fences. Then extend the existing independent provider and
real HTTP harness with signed delayed/out-of-order delivery, duplicate lost ACK,
full-capacity retry and failed inbox publication. Keep the provider journal
independent of the backend process and storage.

The required restore test takes a backup **before provider start**, lets the
independent journal accept success, stops the old worker, restores that earlier
snapshot, then reconciles with exactly one remote acceptance and no submission
from the restored copy. Empty lookup stays uncertain. Verify the complete
bounded backup/check, compiled action-version mismatch and archive retention.
Run formatting/Clippy and affected native controls before the one optimized
workflow. Record timings separately, publish the coherent checkpoint, then
prepare the next capability gate from its concrete contracts.
