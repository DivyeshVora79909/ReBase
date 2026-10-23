# G5b implementation entry

**G5b accepted, 2026-10-23.** Source 0.11.0 uses store 8 /native codec 6 /
effect codec 2 /API 2. [Evidence](evidence/2026-10-23-g5b-fenced-worker.json)
records the exact sources, executable, native controls and real-process workflow.
This is bounded fake-provider acceptance, not a packaged deployment or a live
provider/distributed/exactly-once claim. The [G5 lifecycle contract](33-external-effects-gate.md)
remains authoritative; G5c ingress and restored reconciliation are next.

The model identity is
`1be09569fa1ffbc0b32dc1ef36eaffeb6d37426bb5f53af723670db90caf9417`;
behavior is `effect-demo-delivery-2`, action `fake-units-1` on `fake-account-1`.
The accepted executable is `target/g5b-accepted/rebase-next`, 27,641,568 bytes,
SHA-256 `66fe7e4582aebb499a35b58cc40ac4c2e62f196e232a87602ba2c84a785bd206`.
Keep `target/g5a-accepted/rebase-next` with its format-7 stores.

## Executed acceptance

All **25 distinct affected Rust controls** pass: twelve final worker controls,
five shared local/server controls, and eight retained earlier effect controls.
The final twelve take 3.32 seconds and shared controls 0.49 seconds. Formatting
and all-target Clippy pass. Earlier application failures identified the engine's
pre-bind authorization callback; the restricted authorizer now handles both
calls. An abort control used zero against the existing one-based hook; corrected
controls prove ten actual-write abort boundaries across fact and application
publication. Original failed logs remain in the evidence trail.

The optimized HTTP workflow passes **16 scenarios**, 18 record mutations /
34 commands (17 commits, one rejection), two cancellations with replay and four
actual backend kills. It establishes 12 → 10 → 7, success blocked at balance 2,
authorized repair to 5 followed by one application to 2, waiting delivery,
definitive nonacceptance retry, permanent rejection, lost response, cancellation
before/after start, the two-call bound and a real five-second timeout. Crashes
before start, after start, after provider acceptance and after fact commit use
explicit process barriers. Calls and unique accepted actions are read separately
from the independent SQLite journal. A started-but-unobserved execution remains
uncertain with no resubmission. Complete final check finds sixteen retained
executions, sixteen facts and one unresolved execution.

The first HTTP attempt passed seven scenarios before a shared test hold delayed
the next scenario; execution-specific holds fix that harness issue. The corrected
run reused the same executable and completed in **27.275 seconds**. Its report is
`target/g5b-worker-http-2/result.json`. The one optimized build took **375.832
seconds**, including the new HTTP-client dependencies. No accepted population or
full optimized Rust campaign was repeated. Existing calculation, equipment,
invoicing and measurement model identities are unchanged. A valid format-7
effect store rejects under 0.11 with its physical SHA-256 unchanged.

Native controls additionally establish captured credential epochs at claim/start,
post-revocation fact retention/application, stale/duplicate lease losers, finite
renewal and submission/observation budgets, expiry, bounded sweep wrapping and
backdated insertion, typed corruption rejection, monotone terminal facts and the
actual 1,024-fact ceiling with reserved terminal capacity and bounded backup.
These counts are bounded prototype evidence, not production-capacity claims.

## Implemented structure

1. Extend the checked execution/fact representation with lease mode/token,
   activation/revision fences, provider-start evidence, finite submission and
   observation budgets, eligibility, remote phase and separate application
   status. Use explicit `now` arguments in transition functions. Due discovery
   needs work class plus full time/UUID ordering and bounded sweep progress;
   an unclaimable first row cannot monopolize a scan.
2. Keep normalized outcomes model-owned and typed. The concrete fake result
   should justify the smallest compiled binding addition; do not introduce an
   erased result/patch channel or adapter registry. Validate pinned action and
   provider-account version, execution identity and frozen units before a fact
   can enter storage. Discretionary facts cannot spend another execution's
   reserved terminal-result slot/bytes.
3. Implement claim/renew/start/finish/reconciliation with short transactions.
   Resolve the stored requester and captured epoch at claim and start; the
   bootstrap Store's authority is not a substitute. Calls follow confirmed
   start commit and occur outside transactions. Activation changes invalidate
   old leases; an unresolved started request becomes uncertain, never ordinarily
   ready. Unknown start/finish commit outcomes require inspecting stored state.
4. Persist provider facts before attempting business application. A pure typed
   function constructs the permitted Account balance update from the frozen
   request, validated result and current Account. Use `mutation::settle_authorized`,
   normal reader repair and `Store::publish_native`; mark the fact applied in
   that same domain transaction. Restrict repair authority to that compiled
   target/update. A rejected attempt leaves its fact durable and records blocked
   application afterward; explicit retry cannot submit remotely again.
5. Add one bounded Tokio worker and a separate deterministic fake HTTP journal.
   Use an established HTTP client, two owned concurrent calls, five-second
   transport deadlines and the ten/thirty-second lease limits from the gate.
   No detached retries, general workflow service or client-selected endpoint.
   Normal server configuration remains valid with no worker configured.

Continue to reject worker activation for restored/quarantined stores until G5c
implements and verifies reconciliation from a snapshot predating provider start.
Source deletion and receipt archiving cannot erase execution/fact evidence.
Cancellation after start must preserve uncertainty; it cannot claim that the
provider did nothing. Incoming webhooks remain G5c.

G5a owns source 0.10 /store 7 /native codec 6 /effect codec 1 /API 2. The changed private row/due/fact format uses source 0.11 /store 8 /effect codec 2.
No implicit migration is supplied.

## Verification discipline

First cover exact transitions, fences, budgets, reservations and complete
inventory with small native controls. Then run the actual HTTP backend against
the independent provider process: literal 12 → 10 → 7; success with balance 2
blocked, authorized repair to 5 and one application to 2; current authority;
duplicate/stale claims; definitive nonacceptance versus ambiguous loss; bounded
polling and backdated work. Kill real processes at the required start/acceptance/
fact boundaries and count provider calls separately from accepted actions.
Use controlled boundary instrumentation rather than probabilistic race loops.

One Cargo owner reuses `target/native-slice/build` for debug and
`target/g4b-retained-b377b21/build` for optimized builds, with two jobs and
incremental compilation disabled. Run formatting/Clippy before the optimized
workflow. Preserve passed unrelated evidence and measure build/test time
separately. Continue with [G5c ingress/recovery](39-ingress-recovery-implementation.md) on `main`.
