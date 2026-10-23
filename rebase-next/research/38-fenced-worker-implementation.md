# G5b implementation entry

**Prepared after accepted G5a, 2026-10-23; worker/provider execution unaccepted.**
The owning [G5 lifecycle gate](33-external-effects-gate.md) supplies the complete
transition, authority, retry and crash obligations. G5a's checked atomic intent
is implemented in `src/effects.rs`, with the model in `src/models/effect_demo.rs`.
Its retained executable is `target/g5a-accepted/rebase-next`; do not overwrite it.

## Implement in dependency order

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

G5a owns source 0.10 /store 7 /native codec 6 /effect codec 1 /API 2. The planned
changed private row/due/fact format therefore needs a new store/effect version;
source 0.11 /store 8 /effect codec 2 are available. Recheck actual predecessor
and affected behavior identities before assigning them. Do not migrate silently.

## Focused acceptance

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
separately. Commit/push the coherent G5b checkpoint on `main`, then proceed to G5c.
