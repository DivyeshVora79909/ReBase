# G2b: verified indexed selection and compact scheduling

**Accepted checkpoint, 2026-10-22.** Retain the substantial implementation from
unfinished `7d7e387`, replace that unverified Git snapshot with this tested
checkpoint, and continue G2c. The predecessor [G2a evidence](evidence/2026-10-22-g2-baseline.json)
matches all 12 recorded source hashes at `57b3588`.
All work remains inside `rebase-next/`; no dependency was added.

Reverse incoming, direct and ordered-query registrations are now point-addressed
AVL nodes. Changing one registration rewrites balanced paths rather than a whole
subscriber list. Strict-prefix invalidation selects endpoints after the earliest
changed old/new contribution; a backwards move opens the newly exposed interval.
Dated quote invalidation uses old and new successor intervals. Original selection
uses original headers and nodes, including when a registration moves in the same
attempt. Zero-valued emissions and whole-root queries retain dependency identity.

The final graph uses prefix gates for each root/time. A gate depends on its
predecessor and producers emitting at that time; a consumer depends on the gate
before its strict bound. This preserves producer reachability and cycles with
linear graph size instead of explicitly materializing every producer pair.
Construction still has ordered-map/search costs; full fanout remains real work.

## Executed checks

- **55 Rust tests** pass, including new route endpoint/move/drain/corruption
  controls, 4,096-registration selective bounds, 512 independent pairwise graph
  comparisons and a source-only 160-edit equipment settlement control.
- The real native/local runners and independent checkers pass **68 foundation
  cases /93 operations**, **39 causal cases /55 operations**, and **nine local
  cases /14 operations**. Complete state, rollback, reopen and exact-work checks
  remain. The route checker gains eight deliberate corruptions; it derives
  registration inventory from sources rather than calling the route writer.
- One old exact-work literal changes from five to four evaluations. Editing W
  at time 15 affects Q, L, R and J. P reads strictly before 10, so it is correctly
  excluded. A separate source-derived closure control proves that exact inventory;
  the state and exact-work assertions are retained.
- At 24 equipment reservations, an after-all-reads edit now selects **zero**
  producers, loading **24 keys /11,636 bytes**, instead of selecting all 24.
  A last-read edit selects **one**, loading **33 keys /13,880 bytes**. Full fanout
  uses **240 dependency checks /118 graph edges**, versus G2a's 1,154/276.
  Independent public source arithmetic and full native integrity pass.
- Formatting and warning-denying Clippy pass. Exact execution, source hashes and
  local observation paths are in [checkpoint evidence](evidence/2026-10-22-g2b-indexes.json).

This is an intermediate 0.4 checkpoint, with explicit store/codec format 4 and
calculation/equipment behavior revisions 3/2. The bundled population limits still
remain 64/48/256 here. New outer inventory constants prepare the next checkpoint;
they do not admit a larger model population by themselves. G2c must adjust model,
codec, inventory and recovery bounds together and test the larger real API.
Historical evidence and old stores keep their original identity; no silent
migration is supplied.

## Continue with G2c

Follow [the gate](22-population-scaling-gate.md): 64, 256, 1,024 and 4,096 public
sources through both models, fixed small-selector bounds, at least 128 affected
producers committed under the unchanged 200,000-unit budget, and honest larger
fanout rejection/rollback. Keep command, transport, principal, receipt and backup
byte limits separate. Whole-store checking/backup is an offline inventory task.
Generic output-producing calculation shape is supported; an arbitrary reactive
validator-only contract needs its own model/engine contract. Full accounting,
effects, arbitrary monoids and distributed adapters remain later gates.
