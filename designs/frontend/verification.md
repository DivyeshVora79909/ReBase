# Frontend verification

## Redesign review — 2026-10-03

The user requested a fresh backend and frontend review through local SurrealDB
consistency. The [combined evidence](../rebase-system/evidence/2026-10-03-redesign-verification.json)
records commands, source fingerprints, corrections and scope.

- At MetaSol `3022392`, the full baseline passed **26 native/unit tests** and
  **28 Chromium browser tests**, including the production build. Desktop entry,
  overview and mobile dark cash screenshots were inspected.
- Review found a backend invoice guard using strict record prefixes instead
  of complete timestamps. It now uses `outstanding.instant_min`. The frontend
  no longer warns against same-instant settlement. Focused final checks passed:
  **one native invoice test** covering sales and purchase partial/full settlement
  and early/excess rollback, plus **one browser invoice test** and a fresh build.
  The browser confirms allocation timestamps equal the entered issue timestamp
  and no duplicate cash movement is created.
- The full baseline was not repeated after those four focused frontend edits.
  Exact final fingerprints and the focused checks identify what was revalidated.
- The final browser runs use a sanitized process environment and temporary
  Vite configs with an empty `envDir` for both build and preview. One initial
  baseline attempt was interrupted to extend that isolation to preview;
  it has no passing-suite claim. No provider calls or API keys were tested.

No existing data needs migration for this task. Live providers and deployment
load are outside acceptance. Deferred product workflows below remain separate
features; these results cover the delivered screen contracts.

## Implementation verification — 2026-10-02 (historical)

The delivered scope in [screen-contracts.md](screen-contracts.md) is implemented
and verified. Evidence is retained in
[`evidence/2026-10-02-frontend.json`](evidence/2026-10-02-frontend.json).

## Final checks

| Check | Result |
| --- | --- |
| `env -i PATH="$PATH" node --test tests/*.test.js` from MetaSol | **26 passed**, 0 failed, 0 skipped; includes 10 native accounting tests and 16 value/runtime/storage tests |
| `npm run test:browser` from MetaSol | **28 passed**, 0 failed; 12 accounting/UI tests and 16 existing session/engine regressions |
| Production Vite build | Passed as the browser suite's `npm run build` web-server prerequisite; tests served `dist/` through Vite preview |
| `git diff --check` in both repositories | Passed |
| Documentation links, authored-file whitespace and source fingerprints | Recorded in the evidence JSON |

The final [native/unit log](evidence/2026-10-02-native.log) and
[browser/build log](evidence/2026-10-02-browser.log) are retained with the evidence.

Environment: Node 22.23.2, SurrealDB 3.2.0, Chromium through Playwright 1.62.1,
Solid 1.9.14, TanStack Solid Router 1.170.36 / Query 5.101.4, native SDK 2.0.8,
Vite 8.1.5. Browser test time zone is explicitly Asia/Kolkata.

The accounting fixture compiles the current ReBase profile with an empty child
environment plus PATH into a temporary directory. It starts a disposable memory
database, creates synthetic directory/accounting records and verified test
principals, then signs in through the actual record access method. Root access
exists only in the Node fixture. The browser receives a record-session login
and public connection profile. Fixtures close their clients/server and remove
the temporary schema output.

## What the checks establish

- Native record sessions read compiled balances and bounded polymorphic
  references. A viewer cannot read the operator's accounts or create its cash.
- Cash entry, editing and deletion preserve exact decimal amounts, including
  digits beyond binary floating-point precision. Invalid historical cash use
  rolls back, duplicate stable IDs fail, and stale edits/deletes are rejected.
- Treasury cutoff reads exclude entries at the exact instant. Stock movement
  and account creation enforce historical capacity. Claim allocations reject
  over-settlement without partial writes; net remains derived.
- Sales and purchase invoices create header/issue atomically, consume stock
  billing capacity, settle from existing cash and roll back invalid lines.
  At this checkpoint same-instant invoice settlement was rejected. The
  2026-10-03 correction and focused checks above supersede that boundary.
- Exchange and its full reversal restore the two account effects. Both
  production and assembly create recipe versions and change lifecycle state
  through their source records. All eight directory create adapters run against
  the compiled schema; Overview queries separate currency groups.
- Browser actions cover entry, every accounting navigation destination, actual
  cash edits/deletion/rejection, directory and treasury setup, historical cutoff,
  claim allocation, stock receipt, invoice multi-selection/issuance/settlement,
  FX/reversal, timed production and immediate assembly with a new recipe.
- An intentionally withheld write response produces an unknown outcome. The
  form inspects the already committed record and a retry cannot create a second
  source. Search-response withholding proves late lookup results cannot replace
  a newer term. Lookup pagination remains focused and hydrates its selection.
- Existing regressions cover endpoint/namespace/database/account isolation,
  late sign-in/read completion, token persistence and expiry, storage failure,
  reconnect timeout and both WebSocket/HTTP transports.
- Desktop table/grid/board presentation, search history and CSV work with real
  data. Mobile navigation supports Escape/focus restoration; dark appearance,
  accent/density/time preferences and keyboard record selection work at 390px.

## Findings fixed during integration

The checks exposed real issues beyond compilation: bound `null` versus `NONE`,
SDK empty transaction result slots and masked assertion failures, loss of
precision in date editing, stale mutation-cache scope, implicit owner fallback,
and lookup Suspense detaching a focused form. Lookup pagination also lost focus
when a loading state disabled the active button. Those behaviors are corrected;
transaction, focus, ownership and delayed-response checks remain in the suite.

## Visual review

These screenshots use only synthetic local fixture data. They were inspected
after the final implementation:

- [Desktop workspace entry](evidence/workspace-desktop.png)
- [Desktop overview](evidence/overview-desktop.png)
- [Mobile cash form, dark/teal](evidence/cash-mobile-dark.png)

## Repository boundaries and limits

ReBase began clean at `0625f9bf6ac370721d22f855d1e904e99479e1e4`.
MetaSol began with the earlier uncommitted Solid starter at
`cccd1df7c53aba2f43b6c8b1b949452094420fbb`.
The exact recorded baseline and current fingerprints in the evidence identify
the changed files; the original starter's legacy deletions were preserved.
MetaSol is a separate ignored repository. Both worktrees were uncommitted at
this historical checkpoint; the frontend was subsequently committed as noted
above. No push or deployment was performed by this review. This work added the frontend package in
ReBase and changes the frontend checkout; backend source remains unchanged.

The tests use local memory databases and Chromium. They do not establish
Safari/Firefox behavior, physical capacity, a production migration, live
provider delivery or statutory correctness. Main lists and boards remain
bounded views, not full ledger exports. Advanced tax/credit, returns/refunds,
quote-based FX, account administration and onboarding are described in the
[deferred-work map](deferred-work.md). Public JSON create schemas are not a
generated frontend validation/form system.
