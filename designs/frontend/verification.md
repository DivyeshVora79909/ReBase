# Frontend verification — October 18, 2026

This packet targets ReBase `ebe999d` and replaces the October 8 frontend
contract. MetaSol is committed independently as `816e983`; the full revision
and artifact fingerprints belong in the [evidence record](evidence/2026-10-18-frontend.json).
Backend source was unchanged. The two user-owned enterprise fixture scripts
and unrelated `history.txt` are outside this packet.

## Checks

| Check | Result |
| --- | --- |
| `npm test` in MetaSol | 29 passed; no failures or skips |
| `npm run build` in MetaSol | Passed: 328 modules, 3.08 seconds in Vite |
| `npm run check:all-in-accounting` in ReBase | Passed: 65 tables, 48 public schemas, 0 views |
| Disposable native acceptance | 10 scenarios passed against the current compiled model |
| Maintained Playwright acceptance | 13 passed, 0 failures or retries; 3.5 minutes |
| Public input reachability | All 48 forms opened; each published field has an input |
| Dependency audit | `npm audit --json`: 0 vulnerabilities |

Reproduce the maintained stages with `npm run test:acceptance`. Final verification
runs `verifyNative(demo)` and the complete Playwright suite in the same owned
fixture. The command's pre-hook refreshes the generated contract before importing
readers. Startup without a pre-existing
`generated/contract.json` was also exercised. The runner installs the compiled
model using `prepare()` into an owned, disposable SurrealKV database, provisions
a record user, seeds its own demo and runs native scenarios before Playwright.
The browser receives record-user credentials through a private temporary file;
administrator credentials remain in Node. Cleanup closed the owned connections
and servers and removed the private manifest; process and filesystem checks
confirmed their removal. No configured database or runtime
profile is changed.

Environment: Node 26.12.0, SurrealDB 3.3.0, SDK 2.1.1, Solid 1.9.17,
TanStack Solid Router 1.170.36 / Query 5.101.4, Kobalte 0.13.14,
Ajv 8.20.0, Vite 8.1.5 and Playwright 1.62.1.

## Native and unit boundaries

The maintained unit suite covers generated input contracts, unknown fields,
readonly updates, optional clearing, exact decimals, typed record identities,
datetime precision, transaction responses, stable IDs on timeout, session/token
identity, relationship scopes, conversion directions and appearance contrast.

The ten native scenarios exercise:

1. Ownership/reference adjacency and authenticated principal scope.
2. Forward/reverse pages, native cursors, prefix isolation and sparse filters.
3. Copied native IDs, quoted/UUID keys and exact relationship/index membership.
4. Equal timestamps, exact sums and changed index revisions.
5. Clearing an optional field and rejecting stale updates/deletes.
6. Database rejection, effect rollback and retry with the same source identity.
7. Invoice lines, payment, signed correction and foreign-currency payment.
8. A dated exchange rate recalculating an existing directed transfer.
9. Production inputs/outputs and explicit subsidiary context.
10. Denial of records and tree members to another principal.

The invoice scenario produces INR 200 total, INR 90 paid and INR 110 balance
before its foreign payment. A later USD 1 cash payment calculates INR 83 while
its movement display remains USD 1. A EUR 2 transfer initially yields USD 2.2;
a later effective rate recalculates it to USD 2.4. These are native results,
not frontend financial calculations.

Composite partition enforcement is covered in the read-primitive unit tests.
Current public accounting roots have one business key component; native tests
exercise their actual typed prefixes and duplicate tie breakers. This evidence
does not claim that private composite identity roots are publicly browsable.

## Browser scenarios

The maintained Chromium suite covers thirteen scenarios:

- Workspace routes and all 48 public forms, including their published fields.
- Keyboard reference selection, clearing and empty results with a retained draft.
- Missing conversion creation, child cancellation/save, return focus and explicit
  submission of the intact parent transfer.
- Invoice payment followed by a nested adjustment note and signed correction.
- A production material input through the shared form and picker.
- An optimistic conflict that retains the user's draft.
- Appearance persistence and mobile navigation focus.
- Lookup failure and retry without losing input focus or draft values.
- Subsidiary changes and copied-reference scope isolation.
- A 53-entry history, next/previous pages, empty filtered pages and recovery from
  a concurrently changed revision.
- Touch selection, bounded mobile dialogs and focus restoration.
- A database-accepted write whose confirmation is delayed past the actual
  20-second timeout; inspection and deliberate retry retain one ID and one row.
- A delayed read released after signout without restoring the old interface.

Transport injection handles both SDK `query_stream` and `query` requests.
The revision scenario reads an uncached page before asserting the change;
returning to a cached page is not treated as a fresh database read.

## Integration corrections and visual review

Acceptance drove corrections to pointer focus inside native dialogs, capturing
the invoking element before mounting a child, and restoring focus after that
child is removed. Dialogs now use a stable portal in the owning theme root so
reactive DOM moves cannot discard native modal state. Picker errors describe
the settled search rather than a previous request during debounce. Parent drafts
survive principal refresh;
queries consume the identity snapshot that keyed their request.

Account and invoice projections retain exact native positions and outstanding
balance. Movement amounts keep their authored unit, and related records display
readable names. Generated contract startup and disposable-server cleanup are
part of the maintained harness.

Final-run screenshots were visually inspected:
[desktop overview](evidence/2026-10-18-overview-desktop.png),
[nested conversion](evidence/2026-10-18-nested-conversion-desktop.png) and
[mobile transfer](evidence/2026-10-18-transfer-mobile.png). The desktop layout
keeps workspace context visible, nested drafts remain open, and the mobile
dialog fits the viewport with scrollable form content. Browser assertions also
cover horizontal overflow, native modal state and focus restoration.

## Limits and historical evidence

Only declared index surfaces paginate. Backlink lookups bound returned rows,
not total relationship work. Page traversal and hydration are separate reads,
not a frozen snapshot; cached pages are not live updates. Composite prefix
walks are forward because no generic native upper-bound sentinel is assumed.

Browser coverage is Chromium desktop and touch emulation. Form reachability
does not prove every business-field combination, assistive technology/device
behavior or large-data throughput. Persistent notifications, offline drafts,
bulk import/export, additional authentication flows and deployment remain in
[deferred work](deferred-work.md). No push or deployment belongs to this packet.

The [October 8 evidence](evidence/2026-10-08-frontend.json) and
[October 2 evidence](evidence/2026-10-02-frontend.json), including their screenshots
and logs, remain historical. Their results do not certify this implementation.
