# Frontend execution decisions — October 18, 2026

The request is to improve the return on authored code: reuse compiled contracts,
make native indexed reads explicit, preserve composable source APIs and remove
friction from connected workflows. Breaking replacement is authorized. The two
user-owned enterprise fixture scripts are excluded from all edits and commits.

The inspected baselines were ReBase `ebe999d` and MetaSol `89799ec`. The
[design plan](redesign-2026-10-18.md) defines the implementation slices and
acceptance matrix. Backend build artifacts expose 48 public input schemas.

## Implemented shape

1. Reuse the parent's compiler/model loader at build time. Publish only public
   schemas, native input bindings, readonly facts, references and tree metadata.
   Ajv supplies JSON Schema validation; the SDK preserves native values.
2. Replace domain-specific table scans with direct IDs, native inverse references
   and public tree readers. Pagination is a native cursor over bounded members.
   Composite browsing requires a leading prefix.
3. Share the form/write lifecycle and accessible async picker. A flat mounted
   composer stack returns a saved prerequisite's ID to its parent. It does not
   silently submit a parent or construct an implicit business transaction.
4. Replace the retired accounting pages with current subsidiary, sparse account,
   invoice, correction, tax, dated conversion and production workflows. Keep
   business hints/dependencies in direct modules, separate from generated types.
5. Improve navigation, account/invoice projections, contextual detail pages,
   readable connections and theme controls. Allow ordinary primitive and named
   field overrides without introducing a resource DSL.
6. Maintain an owned disposable database and native/Playwright scenarios.
   Commit frontend implementation and parent documentation independently after
   verification. No push or deployment is included.

## Validation decisions

The tests exercise native authorization, scoped references, exact values,
optimistic writes, sparse/tied/reversed index pages, changed revisions,
prerequisite creation, draft retention, pointer/keyboard/touch behavior and
session fencing. These checks are part of the current request; the October 8
deferral of new automated tests is historical.

Integration exposed native-dialog pointer focus and early trigger capture,
draft resets on principal refresh, stale picker errors during debounce and
projection aliases. Fixes stay in their own small ownership boundaries.
Final results and limits belong in
[verification](verification.md); the plan itself is not evidence of passing.

Future extensions should start at the relevant boundary in
[deferred work](deferred-work.md), retaining the smallest ordinary module that
satisfies the demonstrated use case.
