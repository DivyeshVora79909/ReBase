# Continue the current frontend

Read [the execution plan](execution-plan.md), [architecture](architecture.md),
[screen contracts](screen-contracts.md), [verification](verification.md) and the
[current backend accounting contract](../all-in-accounting/extension-contract.md).
Inspect both parent ReBase and nested MetaSol Git status/log/diffs before editing.
The October 8 backend API supersedes the old frontend recipe/claim-account model.

```text
Continue the MetaSol accounting frontend from its actual checkout. Read the current
frontend documents, both Git histories/diffs and the relevant backend schemas.
Use direct JavaScript/JSX, Solid/TanStack and native SurrealDB values and queries.
Keep pages and content builders explicit. Do not add a resource/form/query registry,
compatibility layer, context per table or custom framework.

Run npm run demo inside MetaSol for an owned disposable current-schema example.
Use the printed record-user login. Do not use demo/root credentials on an existing
server or modify a user's configured database. Review which native/browser checks
were actually performed; historical evidence does not certify newer changes.

Preserve tenant/session fences, mounted-form callbacks, stable create IDs, exact
Decimal values, optimistic updated_at checks and deliberate handling of uncertain
writes. A field's actual dependency belongs in its query key (including custom
picker scope). Use native typed tree bounds/cursors and visible units/time semantics.
Keep a form's initial record snapshot independent of background refetches.

Add only the next concrete workflow. A new capability normally owns one route and
one data module and composes existing fields/presentation. Update current docs and
verification/deferred boundaries with the code. No new automated tests were requested
in the October 8 pass; ask the current task's intent before expanding that scope.
```

For persistent notifications, gateway authentication screens, live collaboration,
import/export or another application, start from the corresponding section of
[deferred work](deferred-work.md). Complete its missing public contract before
building user-facing controls around it. Routine implementation and reversible
local work do not need another permission checkpoint.
