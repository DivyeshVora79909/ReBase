# Adding and maintaining a frontend page

Read the [architecture](architecture.md), [screen contracts](screen-contracts.md)
and the current [accounting inputs](../all-in-accounting/schemas). Application
code lives in the separate `MetaSol/` Git repository; these documents live in
ReBase. Inspect both working trees before editing shared code.

## Start from the native contract

1. Read the table's public inputs and native source in the accounting
   [source map](../all-in-accounting/context-map.md). Identify permissions,
   immutable references, optional fields, units, date guards and derived values.
2. Add an ordinary `src/routes/w.$profile.$tenant._app.<page>.jsx` file with
   `createFileRoute`, validated URL search and an explicit component. Vite updates
   `src/routeTree.gen.js`; do not hand-edit it.
3. Add reads and content encoders to the appropriate `src/data/` module. Bind all
   user values; allowlist dynamic table/order choices. Preserve native values.
4. Compose fields, tables and feedback directly. Extract another shared component
   only when the same substantial interaction already repeats.
5. Update this page's contract and record the actual verification performed.
   [Verification](verification.md) owns evidence; [deferred work](deferred-work.md)
   owns unfinished capabilities.

## One page and one form

This reduced currency page uses the real Directory API. The full
[Directory route](../../MetaSol/src/routes/w.$profile.$tenant._app.directory.jsx)
adds URL filters, pagination, cards and editing. For a new page, change the route
path and import its explicit data functions; no registration layer is needed.

```jsx
import { createSignal, Show } from "solid-js";
import { createFileRoute } from "@tanstack/solid-router";
import { createSessionQuery } from "@/app/queries.js";
import { useSession } from "@/app/SessionProvider.jsx";
import { directoryContent, listDirectory } from "@/data/directory.js";
import { QueryState } from "@/ui/Feedback.jsx";
import { Records } from "@/ui/Records.jsx";
import { SourceForm } from "@/ui/SourceForm.jsx";
import { TextField } from "@/ui/Fields.jsx";

export const Route = createFileRoute("/w/$profile/$tenant/_app/directory")({
  component: CurrencyPage,
});
function CurrencyPage() {
  const session = useSession();
  const [creating, setCreating] = createSignal(false);
  const close = () => setCreating(false);
  const query = createSessionQuery(
    () => ["directory", { kind: "currency", q: "", page: 0 }],
    (db, [, input]) => listDirectory(db, input),
  );
  return <div class="page">
    <Show when={session.can("currency_create")}>
      <button class="btn" onClick={() => setCreating(true)}>New currency</button>
    </Show>
    <QueryState query={query}>
      <Records rows={query.isPending ? [] : query.data?.rows} view="table"
        columns={[{ label: "Currency", cell: row => `${row.name} (${row.code})` }]} />
    </QueryState>
    <Show when={creating()}>
      <SourceForm table="currency" initial={{ precision: "2" }} title="Currency"
        encode={values => directoryContent("currency", values)}
        onSaved={close} onCancel={close}>
        {form => <>
          <TextField form={form} name="name" label="Name" required />
          <TextField form={form} name="code" label="Code" required />
          <TextField form={form} name="precision" label="Decimal places"
            type="number" min="0" max="18" step="1" required />
        </>}
      </SourceForm>
    </Show>
  </div>;
}
```

`createSessionQuery` adds identity/epoch scope and completion fencing. Its read
callback gets the real SDK and key input. `SourceForm` supplies the owner, stable
ID, confirmation/error handling, dirty protection and success notice. Its callback
runs after session query invalidation. New business payloads still need their
own encoder: never spread a database row or arbitrary form values into a write.

## Extending queries and pickers

Use explicit projections and `tenant = $auth.tenant`; native permissions remain
authoritative. Normal pages use an ID sort tie-breaker, `WITH NOINDEX`, a bounded
`LIMIT` and the extra-row Next sentinel. The shared `pageResult` displays 25 of
26 fetched rows. Aggregates need an explicit population and unit; adding loaded
cards is not a ledger total. Put every read dependency in its query key.

Use `ReferenceField` with a finite `tables` array and native field value. For an
invoice-scoped search, the existing API is:

```jsx
<ReferenceField form={form} name="source" label="Issue"
  tables={["sales_issue"]} required
  scope={String(form.value("invoice") ?? "")}
  search={(db, tables, input) =>
    searchInvoiceReferences(db, tables, input, form.value("invoice"))} />
```

Import `searchInvoiceReferences` from `src/data/invoices.js`. Choose the matching
issue table for the invoice side. A custom search must bind its filter and return
`{ rows, hasMore }`; `scope` must include every external dependency it captures.
Clear incompatible selected references when their parent changes. Add a
new reference type to the finite allowlist in `src/data/references.js`, not to a
resource or form registry. Preserve pending-state guards around picker query data.

## Editing and shared controls

Capture the selected original row when opening an editor. Mount SourceForm with
that stable `record` and `table`; key the surrounding `Show` by editor selection.
Do not key it by a refetching query result. `form.value(name)`, `form.set(name,
value)` and `form.editing` are the field API. Pass immutable field names through
`immutable` and disable their controls. SourceForm uses the original `updated_at`
for update/delete and suppresses local callbacks after unmount or session change.
A failure after unmount can still report its record and inspection action in the
same session; it cannot publish into another session.

| Shared piece | Responsibility |
| --- | --- |
| `TextField`, `ReferenceField`, `CheckField`, `SelectField` | Authored input JSX over the form API |
| `FeeFields`, `AnalyticsFields` | Actual repeated optional payment/analytics inputs |
| `Records`, `ListToolbar`, `Pagination` | Explicit columns/cards, bounded filters and paging |
| `Amount`, `DateTime` | Exact values with currency/resource unit and display time zone |
| `PageHeader`, `QueryState`, `RefreshButton` | Page actions and pending/error/refresh feedback |
| `Modal`, `useUnsavedChanges`, `FormError` | Focus, draft protection, errors and record inspection |
| `ExportButton` | Current explicit rows/projections as exact CSV cells |

Encoders use `src/data/values.js` and `inputs.js`: native IDs/decimals/instants/
durations, allowlisted references and `undefined` for cleared optional fields.
Keep zero and false. Quantity, pricing currency, invoice currency and cash currency
can differ; label the input's actual unit. Calculations and date/capacity checks
belong to the backend. Never optimistically adjust balances or retry an uncertain
write automatically. Inspect its stable reference and compare current values.

## Run and verify the concrete change

From `MetaSol/`, `npm run demo` compiles the current sibling accounting schema,
starts a disposable loopback memory database, seeds native records and launches
Vite. It prints the URL and record-user credentials; Ctrl+C discards the demo.
The `surreal` executable and installed dependencies in both repositories are
required. `npm run dev` instead uses `public/runtime.json`; keep that configuration
public and provision the database separately.

Run `npm run build`, exercise the changed native/browser flow, and run
`git diff --check` in each edited repository. Check denied/error/empty states,
dirty navigation and the relevant tenant/time/unit boundary. Do not infer current
integration acceptance from utility tests or old evidence. Record actual results
in [verification](verification.md) and missing coverage in [deferred work](deferred-work.md).
