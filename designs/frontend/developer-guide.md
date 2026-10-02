# Adding and maintaining a frontend workflow

Start with the [architecture](architecture.md) and
[screen contracts](screen-contracts.md). Work in `MetaSol/` for application code
and in `designs/frontend/` for this documentation. They are separate Git roots.
The application's source is the example; there is no secondary scaffolding API.

## Follow one existing page

Use [`treasury.js`](../../MetaSol/src/data/treasury.js) and the treasury routes
for a read/detail/create example. Use [`invoices.js`](../../MetaSol/src/data/invoices.js)
for a two-source transaction. Use the production route for an explicit state
transition. Each has a native test using the real compiled accounting schema.

1. Read the source table's fields, permissions, immutable dimensions, references
   and guards. Identify its managed outputs and do not expose them as writable
   records. Write down a successful example and a rejected example.
2. Add a normal `src/routes/w.$profile.$namespace.$database._app.<page>.jsx`.
   Export a `createFileRoute` with URL validation and the page component. Let
   Vite regenerate the route tree.
3. Put the actual SDK read/write functions in an appropriate `src/data/` module.
   Bind values. Only finite local choices may select a table or SQL order clause.
4. Render the small shared pieces with authored JSX columns and fields. Keep
   state local until there is a real second consumer and independent lifetime.
5. Run the domain's native positive/negative case and the visible browser flow.
   Update the contract and evidence when behavior changes.

## Queries are visible and ordinary

This is the pattern used by the treasury page:

```jsx
const search = Route.useSearch();
const query = createSessionQuery(
  () => ['treasury', { ...search() }],
  (db, [, input]) => listTreasury(db, input),
);

return <QueryState query={query}>
  <Records
    rows={query.data?.rows}
    view={search().view}
    columns={[
      { label: 'Account', cell: row => row.name },
      { label: 'Balance', cell: row =>
        <Amount value={row.balance} code={row.currency_code} precision={row.precision}/> },
    ]}
    card={row => <article class="record-card">{row.name}</article>}
  />
</QueryState>;
```

`createSessionQuery` adds a session scope and completion check. Its callback
gets the real SDK, the same input used in the key and an abort signal. The
signal suppresses obsolete UI results; it does not promise remote cancellation.
It has no resource metadata, implicit joins or query compiler.

Use `LIMIT pageSize + 1` and an ID tie-breaker for a normal page. Apply optional
filters with `NONE`, not bound JavaScript `null` (which means SurrealQL `NULL`).
Preserve the query's empty/loading/error states. An aggregate is a different
query with a named population and dimensions, not a sum of loaded cards.

Solid Query's `data` getter participates in Suspense. In controls that must
retain focus, check `isPending` before reading it. The record picker is a tested
example. Do not retain another query's rows as placeholder data across a session
or workspace transition.

## Forms keep source identity and input snapshots

Use `createStore` for a route-local draft; use `unwrap` to make a plain snapshot
for the SDK. Copy nested line objects explicitly. Keep native values such as
RecordId/Decimal instead of JSON round-tripping them.

```jsx
const id = newRecord('cash_in'); // Once per form, never inside submit.
const [values, setValues] = createStore({
  owned_by: session.principal().id,
  amount: '',
  effective_at: localDateTime(),
});
const [dirty, setDirty] = createSignal(false);
const mutation = createSessionMutation(saveCash, () => {
  setDirty(false);
  props.onClose();
});
const submit = event => {
  event.preventDefault();
  mutation.mutate({ id, kind: 'in', values: { ...unwrap(values) } });
};
useUnsavedChanges(dirty);
```

The data function builds an allowlisted content object and converts strings
with `record`, `decimal`, `integer` and `instant`. Do not spread an entire form
or database row into a write. Catch expected business failures at the form with
`FormError`. Unknown outcomes should expose the stable draft reference and the
existing inspection action; do not add an automatic retry.

Updates pass the last-read `updated_at`. Immutable dimensions stay fixed in the
editor. Native `RETURN BEFORE` plus an exact-row assertion is required for
deletion; an empty deleted result must not look successful. A custom transaction
can call `commitSource(db, boundQuery, stableId)` after returning exactly one
native source ID. Always include BEGIN/COMMIT and check every intermediate
statement response.

Successful writes clear dirty state before navigation. A late completion must
not navigate after its captured session has changed. Never update a financial
summary optimistically or add a writable `net` field.

## Shared component APIs

| Component/helper | Inputs and responsibility |
| --- | --- |
| `PageHeader` | `title`, optional `eyebrow`, `description`, action children |
| `QueryState` | Query object; pending/error/retry around result children |
| `Records` | `rows`, JSX `columns`, JSX `card`, `view`, optional `groupBy`; presentation only |
| `ListToolbar` | Validated `search`, `onChange`, input label, optional finite sorts/views |
| `Pagination` | Current page/count, `hasMore`, `busy`, `onPage`; no guessed total |
| `ExportButton` | Current rows and explicit export value functions; exact CSV cells |
| `RecordPicker` | Finite `tables`, native `value`, `onChange`, label; optional `multiple`, entity, disabled and explicit search callback |
| `Amount` / `DateTime` | Exact amount with currency/unit; saved instant with display preference |
| `EntityFilter` | URL entity value and change callback; never changes authentication |
| `OwnershipField` | Controlled owner value; caller supplies the initial principal |
| `Modal` | `open`, title, optional wide, `onClose`; caller owns dirty/pending decisions |
| `FormError` | Friendly error and stable-ID current-record inspection when available |
| `useUnsavedChanges` | Dirty accessor; router and before-unload protection |

When a new reference type is needed, add it to the finite list in
[`references.js`](../../MetaSol/src/data/references.js), choose an explicit
projection/search contract and add native permission checks. Do not turn that
lookup allowlist into a generic resource/form definition. Currency, resource,
location, source ID and effective date help distinguish similarly named records.

## Public configuration and deployment

`public/runtime.json` is fetched without a build-time environment dependency.
It contains only public connection profiles. Configure the access method for
record sign-in and serve `dist/` with SPA fallback. Runtime JSON can be replaced
in the built output without rebuilding application routes.

The frontend does not provision databases. Apply the intended compiled profile
with the backend developer tools and provision a record principal independently.
Do not put root/database credentials, provider secrets or private SurrealQL in
the frontend, and do not import the backend Node toolchain into a browser bundle.

## Verification commands

From `MetaSol/`:

```bash
npm test
npm run test:browser
npm run build
git diff --check
```

For a focused follow-up, run the relevant test only, for example:

```bash
node --test tests/values.test.js
node --test --test-name-pattern="invoice" tests/accounting.test.js
npm run test:browser -- tests/accounting.spec.js -g "invoice"
```

The native fixture compiles the sibling ReBase schema into a disposable
directory, starts a loopback memory database and signs in through the real
record access method. It does not use deployment settings or personal `.env`.
The browser suite uses production Vite output and both accounting and session
fixtures. `surreal` 3.2.0 and Chromium must be available; override
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` when needed.

Use a failure to decide the next check: a syntax failure needs the data query;
a wrong balance needs the native contract; a lost form needs the browser state;
a context leak needs the existing runtime regressions. Do not rerun unrelated
Redis/provider/capacity suites for a CSS change.
