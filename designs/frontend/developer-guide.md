# Extend MetaSol

Start with the current compiled accounting profile. MetaSol is a separate Git
repository under ReBase; inspect and commit each checkout independently.

## Routine development

1. Update authored backend schemas and rebuild `build/all-in-accounting`.
2. Run `npm run contract` in MetaSol. Dev/build/test hooks also refresh it.
3. Keep domain decisions in a route, presentation helper or ordinary reader.
4. Add a boundary/workflow regression where behavior changes.
5. Run unit/build checks and disposable acceptance for native/UI changes.

Use `npm run demo` for an isolated record-user workspace. It installs the current
build using `prepare()`; it does not compile the backend or touch runtime profiles.

## Author a record

```jsx
const composer = useComposer();
composer.open({
  table: "sales_issue",
  initial: { invoice: invoice.id },
  context: { subsidiary: invoice.subsidiary },
  onSaved: id => { /* Optional next explicit action. */ },
});
```

`RecordForm` consumes the generated fields. `SourceForm` validates all input and
owns stable identity, optimistic concurrency, errors and completion. Pass the
original record once when opening an editor; do not replace it with refetched
data while the user edits. `inputModel.pick(table, record)` extracts only inputs.
Calculated fields, tree slots, tenant and authorization metadata stay out of
content objects.

For a field with distinct UX, supply ordinary JSX:

```jsx
function InvoiceNumber(props) {
  return <label class="form-field">
    <span>Invoice reference</span>
    <input name={props.name} value={props.form.value(props.name) ?? ""}
      disabled={props.disabled}
      onInput={event => props.form.set(props.name, event.currentTarget.value)} />
  </label>;
}

<Application fields={{ "sales_invoice.number": InvoiceNumber }} />
```

The renderer receives `table`, `name`, `field`, `schema`, `form`, `required` and
`disabled`. `form` supplies `value(name)`, `values()`, `set(name,value)`,
`error(name)` and `editing`. Application `primitives` can replace `Input`,
`Textarea`, `Select` or `Reference` across forms. Forward native input props and
accessible labels. New unsupported field shapes require an explicit renderer;
the current profile uses text, enums, integers, booleans, exact decimals,
datetimes, durations and native references.

## Compose reads

```js
relatedRecords(db, {
  tables: ["sales_issue"], owners: [invoice.id], field: "invoice", limit: 50,
});

indexRecords(db, {
  owner: subsidiary.id, slot: "z_accounts", limit: 50,
  after: previous.next, revision: previous.revision,
  filter: row => row.kind === "treasury",
});
```

Values are bound. Table, field and root identifiers are checked against the
generated public contract. Never substitute a table scan or numerical offset
when there is no root. An indexed read makes one bounded page request and a
bounded identity hydration. Its `next` describes visited candidates, so preserve
it even when filtering returns no rows. Do not repeatedly fetch until a visible
page fills. Keep cursors native and in memory; JSON serialization loses key types.

`readIndex(db, options, load)` is the smaller primitive: a caller supplies the
native owner/root, declared `keyTypes`, optional prefix, cursor, revision, limit,
filter and an identity projection function. Composite keys require a leading
typed prefix. Record prefixes must be resolved native RecordId objects, not
unparsed StringRecordId aliases. Native datetime precision is preserved.

`RecordCollection` calls `read(db, args, identity)` with the identity that keyed
the request. Destructure the owner, type and relationship from that snapshot:

```jsx
<RecordCollection identity={[owner(), slot()]} indexed
  read={(db, args, [owner, slot]) => indexRecords(db, { ...args, owner, slot })} />
```

`RecordPicker` accepts tables, a native value, `onChange`, optional
`search(db, tables, args)`, scope and creation callbacks. A scope can be an
inverse relationship or a public index. Exact IDs remain within that scope.
Use contextual business references when known; ownership adjacency is the
catalog fallback.

New queries use `createSessionQuery(key, read)`. Its callback receives the actual
SDK and the input used in its cache key. Snapshot all read inputs in that key;
avoid reaching into a later reactive selection after starting a query. Guard
pending `.data` getters for controls inside a form.

## Units and writes

Keep decimal input as text until native binding; never use Number for money.
Keep returned RecordId, Decimal and DateTime values intact. Display can use local
time or UTC; date entry uses device-local time. Editing other fields must not
truncate a saved nanosecond timestamp.

Invoice payments enter treasury units. Transfers enter outgoing units. Account
and organization valuation directions differ and are immutable after creation.
Movement projections preserve the authored amount's unit, even when the record's
calculation currency differs. CSV amount cells retain the unit alongside the
exact value. The helpers in `workflows.js` only guide selections; they do not recalculate
amounts or duplicate backend validity rules. When a prerequisite is missing,
offer its normal authoring form. Never silently create a rate or inverse pair.

The native write helpers inspect `.responses()` and exact affected-row counts.
An unknown save keeps the original ID, and an update uses the original version.
Do not turn transport retry into another CREATE identity. Errors and warnings
belong to the form/current session, not a global unscoped store.

## Verification

`npm test` covers pure boundaries. `npm run test:acceptance` owns a disposable
database, runs `tests/native-scenarios.js`, then `tests/browser/workbench.spec.js`.
It closes connections/servers and removes private test credentials in `finally`.
Browser screenshots and traces are ignored artifacts. Add scenarios for changed
relationships, permissions, validation, cursor boundaries and draft lifecycle;
opening a page alone does not verify that it saves correctly.

The [verification record](verification.md) records actual runs and limitations.
