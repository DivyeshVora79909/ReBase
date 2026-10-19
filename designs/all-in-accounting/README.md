# Subsidiary accounting as explicit calculation records

The active profile implements sparse organization currency/resource positions,
subsidiary reporting, directional receivable/payable contributions, unified
adjustments, strict tax recalculation records and shared dated exchange rates.

Read the [developer guide](developer-guide.md) for the model, equations, typed
reference diagram, tree memberships, graph queries and extension standard.
The [source map](context-map.md) locates implementations; [examples](examples.md)
start with native SDK inputs. The [domain design record](redesign-2026-10-13.md)
preserves the recovered accounting request. The
[declarative-engine plan](../rebase-system/declarative-engine-plan.md) owns the
current engine, and [verification](verification.md) records evidence.

```bash
npm run build:all-in-accounting
npm run verify:accounting
node dev-tools/accounting/fixture-example.js
```

There are 48 authored public create schemas under `schemas/`; the compiler copies
them to `build/all-in-accounting/client/schemas`. Apply the profile to a fresh
database. Historical recipes remain in Git history.
The [complete fixture](fixtures/README.md) ships its recipe, defaults and three
fixture-only contact schemas in `build/all-in-accounting/fixtures/`. Open
`build/all-in-accounting/inspector.html` directly to explore schema relationships,
dependencies and tree memberships.
The separate MetaSol prototype uses an earlier accounting API and is not part
of this redesign's acceptance.
