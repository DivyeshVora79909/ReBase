# SurrealDB Update Permission Probe

## Execution

The probe ran successfully against a fresh in-memory SurrealDB instance.

- SurrealDB: `3.2.0`
- Namespace: `permission_probe_1569148_1786908021255`
- Database: `probe`
- Cases: `28`
- Runner: [`scripts/run-update-permission-probe.sh`](../scripts/run-update-permission-probe.sh)
- Probe: [`scripts/probe-update-permissions.js`](../scripts/probe-update-permissions.js)

The probe creates and removes its own namespace. It does not touch the project database. Each case records the SQL, actor, pre-state, returned rows, error, and post-state.

## Results

### Table-level update permissions

`FOR update WHERE owner = $auth` is effectively enforced against both the existing row and the candidate/resulting row. This is analogous to applying the same expression as PostgreSQL's `USING` and `WITH CHECK` conditions:

- Alice cannot transfer her row to Bob: the existing row passes, but the resulting row fails.
- Bob cannot take over Alice's row by setting its owner to Bob: the resulting row would pass, but the existing row fails.

Both statements return an empty result and leave the original row unchanged.

The same behavior was observed for `SET`, `MERGE`, JSON `PATCH`, `CONTENT`, and `UPSERT` of an existing record.

Bulk updates filter unauthorized rows. In the probe, an `UPDATE table SET ...` changed Alice's row and skipped Bob's row without an error.

A table predicate using `$before.owner`, `$after.owner`, or both did not authorize the tested update. Although SurrealDB applies the ordinary permission expression before and after the mutation, those event-style variables are not usable as reliable record snapshots inside table-level permission predicates in this version. The statements returned no rows and made no change. Do not build the primary authorization rule around them.

### Field-level permissions

Field permissions are non-throwing filters:

- `PERMISSIONS FOR update NONE` silently retains the previous field value.
- A `$value` restriction that rejects the new value silently retains the previous field value.
- A field predicate can retain only that field while other fields in the same statement still update.
- A field `$before` predicate can authorize a field mutation based on its previous value.

Field permissions are suitable for server-managed or deliberately ignored writes. They are not suitable when the API must receive an explicit authorization failure or when several fields must be governed atomically.

### Machine-controlled `VALUE` fields recompute on row mutation

An isolated SurrealDB `3.2.0` probe defined token fields with each of these
permission forms:

```surql
DEFINE FIELD token ON t TYPE uuid VALUE rand::uuid::v7() PERMISSIONS NONE;
DEFINE FIELD token ON t TYPE uuid VALUE rand::uuid::v7()
    PERMISSIONS FOR select NONE FOR create WHERE true FOR update NONE;
```

Both forms behaved the same: `VALUE` ran during creation, during an unrelated
single-record update, during a table update, and when a caller supplied an
explicit token. The stored value was a fresh UUIDv7 in every case. `PERMISSIONS
NONE` also hid the field from the record user's returned row and silently
discarded caller input; privileged server-side access can still use the value
for an access/signup condition.

This makes a field-only machine-controlled token sufficient:

```surql
DEFINE FIELD invite_token ON user
    TYPE uuid
    VALUE rand::uuid::v7()
    PERMISSIONS NONE;
```

The token therefore rotates on every mutation that produces a new row version,
including permission-propagation updates and the password-setting update used by
signup. The expiry remains an independent, visible, administrator-controlled
field. A denied field write still cannot set the token; the `VALUE` expression
remains the only producer of token values.

### Events and rollback

Synchronous event blocks with `THROW` return an error and roll back the complete statement. This held for both a single-row update and a bulk update: when one row triggered the event, no rows in the statement were changed.

### ReBase uniform ownership matrix

The selected project policy protects only `owned_by` at field level:

```surql
FOR update WHERE
    $value = $before
    OR $before = $auth
    OR $before IN $auth.dominates
```

Combined with the unchanged table update predicate, the probe produced this matrix:

| Case | Result |
|---|---|
| Parent-group member edits ordinary fields | Allowed |
| Owner transfers self-owned row to an accessible parent group | Allowed |
| Parent-group member attempts ownership transfer while editing another field | Ownership retained; other field updated |
| Parent-group member submits the existing owner unchanged | Allowed |
| Owner transfers to a dominated principal | Allowed |
| Dominator transfers a dominated row to self | Allowed |
| Owner or dominator transfers to an unrelated principal | Entire row update denied by the resulting-row table permission |
| Parent-group member updates visibility and governance fields | Allowed as ordinary fields |
| Client writes a server-managed field with an ordinary field | Server field retained; ordinary field updated |

## Project Policy Conclusion

The event tests remain useful for documenting SurrealDB rollback behavior, but ReBase no longer needs mutation events for ordinary resource ownership or resource-specific governance.

The uniform model is:

- Table permissions determine which existing and resulting rows the actor may update.
- The `owned_by` field permission uses `$before` and `$value` to stop parent-group members from taking ownership while permitting no-op writes, owners, and dominators.
- Denied ownership writes are intentionally silent and may coexist with successful ordinary-field writes.
- Visibility, sending state, and compliance data are ordinary fields. They have no authorization rules beyond the table update permission.
- Secret, immutable, and server-managed fields retain their independent native field permissions.

Generated `rebase_guard_owned_by` events and the Brevo/campaign visibility or governance events are therefore removed. The client must inspect the returned row when it needs to confirm whether a silently filtered field changed.

## Reproduction

```bash
bash scripts/run-update-permission-probe.sh
```

## Verification Note

`npm run build`, `npm run check`, and the complete unit suite pass with the uniform policy. The smoke flow successfully deploys the compiled schema and completes authentication and transaction checks, then reaches the pre-existing scenario generator failure where `test_relation.readers` contains a nested empty array that cannot coerce to `array<record<user | groups>>`. That failure is unrelated to ownership permissions and remains outside this change.
