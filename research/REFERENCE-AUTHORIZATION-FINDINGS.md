# SurrealDB Reference Authorization Findings

Status: measured architecture input

Tested version: SurrealDB `3.2.0` on x86_64 Linux with the in-memory datastore

Reproduction: `npm run probe:architecture`

## Decision

The default framework rule for a required client-supplied record reference is:

```surql
DEFINE FIELD config ON send_brevo_email
    TYPE record<email_brevo_config>
    ASSERT record::exists($value);
```

On the tested version, this simultaneously rejects:

- a nonexistent record ID;
- a physically existing record the authenticated client cannot select.

This is the desired default policy when “may use” is equivalent to “may see the
referenced configuration row”. It avoids a custom `fn::can_use_reference` for
ordinary references.

The provider configuration row should be selectable under normal row access,
while credential fields remain hidden:

```surql
DEFINE TABLE email_brevo_config ... PERMISSIONS
    FOR select WHERE <normal row policy>;

DEFINE FIELD api_key ON email_brevo_config
    TYPE string
    PERMISSIONS NONE;
```

The client can validate and reference the configuration without reading the API
key. A privileged handler can load the hidden field.

## Officially documented behavior

Official documentation guarantees that:

- `record<config>` restricts the record ID to the declared table type;
- record links can point to IDs and do not by themselves prove target existence;
- `record::exists(record)` reports whether a record exists;
- field `ASSERT` clauses reject values whose expression is false;
- field permissions narrow table permissions for record users;
- queries inside events always execute without permission checks.

The documentation does not clearly promise that `record::exists()` returns
false for an existing but unauthorized record in every evaluation context.
That exact behavior is therefore version-sensitive and probe-gated.

References:

- <https://surrealdb.com/docs/reference/query-language/functions/database-functions/record#recordexists>
- <https://surrealdb.com/docs/reference/query-language/statements/define/field>
- <https://surrealdb.com/docs/reference/query-language/statements/define/event#events-and-permissions>
- [RECORD-REFERENCES.md](./RECORD-REFERENCES.md)

## Measured client-session behavior

The probe creates:

- `config:alice`, owned by the authenticated user;
- `config:bob`, owned by another user;
- `config:missing`, which does not exist;
- `api_key`, hidden with field `PERMISSIONS NONE`.

From Alice's record session:

```text
record::exists(config:alice)   -> true
record::exists(config:bob)     -> false
record::exists(config:missing) -> false
```

Direct dereferencing behaves consistently:

```text
config:alice.owned_by -> principal:alice
config:bob.owned_by   -> NONE
config:alice.api_key  -> NONE
SELECT * FROM config:bob -> []
```

The important distinction is:

```text
row select permission controls whether the configuration row exists to the
client query

field select permission controls which values are visible after the row is
accessible
```

This supports visible metadata plus invisible credentials without a separate
secret-reference table for the common case.

## `ASSERT` findings

### `ASSERT record::exists($value)`

This accepted `config:alice` and rejected both `config:bob` and
`config:missing`.

Use it when reference usability is exactly the referenced row's client-visible
existence.

### `ASSERT $value.owned_by = $auth`

This also accepted Alice's row and rejected Bob's row. A denied or missing
record dereferences to `NONE`, so the equality is false.

This can express a stronger owner-only policy, but it duplicates the framework's
normal ownership rules if those rules are more than direct `$auth` equality.
Do not generate it as the universal default unless the intended policy is
actually direct ownership.

### Arrays and optional references

The same idea must be expressed for the field's cardinality:

```surql
DEFINE FIELD configs ON effect
    TYPE array<record<provider_config>>
    ASSERT $value.all(|$id| record::exists($id));

DEFINE FIELD fallback_config ON effect
    TYPE option<record<provider_config>>
    ASSERT $value = NONE OR record::exists($value);
```

Cardinality, uniqueness, and maximum array size remain separate assertions.

The permanent architecture probe now executes all three cardinalities from an
authenticated record session. Required, optional, and array assertions accept
accessible references and reject both hidden existing and missing references.

## Compiler policy

The compiler now emits a generated `ALTER FIELD ... ASSERT` for every top-level
record field declared in project schema material:

```surql
-- required scalar
ASSERT record::exists($value)

-- optional scalar
ASSERT $value = NONE OR record::exists($value)

-- arrays and sets, including optional containers
ASSERT array::all($value ?? [], |$reference| record::exists($reference))
```

If the developer already declared an assertion, the compiler combines it with
the existence invariant using `AND`; it does not discard domain validation.
An identical explicit existence assertion is kept once rather than duplicated.

Only root field definitions are parsed and altered. Nested record paths are not
generated. Untyped `record` and `option<record>` fields are supported as well as
`record<table>` fields.

Framework principal `parents` fields are the deliberate exception. They carry
the internal `@rebase-reference-delta` marker and retain their changed-edge
assertion, documented in [PARENTS-FIELD-FINDINGS.md](./PARENTS-FIELD-FINDINGS.md).

The generated policy is a SurrealDB-version compatibility boundary. Keep both
`npm run probe:architecture` and the security probe in upgrade verification.

## Field permissions are not validators

Do not replace an assertion with:

```surql
DEFINE FIELD config ON job
    TYPE record<config>
    PERMISSIONS FOR create WHERE record::exists($value);
```

The measured behavior is unsuitable for required-reference validation:

- an accessible existing reference was stored;
- a hidden but physically existing reference was also stored;
- a missing reference caused the field to be silently omitted rather than the
  record creation necessarily failing.

This also demonstrates that `record::exists()` cannot be assumed to have the
same permission perspective inside every schema clause. The direct client query
and field `ASSERT` were visibility-aware; the field create-permission predicate
accepted the hidden physically existing target.

Use field permissions to control who may write a field. Use `ASSERT` to define
what values make a valid record.

The permanent architecture probe also covers table write permissions:

```surql
DEFINE TABLE exists_write PERMISSIONS
    FOR create WHERE record::exists(config);

DEFINE TABLE owner_write PERMISSIONS
    FOR create WHERE config.owned_by = $auth;
```

`exists_write` accepts both an accessible target and a physically existing but
client-hidden target, while rejecting a missing target. `owner_write` accepts
the owned target and rejects both hidden and missing targets. Therefore a table
permission must carry the actual use/ownership predicate whenever the reference
itself is not meant to be client-visible. Existence alone is never an
authorization decision.

Field permissions remain filters, not validators: a false field permission can
silently omit that field while allowing the record itself to be created.

## Events are privileged

The event documentation explicitly states that queries inside events bypass
permissions. The probe confirms it:

- Alice created an effect record referencing `config:bob` on a field without an
  assertion;
- the synchronous event read Bob's hidden `api_key`;
- the event wrote that key into an admin-only effect field.

Therefore this is unsafe reasoning:

```text
the client triggered the event
  => every record the event can dereference was authorized for that client
```

The event is a privileged database program. It must receive already validated
references or perform an explicit authorization comparison using `$auth`.

The probe also confirms that a synchronous event can reject the unauthorized
reference with:

```surql
IF $after.config.owned_by != $auth {
    THROW 'REFERENCE_NOT_OWNED';
};
```

That works because the event intentionally uses its privileged read to compare
the target policy with the authenticated actor. It is not automatic permission
inheritance.

## Generated default policy

For ordinary effect/config relations, generate all of the following:

1. a strict `record<table>` type where the target tables are known;
2. the compiler-generated cardinality-appropriate existence assertion;
3. an appropriate `REFERENCE ON DELETE` action;
4. an immutable effect input field after submission where practical;
5. a selectable configuration metadata row;
6. `PERMISSIONS NONE` on credential fields;
7. a runtime loader that loads only declared root references.

Example:

```surql
DEFINE FIELD config ON send_brevo_email
    TYPE record<email_brevo_config>
    ASSERT record::exists($value)
    REFERENCE ON DELETE REJECT
    READONLY;
```

Whether `READONLY` is appropriate depends on the effect lifecycle. Immutable
async submissions should use it. Mutable sync grants should permit only their
explicit request fields and use generation checks.

## Completely invisible configurations

If the entire provider configuration row is unselectable, the default
visibility-based assertion correctly rejects its ID. Use one of these explicit
models instead of weakening every reference:

1. **Visible capability row, hidden secret fields — recommended.** Expose a
   harmless label/provider/account-state row and hide credentials field by
   field.
2. **Visible platform alias.** The effect references a visible alias such as
   `email_sender:platform_default`; the handler resolves it to a platform secret
   outside the tenant database.
3. **Generated synchronous use guard.** A synchronous validation event reads the
   invisible row with privileged access and explicitly compares `owned_by`,
   allowed users/groups, or another use policy with `$auth` before permitting
   the write. This must be synchronous even when a second async notifier performs
   the effect.
4. **Framework function/capability table.** Introduce `fn::can_use_reference`
   only after a real policy cannot be represented by normal row visibility or a
   generated ownership predicate.

Platform credentials that are not tenant-owned should generally use option 2
and should not be placed into every tenant database merely to create a record
reference.

## Runtime rules

- The worker reloads the committed effect record and declared references.
- It does not accept expanded config or secret objects from the queue envelope.
- The queue envelope contains `{ namespace, database, id }` only.
- The sync event snapshot contains referenced IDs, not secret contents.
- Provider webhook payloads never become trusted record locators merely because
  they contain an `id`; first verify the provider signature and correlation.
- An effect record's validated reference should be immutable after submission
  unless the table explicitly uses generation semantics.
- Reauthorization at execution time is a product choice. If revocation must stop
  pending work, the generated loader must re-check the current config/owner
  relationship. If submission creates a durable authorization decision, store
  that decision explicitly and keep the referenced inputs immutable.

## Upgrade and fallback policy

Because permission-aware `record::exists()` is not clearly guaranteed by the
official function reference:

1. run `npm run probe:architecture` before every SurrealDB upgrade;
2. pin the supported SurrealDB version in deployment tooling;
3. if behavior changes, replace the assertion with the framework's canonical
   ownership/readers predicate against a universally present field such as
   `owned_by`;
4. if the target must be invisible, use the synchronous explicit-use guard;
5. never fall back to type-only record references, because those allow dangling
   and unauthorized IDs.

The default remains `ASSERT record::exists($value)` while the version-pinned
probe passes.
