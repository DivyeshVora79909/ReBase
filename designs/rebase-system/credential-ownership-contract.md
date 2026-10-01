# Credential ownership and use contract (K4a)

This is a design contract for the existing `rebase_email_delivery_config` and
`rebase_sms_delivery_config` tables. It does not add a provider DSL, platform
key family, automatic default, or credential-policy hierarchy. `rebase_group:root`
is an authorization owner in the application graph, not a SurrealDB root login
or a bypass for native `PERMISSIONS NONE` (see
[`core-handoff.md`](./core-handoff.md#requirements-that-override-older-plans),
lines 30–52).

## Actor and action matrix

| Actor and action | Required contract | Current exact access and gap |
|---|---|---|
| Anonymous caller: direct read/create/update/delete of either credential table, or read of any secret field | Deny all actions. No credential table or secret field is exposed to anonymous callers. | Both credential tables and every typed field are declared `PERMISSIONS NONE` in [`framework/authentication.surql`](../../framework/authentication.surql#L13-L33). This is the native deny boundary, but no live authorization probe was run for this K4a documentation task. |
| Developer with the trusted system connection: provision platform credentials and choose deployment bindings | Permit trusted provisioning of typed email/SMS credentials and selection of the fixed deployment binding. Provisioning and binding are developer/deployment actions; they do not create provider accounts, defaults, tenants, or organizations. | The current config tables are native-private; [`rebase_authentication_delivery_policy`](../../framework/authentication.surql#L35-L41) is also `PERMISSIONS NONE`. The anonymous challenge path reads its fixed `:default` row and loads the selected config through the server store ([`gateway/authentication.js`](../../gateway/authentication.js#L238-L243), [lines 333–363](../../gateway/authentication.js#L333-L363)). Whether `options.stores` is backed by a sufficiently privileged system connection is not established by the inspected files and remains unverified. |
| Platform-config client visibility and use | `rebase_group:root` credentials remain completely invisible and unwritable to clients, including non-secret metadata. An explicit operation may use a developer-provisioned fixed platform binding; callers do not supply a root credential ID. The trusted worker verifies operation and caller authority, resolves the fixed config, verifies root ownership, then loads its secret. | Existing auth binding stores email/phone config references and rejects deletion of referenced configs; credential ownership and root-scoped use are not present in the native table definitions. See [`framework/authentication.surql`](../../framework/authentication.surql#L10-L41). |
| Authenticated tenant/user administrator: create or manage a BYOC credential | Treat a BYOC record as owned by that user/group for authorization and operation use. An authenticated owner or explicit delegate may create/update its secret through narrowly scoped write-only fields and manage authorized metadata. Secret SELECT is always denied; generic row returns/audit/logs must not reveal it. The owner can use only its own or delegated config through a specific operation. | Native tables currently deny all client operations, so neither authorized BYOC use nor a controlled write-only management path is implemented. Ownership and native field/table policies must be added explicitly because framework tables bypass generated RLS. |
| Authenticated permitted consumer: invoke a specific operation with an authorized config reference | Permit the operation to resolve and use an authorized config without returning credential fields. The operation must check ownership/delegation or an explicit trusted deployment binding before using a config; an unrelated authenticated user must not turn the service into a confused deputy. | The auth recovery path reads the fixed binding, resolves an identity and recipient, and queues a task with a config reference. The private handler later loads the config and passes the provider key to the adapter, while returning only an operation outcome/reference ([`gateway/authentication.js`](../../gateway/authentication.js#L245-L290), [`gateway/operations/authentication-delivery.js`](../../gateway/operations/authentication-delivery.js#L21-L78)). This is specific to authentication recovery; it does not establish general CRM/HRM email/SMS delivery or authorization. |
| Anonymous challenge caller: request a recovery challenge | Caller may provide an identifier/channel request only. Trusted server logic chooses identity, recipient, channel, and the fixed deployment config; arbitrary record IDs, recipients, or config refs from the caller are not accepted. Keep uniform response, expiry, attempt limits, single-use, revision/nonce fencing, and encrypted atomic challenge/task creation. | The current implementation resolves `rebase_authentication_delivery_policy:default`, finds identity records server-side, selects a configured channel, and enqueues a task containing references; the request path shown does not accept a credential/config record ([`gateway/authentication.js`](../../gateway/authentication.js#L238-L290), [lines 327–364](../../gateway/authentication.js#L327-L364)). The handler checks task/identity/challenge consistency and expiry before delivery ([`gateway/operations/authentication-delivery.js`](../../gateway/operations/authentication-delivery.js#L21-L77)). Source inspection only; spoofing was not probed. |

## Existing policy boundaries and required small changes

- Compiler framework discovery parses every table from framework source into
  `frameworkTables` ([`dev-tools/compiler/pipeline.js`](../../dev-tools/compiler/pipeline.js#L40-L68)). The security generator skips tables in
  `systemTables` before emitting ownership/RLS and otherwise preserves native
  `PERMISSIONS NONE` ([`src/generators/security.js`](../../src/generators/security.js#L36-L59)). Therefore adding `owned_by` or keeping a table under
  `framework/` does not install authorization for these credentials.
- Keep these two typed credential families. Add explicit native policies or a
  small targeted permission helper for ownership-aware BYOC writes and use.
  Keep secret fields out of SELECT and general audit/log projections. Root
  platform records remain wholly hidden from clients; only the trusted
  operation boundary can resolve a fixed deployment binding. Do not broaden a
  framework-wide system-table bypass.
- Secret storage uses ordinary stored fields with field-level SELECT denied;
  do not represent a secret as `COMPUTED` or `VALUE`. SurrealDB's official
  [DEFINE FIELD reference](https://surrealdb.com/docs/reference/query-language/statements/define/field)
  documents the pre-3.3 computed-field copy-out warning. The raw stored-field
  behavior relied on here is separately exercised against SurrealDB 3.2.0 in
  the K4b disposable regression evidence below.
- Keep the existing fixed authentication binding as a deployment binding, not
  a generic credential policy system. Permit its use only from the trusted
  operation path. Platform `rebase_group:root` configs are resolved from a
  fixed deployment binding; their owner value alone is not authority for
  anonymous or unrelated users, and clients cannot query or select their IDs.
- For BYOC operations, authorize the requested config against the authenticated
  principal's current ownership/delegation before the privileged worker loads
  the full record. Never return credential fields. Platform-use operations take
  no client-selected config reference; the trusted worker resolves and checks
  the bound root config after verifying the operation and caller role.
- User identity does not require a business organization. Existing
  `authentication_email` and `authentication_phone` rows point to
  `rebase_user` principals and have no mandatory organization reference
  ([`framework/authentication.surql`](../../framework/authentication.surql#L43-L49),
  [lines 80–91](../../framework/authentication.surql#L80-L91)). Do not add an
  organization prerequisite to credential ownership or authentication.

## Focused K4b acceptance cases

1. Anonymous direct SELECT/CREATE/UPDATE/DELETE is denied. Root-owned platform
   records are fully hidden and unwritable to clients. Secret SELECT is denied
   for all actors; BYOC secret create/update is available only to owners and
   current delegates, without exposing the value in mutation results.
2. A trusted developer/system connection can provision each typed config and
   set the fixed deployment binding. Platform config SELECT/CREATE/UPDATE/
   DELETE, including metadata, is denied to clients. An authorized operation
   uses the fixed `rebase_group:root` config without accepting a client-selected
   ID.
3. An authenticated owner can create/update BYOC secrets through write-only
   fields and read only permitted metadata. Explicit delegates may do the same
   within their current scope. A different user cannot read, update, or use it;
   replacing/spoofing the config reference in another context is rejected.
4. The operation can send through local mock email and SMS adapters without
   returning, auditing, queueing, or logging secret values. Cover root-shared
   and BYOC records with the same operation contract.
5. Anonymous challenge input cannot choose a recipient, identity record, or
   config record. Preserve challenge expiry, attempt ceiling, single use,
   revision/nonce fencing, uniform responses, and atomic encrypted task creation.
6. A user with verified auth identity and no business organization can use
   authentication normally; organization identity remains optional and
   independent of authorization ownership.

The actor/action matrix began as K4a source inspection and was refined for
root-hidden platform records and BYOC write-only owner updates. K4b implementation
and the scoped checks are recorded in
[`2026-09-29-k4b-credentials.json`](./evidence/2026-09-29-k4b-credentials.json).
The checks establish the tested local mock path, and K5 integration passed on
the same recorded snapshot. Live provider delivery and production rollout
remain open.
