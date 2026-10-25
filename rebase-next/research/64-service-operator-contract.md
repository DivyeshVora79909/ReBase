# N2 — service, model and operator extension

Frozen implementation decisions, 2026-10-25; **N2 pending acceptance**. Extends
[N1](60-native-host-contract.md) without changing its protocol, framing, public
RPC, engine semantics or persisted formats. [Wire fixtures](fixtures/n2-native-protocol.json)
freeze the new object shapes. N2a is service/model/identity; N2b completes operator
and optional-adapter trials. Neither milestone alone accepts N2.

All new objects reject unknown fields. Every privileged operation requires its
exact method in configured `operator_methods`, then the current native
`scope:{model:<hash>,store:<UUID>}`. Grant denial precedes target disclosure.
Scope is checked again on every operation. Request IDs remain correlation only.
No public method is added to `rpc::dispatch` or HTTP. Node `openOperator` narrows
an existing host's methods/scope; it never opens another store.

| Method | Exact params | Result |
| --- | --- | --- |
| `model.explain` | `{selector:string}` | Existing `Prepared::explain` value |
| `model.validate` | `{code:u16,input:object}` | `{status:"valid",model,input}` after native validation |
| `model.render` | `{scope:"model"}` or `{scope:"store",target:{model,store}}` | `{model,html}` or `{model,store,html}`; store view requires `store.inspect` grant |
| `fixture.catalog` | `{}` | Existing binding fixture catalog |
| `fixture.plan` | `{name:string,namespace:UUID}` | Existing binding fixture plan |
| `service.start` | `{scope,config:ServerConfig}` | `{status:"started",service:UUID,address:string,endpoint:string,scope}` |
| `service.stop` | `{scope,service:UUID}` | `{status:"stopped",service}` |
| `identity.issue` | `{scope,identity:IdentityConfig,request:TokenRequest,private_key_pem:string}` | `{token:string}` |
| `store.backup` | `{scope,destination:absolutePath}` | Existing native backup metadata |
| `store.archive` | `{scope,destination:absolutePath}` | Existing native archive metadata |
| `store.reset` | `{scope,expect_store:UUID}` | Existing native reset metadata |
| `store.restore` | `{scope,backup:absolutePath,expect_backup_store:UUID,destination:{backend,target}}` | Existing native restore metadata |

`ServerConfig` retains native `listen`, `identity`, `max_inflight`,
`request_timeout_seconds`, optional `effects`. It has no implicit listen/identity/
concurrency/deadline defaults. Native validation, including keys and experimental
fake-provider settings, finishes before bind/worker activation. One bound service
per host; repeated start is `service_running`. Readiness follows validation,
bind and worker initialization. It returns actual socket address, including an
OS-selected port. A service shares the host's **same `Arc<Store<B>>`**. Inspection
and verified backup use that owner while live; no second embedded open occurs.

Stop requires the exact service UUID and current store scope; mismatch is
`wrong_target`. It stops admission, signals HTTP/effect work, awaits HTTP, waits
for admitted blocking work even after client timeouts, joins workers, disables
worker activation and only then releases service ownership. Close/EOF/SIGTERM
perform the same stop/join before dropping the store. Shutdown deadline is the
Node owner's explicit budget; if exhausted it may kill only its child and must
report unresolved effects as unknown. Native never certifies rollback from a
lost response. No detached operation is treated as cancelled merely because its
HTTP deadline expired.

Identity uses existing native `identity::issue` and its EdDSA verification profile.
The request tenant must match the scoped store, and `Store::session(actor,epoch)`
must authorize the current principal before issuance. Private PEM is bounded to
4,096 bytes and travels only through private IPC, never echoed or logged. Node
uses `node:crypto` Ed25519 key generation and public PEM configuration. No Node
JWT implementation or native signing key file is introduced.

Native backup supports its existing 64 MiB bound and explicit caller destination;
only metadata returns through the 8 MiB response envelope. Archive and reset
require service stopped (`service_running` otherwise). Archive publishes a
verified create-only backup before native transaction cleanup/epoch advance.
Reset requires both current scope UUID and identical `expect_store`; its fresh
UUID invalidates every old scope and credential generation. No automatic retries.

Restore requires a stopped service, explicit backup identity and create-only new
destination. Validate/checksum the backup and expected backup UUID before any
requested destination is opened. The model is the host's selected compiled model.
The destination backend object is `{kind,cluster_file}`; `target` is exactly
`{path:absolutePath}` for redb/SurrealKV or `{namespace:string}` for FoundationDB.
It cannot equal the live host target, including canonical path aliases. The
existing native restore performs full integrity validation, effect quarantine
and atomic publication. Restored stores retain native receipt/store identities;
opening an isolated clone is explicit and does not make original unknown requests
safe to refresh. Optional-backend destination creation follows backup validation;
nonempty namespace/directory publication rejects without replacing existing data.

Configuration extends backend enum to compiled `redb`, `surrealkv`,
`foundationdb`. File backends retain `target.path`; FoundationDB uses
`target.namespace` (UTF-8, nonempty, at most 1,024 bytes) and its existing SHA-256
logical-namespace encoding. FDB requires an explicit absolute `cluster_file`;
redb/SKV require null. SDK environment/default discovery is not used by the host.
Host availability reports actual compiled adapters. Native FDB
network lifetime is process-owned and outlives every database/task.

Redb/SKV create is exclusive; open requires expected store UUID. FDB create uses
one protected native transaction against an empty namespace. Multiple FDB hosts
may share one logical store under its existing transaction/conflict contract;
embedded ownership remains exclusive. Redb normal open keeps N1's read-only
preview and refuses recovery. Explicit target `mode:"recover"` requires the
`store.recover` capability and `expect_store`. Recovery authorizes native file
maintenance before UUID can be read; mismatch prevents semantic dispatch but
cannot promise byte immutability after recovery. SKV open authorizes its normal
WAL recovery, then verifies model/store before dispatch. SKV has no public native
read-only preview; its wrong-open guarantee concerns semantic state, not physical
maintenance bytes. FDB checks identity in a read transaction. No adversarial
filesystem isolation or multi-host performance claim is made.

For FoundationDB, expected store UUID and authority checks must be read from the
same transactional snapshot that supplies the published backup/inspection or
credential/service-validation result. A preflight UUID check alone does not fence
a concurrent reset. Archive validates the complete captured image digest before
publication/cleanup, so a reset after snapshot capture cannot authorize an
archive of a different generation. The native executable retains one FDB
network owner at process/Host scope across failed configure attempts and retries;
independent embedded FDB Host owners in one process are unsupported by the SDK.

Node `savePlan` publishes write-once using a private temporary file, file sync,
link and directory sync. If publication succeeds but directory durability or
temporary cleanup cannot be confirmed, it returns a distinct error carrying
whether the destination was published. The caller must retain and reconcile the
target and any temporary residue; it must not delete or retry as if publication
had failed. Private PEM key material is passed only to the scoped identity
operation and is not copied into plan files or automatic inspection output.

New fixed host error kinds are `service_running`, `service_not_running`, and
`invalid_destination`; existing safe native errors preserve uncertain outcomes.
Model/fixture APIs are local developer metadata, with no stored-state disclosure
unless the explicit inspection grant and target scope permit it. All returned
HTML is data, not shell redirection or a host-created file.

Acceptance requires real same-owner HTTP mutation/inspection, key issuance,
public/private denial, stop/close join, original-intent receipt replay, archive/
reset fences, wrong scopes without operation side effects, isolated restore,
create-only refusal, effect quarantine, compiled backend reporting and real
available FDB/SKV target trials. Record actual commands, artifact/source hashes,
owned infrastructure and cleanup. Reuse unaffected semantic evidence; do not
repeat historical capacity campaigns or claim unexecuted adapter coverage.
