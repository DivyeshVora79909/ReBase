# N0 — structured native host contract

Decision date: 2026-10-25. This freezes the initial implementation contract for
[N1](56-node-and-index-redesign-program.md#checkpoint-graph-and-current-status).
**The control host is not implemented or accepted at N0.** The read-only native
trial below establishes reusable exports, identities and output sizes; it does
not establish IPC, ownership or service acceptance. The machine-readable wire
examples are [n0-native-protocol.json](fixtures/n0-native-protocol.json).

## Boundary and checkpoint size

Use one Rust executable with a fixed `host` bootstrap argument, inherited private
stdin/stdout pipes and ordinary object dispatch. Node uses
`spawn(binary, ['host'], {shell: false, ...})`; it never reconstructs historical
CLI commands or parses their human output. A host owns one prepared compiled
model and at most one store. Its configuration is immutable after successful
configuration. No dynamic model code, JavaScript calculation engine, shell,
arbitrary subprocess, raw KV access or public operator endpoint is introduced.
Production Rust service bootstrap remains directly usable without Node.

N1 implements only `host.describe`, `host.configure`, `model.catalog`,
`store.check`, `store.inspect`, and `host.close`. All six compiled models work in
model-only mode; initial store ownership is redb only. This is a small native
module and transport plus the Node owner, not a port of every operator action.
Optional backends are reported as compiled availability and initial host support
separately. Configuring an unsupported host backend fails before opening anything;
it never silently falls back to redb. The existing direct backend implementation
remains authoritative while host ownership for it is completed at N2.

N2 extends the allowlist with model explain/validate/render, fixture catalog/plan,
controlled service start/stop, token issuance and scoped backup/restore/archive/
reset. It adds FoundationDB and standalone SurrealKV target ownership and recovery
controls before claiming their host coverage. N5 adds package/source/build
metadata and extracted-artifact verification; Cargo/archive/file composition
stays ordinary Node functions. Neither checkpoint may tunnel a generic CLI verb
or privileged method through public RPC. New method schemas and fixtures are
accepted at their checkpoint; N1 does not advertise them as enabled.

## Frozen wire v1

Every frame is a UTF-8 JSON object terminated by exactly one LF. The protocol is
`rebase-native-host-1`, independent of native API/store/codec identities. Request:
`{"protocol":"rebase-native-host-1","id":"r1","method":"host.describe","params":{}}`.
Response: the same `protocol` and `id`, and exactly one `result` or `error`.
`error` has exactly `kind` and a bounded, fixed safe `message`. No JSON-RPC numeric
codes are invented for this private wire. Public HTTP retains its existing
JSON-RPC 2.0 envelope and errors unchanged.

All envelope and typed parameter objects reject unknown keys. IDs match
`[A-Za-z0-9._:-]{1,128}`. Methods match the allowlist exactly. No notifications,
batches, unsolicited stdout events or ID reuse within a host lifetime. Node
assigns increasing decimal IDs with a caller-owned session prefix. Only one
request is outstanding; Node serializes requests, and the host dispatches in
input order. ID uniqueness is the caller's obligation; the host retains only its
current correlation ID, not an unbounded request-history set. A second already-
buffered frame is not concurrent execution.

The native constants are 65,536 request bytes and 8,388,608 response bytes,
**excluding LF**, and one outstanding request. These are hard transport bounds,
not mutable JavaScript configuration. Reuse `json::MAX_REQUEST_BYTES` for input;
add a named native response bound. Decode with `json::parse` after bounded frame
assembly: reject duplicate keys at every depth, trailing documents, invalid UTF-8
and non-JSON values. A bounded writer limits serialization before writing any
response bytes; oversized results become `response_limit`. There are no partial
JSON frames, truncation, automatic paging or hidden filesystem spill files.
Large inspections can therefore reject even when the store itself is valid.

An oversized input is drained through the next LF with bounded memory, emits
one `request_limit` error with `id:null`, and resumes framing. A malformed JSON
frame emits `parse_error` with `id:null`; an invalid typed envelope emits
`invalid_request`, correlated only when a unique valid ID was parsed safely.
Unsupported protocol emits `protocol_mismatch`. A nonempty unterminated frame at
EOF emits `parse_error`, then closes; clean EOF closes without a frame. Blank
lines are malformed frames. CR is JSON whitespace and counts toward the limit.
No data from a rejected frame reaches dispatch. Responses always carry v1,
including version errors. Node rejects malformed/duplicate/oversized responses,
unknown IDs and extra envelopes as a transport failure and closes its owned host.

The fixed host errors are `parse_error`, `invalid_request`, `protocol_mismatch`,
`request_limit`, `response_limit`, `method_not_found`, `not_configured`,
`already_configured`, `invalid_config`, `unsupported_backend`, `wrong_target`,
`forbidden`, `store_busy`, `recovery_required` and `internal`. Existing native
operation errors retain their safe `Error.code` where exposed, with the safe
message policy used by `rpc::failure`; private backend error strings and secrets
stay out of frames. A transport error, killed child or lost response never proves
rollback. N2 side-effecting methods must preserve `outcome_unknown`, the original
operation ID/request/context and reconciliation requirements. Response IDs are
transport correlation only; they are never mutation operation IDs.

Stdout contains protocol frames exclusively, from bootstrap to final close.
Diagnostics go to stderr; omit credentials, PEMs, raw requests and signing state.
The Node owner drains stderr even when no subscriber consumes diagnostics,
retains only its configured byte budget and redacts before exposing diagnostics.
It does not use stderr text as readiness, a method result or a capability source.

## Configuration, targets and methods

`host.describe({})` is available before and after configuration. Its exact top
level result keys are `protocol`, `state`, `engine`, `configuration`,
`capabilities`, `selection`, and `ownership`:

- `engine`: package version, API identity, store format, native codec and effect
  codec from Rust constants; compiled model selectors and compiled backend names.
- `configuration`: strict native JSON schema, fixed defaults and source metadata
  for native configuration. Native host settings have no implicit defaults;
  Node's explicit defaults/precedence registry is described in [paper 61](61-node-tooling-contract.md).
- `capabilities`: framing bounds; currently implemented host methods; supported
  host backends; selected public model capabilities after configuration, otherwise
  `null`; mutation work and backup byte limits with their Rust source constants.
- `selection`: `null` while unconfigured; otherwise selector, prepared model
  identity, backend and target descriptor. Model identity is the native hash,
  never a selector, binary hash or a JavaScript recomputation.
- `ownership`: `null` without a store; otherwise store UUID and exclusive owner
  mode. Do not export cursor signing keys, raw runtime headers or private state.

`host.configure(params)` requires exactly `model`, `backend`, `target` and
`operator_methods`. `model` is one of `calculation`, `equipment`, `invoicing`,
`measurement`, `effect-demo`, `quantity`. `backend` is exactly
`{kind:"redb",cluster_file:null}` in N1. The explicit null prevents inherited FDB
configuration; unknown kinds/fields or a cluster file with redb reject. `target`
is exactly one of:

- `null`, preparing only the model, with `operator_methods:[]`;
- `{mode:"create",path,tenant,actor}` for a new secured redb store;
- `{mode:"open",path,expect_store}` for an existing secured redb store.

Paths are nonempty absolute paths without NUL, bounded to 4,096 UTF-8 bytes.
No default path, current-directory inference, directory creation or environment
lookup occurs in Rust. UUIDs are canonical lowercase hyphenated strings. Create
requires valid tenant/actor UUIDs; open requires the expected store UUID.
`operator_methods` is a unique subset of `store.check` and `store.inspect` and is
the complete capability grant for this local handle. A configured target can
have no operator grants. N1 has no credential, service, effect-worker or secret
configuration. Unexpected settings fail, including apparently valid settings
for a later checkpoint. No successful reconfiguration is permitted.

Validate the complete typed config, bounds, model preparation, backend support,
grant set and target shape before acquiring a writable DB, creating a file,
binding a listener or activating workers. Failed syntactic configuration leaves
the host unconfigured so the owner can correct it or close. For existing redb,
read-only preview checks model/store format and expected store UUID **before**
writable open, then rechecks under the acquired native owner to close replacement
races. Initial N1 refuses `RepairAborted` as `recovery_required`; it does not
silently perform allocator recovery before identifying an expected target.
Crash-recovery coverage is deferred to the explicit N2 recovery control. Create
uses exclusive `create_new` and never truncates an existing destination. Errors
after valid create begins may leave an owned incomplete file; report failure,
release ownership and never silently delete/retry an uncertain creation. Tests
distinguish invalid-config rejection from a valid request's I/O failure.

Configure returns exactly `{status:"configured",model,target,operator_methods}`.
`model` is the native identity; `target` is null or `{path,store}`, with the
canonical absolute path and actual store UUID, and grants are sorted. The
selection and capabilities are then available from `host.describe`.

`model.catalog({scope:"public"|"developer"})` requires configuration and returns
the corresponding existing native catalog unchanged. Private pipes allow the
developer scope; authenticated public sessions still receive only the public
catalog. Do not manufacture a second list of schemas, operations or limits.

`store.check({scope:{model,store}})` and
`store.inspect({scope:{model,store}})` require a configured store, their exact
configured grant, and matching native model hash/store UUID on every request.
There is no per-call path or backend override. Wrong model or store returns
`wrong_target` before method execution; absent grant returns `forbidden` without
revealing whether a supplied identity exists. They return `Store::check_integrity`
and `Store::inspect` values unchanged. Inspection exposes the trusted local
developer view, never `observe_for_verification` or its signing material.

`host.close({})` is available in either state, stops admission, finishes admitted
work, closes owned resources, writes `{status:"closed"}`, flushes and exits zero.
It grants no domain/operator capability. EOF and signals use the same cleanup
path; they emit no synthetic close response. Repeated JavaScript `close()` calls
await one shared close promise; they do not send to an exited child.

## Reuse and lifecycle invariants

| Responsibility | Existing authoritative source anchor | N1 change needed |
| --- | --- | --- |
| Compiled model choice | [bin dispatch](../src/bin/rebase-next.rs#L107), [Binding](../src/binding.rs#L52) | One typed selection dispatch; do not invoke CLI `run_model`. |
| Prepare identity/catalog | [Prepared::load](../src/model.rs#L219), [identity](../src/model.rs#L636), [public/developer catalogs](../src/model.rs#L715) | Call ordinary functions, return their values. |
| Hard model bounds/methods | [model_capabilities](../src/model.rs#L763), [Binding::limits](../src/binding.rs#L60) | Export existing model capabilities; report additional named native constants. |
| Strict JSON and frame discipline | [json::parse](../src/json.rs#L79), [rpc::serve](../src/rpc.rs#L204) | Reuse strict parser and bounded drain pattern; private envelopes and bounded output. |
| Public semantic dispatch | [rpc::handle](../src/rpc.rs#L175), [HTTP call/session](../src/server.rs#L56) | No operator branches here. N1 has no public-call tunnel. |
| Backend selection | [BackendKind/BackendTarget](../src/storage/target.rs#L9) | Strict typed host adapter; feature availability separate from host support. |
| Secured create and exclusive file | [create_redb_database](../src/local.rs#L234), [create_secured](../src/security.rs#L271) | Reuse exclusive creation; no unguarded `Database::create` shortcut. |
| Store identity and open | [Store::open](../src/local.rs#L329), [read_header](../src/local.rs#L990) | Add expected-store read-only preview and under-owner check in library scope. |
| Check/inspect | [check_integrity](../src/local.rs#L231), [inspect](../src/local.rs#L823) | Scope/grant guards only; no new semantic implementation. |
| Native error outcomes | [redb commit](../src/storage/redb.rs#L202), [safe public errors](../src/rpc.rs#L122) | Preserve unknown outcomes and redact backend details. |
| Lifecycle, N2 | [backup/archive/reset](../src/lifecycle.rs#L82), [restore](../src/lifecycle.rs#L257) | Reuse native transactions/fences and new-destination publication. |
| Service, N2 | [router](../src/server.rs#L193), [serve](../src/server.rs#L236) | Extract controlled bind/readiness/shutdown seam from existing serve loop. |

Line fragments identify inspected source positions, with function names as stable
anchors. Rust types reused directly include `Prepared<B>`, `Binding`,
`BackendTarget`, `BackendKind`, `Store<B>`, `Context`, `RuntimeHeader` internally,
`ServerConfig`, `IdentityConfig`, `TokenRequest`, and `Mutation`. Only wire/config
DTOs are new. Do not export generic transactions or database handles to JavaScript.

One host retains the sole `Arc<Store<B>>` owner; later HTTP handlers, effect workers
and operator methods share it. Operator handles are granted views over this host,
never separate redb opens. Independent concurrent host/process opens must fail
using the native redb lock; the host normalizes lock errors to `store_busy`.
Hold ownership until all admitted work and service/worker tasks finish. Scope
checks read current header identity, so N2 reset invalidates old handles even
though a path and prepared model remain the same.

N1 may use a synchronous bounded loop; it performs no async service work. At N2,
stdio blocking reads/writes run on owned blocking tasks or dedicated threads with
bounded channels. Database work runs on `spawn_blocking`, retaining its admission
permit and store Arc until it actually finishes, as HTTP already does. Never block
the async executor with `stdin().read_line`, drop a blocking worker as if cancelled,
or serialize Rust locks across `await`. Service readiness is a structured reply
after listener bind and initialization, including its actual bound address.
It is not a successful process spawn or a line of stderr.

Abort before dispatch can reject locally. After dispatch, an abort only stops the
caller's wait; the owner drains the admitted response and keeps framing synchronized.
It cannot revoke committed work. Close is ordered after admitted requests. A
configured close deadline may terminate only the owned PID; classify unresolved
side effects as unknown and retain original requests. No kill-by-name, borrowed
listener shutdown or cleanup of another process's files is allowed. Graceful
service stop joins HTTP, effects and blocking attempts before dropping the store.

N2 operator scope includes explicit granted method plus current store/model UUID
guards; restore uses a new destination and is unavailable while it would reopen
the live embedded target. Archive retains the published verified backup and uses
the native operation-epoch fence; reset requires the native expected-store UUID;
restored effects remain quarantined according to the existing engine. Tokens or
public permission grants cannot grant these operator methods. An HTTP request
named `store.inspect` or `host.configure` remains `method_not_found`.

## Real N0 feasibility and remaining evidence

Read-only execution on 2026-10-25 used
`target/verification-build/release/rebase-next`, SHA-256
`cf9a5ccf864f362f717da9e441d62845981b4e4c7276de9349f43cb83e392b38`, matching
the retained G8 all-feature `target/g84-package-all/BUNDLE.json` binary hash.
It requires explicit `LD_LIBRARY_PATH=target/g7-environment/lib` here; without it
the loader reports missing `libfdb_c.so`. With that library path, `version` and
all six model public/developer exports succeed without opening a store.

| Model selector | Public export bytes | Developer export bytes | Public/developer contracts |
| --- | ---: | ---: | ---: |
| calculation | 27,865 | 43,411 | 10 / 12 |
| equipment | 13,045 | 22,325 | 3 / 4 |
| invoicing | 28,178 | 68,045 | 9 / 16 |
| measurement | 19,643 | 23,406 | 4 / 4 |
| effect-demo | 7,477 | 18,851 | 2 / 2 |
| quantity | 6,342 | 19,756 | 3 / 3 |

Each public export's exact bytes hash matches its retained bundle catalog hash.
The largest developer export fits the selected response limit; it exceeds the
request limit, which is why responses have a distinct bound. These are historical
engine exports executed now, not proof of a new host. No Cargo build, database,
network service or new native executable was created in this trial.

Rust 1.95.0 and Cargo 1.95.0 are installed in this environment; the environment
owner has exposed them through `/home/agent/.local/bin`. Existing build outputs
and the FDB client SDK exist. The source registry cache is initially absent from
the default Cargo home; the next Cargo owner must reuse/configure the supplied
cache or fetch locked dependencies. A default redb-only build avoids the FDB
dynamic loader dependency. Use one Cargo owner, two jobs, incremental off.

N1 acceptance must run the frozen fixtures against the real host and Node owner,
including split/coalesced input, exact/over-limit framing, duplicate keys,
malformed/truncated EOF, bounded result serialization, invalid configuration with
no created path/listener/worker, wrong-model/store guards, missing grants, same-
process and separate-process redb exclusivity, child exit, protocol-only stdout,
repeated close and clean reopen after closure. Snapshot hashes must demonstrate
wrong-target/invalid-config rejection before writable maintenance. A fake child
can test the Node owner's parser failures but cannot establish native acceptance.
N2 additionally proves authenticated HTTP cannot reach private dispatch, real
service readiness/stop, cancellation after dispatch, shared live-store inspection,
backup/archive/reset/restore and optional adapter ownership/recovery. N5 proves
the same controls through an extracted artifact. These obligations remain pending.
