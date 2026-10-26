# Authenticated backend

The service opens one existing store for one selected compiled model and serves
the authenticated HTTP API. Its only binary invocation is
`rebase-next serve /absolute/service.json`; `rebase-next host` starts the native
line-framed protocol. Both bootstrap paths are being accepted as part of N6, so
this guide describes the frozen configuration and protocol contract, not an
accepted deployment release. Calculation, equipment, invoicing, measurement,
effect-demo and quantity are explicit model choices. The [G10 program](../research/56-node-and-index-redesign-program.md)
records current acceptance status and evidence boundaries.

Generate an issuer key with an existing tool; never use public test fixture keys:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out issuer-private.pem
openssl pkey -in issuer-private.pem -pubout -out issuer-public.pem
```

Start from a backend-specific [service configuration](../deploy/server.example.json)
and replace every `REPLACE_WITH_` value and the example store UUID. The JSON
shape is explicit and shared by every backend:

```json
{
  "format": "rebase-service-1",
  "model": "calculation",
  "backend": {"kind": "redb", "cluster_file": null},
  "target": {"mode": "open", "path": "/var/lib/rebase-next/app.redb", "expect_store": "REPLACE_WITH_CANONICAL_STORE_UUID"},
  "service": {"listen": "127.0.0.1:8080", "identity": {"issuer": "REPLACE_WITH_ISSUER", "audience": "REPLACE_WITH_AUDIENCE", "public_keys": {"REPLACE_WITH_KEY_ID": "REPLACE_WITH_ED25519_PUBLIC_PEM"}, "max_token_seconds": 600}, "max_inflight": 16, "request_timeout_seconds": 15, "effects": null}
}
```

The `target` must use `mode: "open"`, an absolute embedded-store path or a
nonempty FoundationDB namespace, and the canonical UUID expected for that store.
The server does not create or reset stores. It fails closed if the opened store
identity or model differs. Give one process exclusive ownership of an embedded
store while serving it.

An existing identity service can issue the supported profile. A token request
has these fields:

```json
{"tenant":"00000000-0000-4000-8000-000000000001","actor":"00000000-0000-4000-8000-000000000002","epoch":0,"ttl":300,"key_id":"main"}
```

Keep the private key outside the server; it needs only verification public keys.
Supply the token as `Authorization: Bearer <token>`
on `POST /rpc`, with `Content-Type: application/json`. Use the structured methods
in the [operation guide](local-prototype.md), plus `session.describe {}`,
`access.describe {model}` and `access.replace {model,if_revision,graph}`. The last
two require a current administrator. Graph changes are compare-and-set operations;
reconcile a lost result by reading current graph/revision before retrying.

Call `session.describe {}` before constructing mutations and include its
`operation_context` as the required `context` field. Retain this original value
with the operation ID for retries and `operations.status`. See
[storage lifecycle](storage.md) for verified backup/restore, reset and fenced
receipt archiving. Never refresh an uncertain request's context to evade expiry.

The token is a deliberately narrow standard JWT profile: `alg=EdDSA`, `typ=JWT`,
configured `kid`, and exactly `iss`, `aud`, canonical UUID `sub` and `tenant`,
integer `epoch`, `iat`, `nbf`, `exp`. Issuer/audience/signature/expiry/not-before,
maximum lifetime and duplicate keys are checked. This is not an interactive
login or a general OIDC identity-token endpoint. A trusted issuer maps verified
identity to these service credentials. Roles are never accepted from a token.
Publish overlapping key IDs for rotation, change the issuer configuration and
restart; remove old keys after the token window. Increment a principal's epoch
or disable it for store-backed revocation on the next request. Reactivation
requires a higher epoch. An already authorized overlapping read may finish.

Reads use fresh graph scopes from the same snapshot as their data. Writes protect
that authority in the serialized redb transaction. Reader/contract partitions
are merged in UUID order, with at most 1280 opened streams; no unauthorized
contract is used as a candidate source. Scalar residual predicates still consume
visit budget. Any committed domain or graph mutation invalidates cursors.
Receipt keys include actor identity. Replay/status suppress a stored projection
if the record is no longer readable at that version; a committed receipt remains
a committed receipt. Receipt absence is not proof that a request failed.

HTTP requests are limited to 65536 bytes. Admission is bounded to 1–64 blocking
workers, including cryptographic verification; excess admitted work returns 429.
A deadline returns an unknown-outcome JSON-RPC error, **not** a promise of
rollback. Blocking work keeps its permit until it really finishes. Retain and
reconcile the same operation ID. SIGINT/SIGTERM drains accepted work.

`GET /health` is a public liveness response only. It certifies neither storage
integrity nor a particular actor's access. No developer inspector, raw KV write,
private contract, token issuer or fixture bypass is exposed by HTTP. RPC batches
and notifications remain unsupported. Replies use `Cache-Control: no-store`.

Terminate TLS and apply connection/header/body-read timeouts and request-rate
limits at a supported reverse proxy before exposing this process to a public
network. Default binding is loopback; an explicitly configured private-container
address can be used behind that proxy. Forwarding actor headers does not grant
authority. A JWT bearer credential is required on `/rpc` regardless of proxy.

Axum/Tokio supply HTTP transport; the Rust library retains the strict JSON-RPC
dispatch shared by its HTTP handler and native host implementation. The binary
exposes only `host` and `serve`; it has no public stdio RPC process. A second
jsonrpsee parse/dispatch layer would add no operation semantics to this API. JWT
cryptography uses jsonwebtoken's AWS-LC provider. The
alternative RustCrypto feature pulled unpatched `rsa` (RUSTSEC-2023-0071), even
though this service only accepts Ed25519; it is absent from the selected graph.


`service.effects` is either `null` or the existing native fake-effects
configuration for effect-demo. The signed ingress example is a separate Node
composition and does not extend the public barrel or service configuration.
See [external work](external-effects.md) for captured authority, durable ACKs,
shutdown/retry behavior and reconciliation-only restored stores.
