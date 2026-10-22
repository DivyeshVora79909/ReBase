# Authenticated backend

This network boundary serves one selected compiled model over one embedded
redb process. Calculation is the default; add `--model equipment` before `init`,
`serve` and other operator commands for equipment. Identity configuration and
the HTTP protocol are shared. It does not add a distributed backend or a full
accounting model. The [current result](../research/24-population-scaling-result.md)
and dated [release checkpoints](../research/17-deployable-backend.md) own acceptance.

Build with `cargo build --locked --release --bin rebase-next`. Generate your own
issuer key with an existing tool; never use the public test fixture keys:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out issuer-private.pem
openssl pkey -in issuer-private.pem -pubout -out issuer-public.pem
```

Create `server.json` with the **contents** of the public PEM as the JSON string
at `public_keys.main` (including its newline escapes):

```json
{
  "listen": "127.0.0.1:8080",
  "identity": {
    "issuer": "https://identity.example.com",
    "audience": "rebase-next",
    "public_keys": {"main": "-----BEGIN PUBLIC KEY-----\nYOUR KEY\n-----END PUBLIC KEY-----\n"},
    "max_token_seconds": 600
  },
  "max_inflight": 16,
  "request_timeout_seconds": 15
}
```

Initialize a new secured store with distinct canonical tenant/administrator UUIDs:

```sh
rebase-next init app.redb --tenant 00000000-0000-4000-8000-000000000001 --actor 00000000-0000-4000-8000-000000000002
rebase-next serve app.redb --config server.json
```

`init` does not overwrite a file. Network serving refuses a legacy local demo
store without authority. The HTTP process owns its file; do not start another
server/CLI against the same live redb file. Pure model tools need no store.

An existing identity service can issue the supported profile. The offline
operator helper accepts `token-request.json`:

```json
{"tenant":"00000000-0000-4000-8000-000000000001","actor":"00000000-0000-4000-8000-000000000002","epoch":0,"ttl":300,"key_id":"main"}
```

```sh
rebase-next auth issue server.json token-request.json issuer-private.pem
```

Keep the private key outside the server; it needs only verification public keys.
The helper prints a bearer token. Supply it as `Authorization: Bearer <token>`
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

Axum/Tokio supply HTTP transport; the existing strict JSON-RPC dispatch remains
shared with stdio. A second jsonrpsee parse/dispatch layer would add no operation
semantics to this API. JWT cryptography uses jsonwebtoken's AWS-LC provider. The
alternative RustCrypto feature pulled unpatched `rsa` (RUSTSEC-2023-0071), even
though this service only accepts Ed25519; it is absent from the selected graph.
