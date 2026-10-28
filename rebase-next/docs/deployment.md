# Deployment

N6 deployment acceptance is pending fresh native and extracted-release checks.
The frozen binary interface is `rebase-next host` for the native line protocol
and `rebase-next serve /absolute/service.json` for HTTP. The process requires no
Node or Python runtime. These instructions describe the service contract and
systemd unit shape; they do not claim an accepted release artifact.

The service reads one explicit JSON object with `format: "rebase-service-1"`,
one compiled `model`, a `backend`, an open `target`, and `service` settings. The
complete examples are [redb](../deploy/server.example.json),
[SurrealKV](../deploy/server-surrealkv.example.json), and
[FoundationDB](../deploy/server-foundationdb.example.json). Each field is
present in each example. Replace every `REPLACE_WITH_` value, the example
canonical UUID, and the FoundationDB namespace before installation. The UUID
must match the existing store. `mode: "open"` never creates a store and a
store/model identity mismatch prevents startup.

Use an absolute store path for redb or SurrealKV. FoundationDB uses the exact
nonempty namespace label and an absolute cluster file path; it is not a local
filesystem path. A FoundationDB-enabled executable also needs the compatible
native client library at runtime, including when deploying a configuration that
selects another backend. See [backend behavior and limits](storage-backends.md).

The supplied systemd examples run the service as a dedicated account and use
the same binary command:

```ini
ExecStart=/usr/local/bin/rebase-next serve /etc/rebase-next/service.json
```

The redb, SurrealKV and FoundationDB units are in [`deploy/`](../deploy/).
Install the matching service JSON as `/etc/rebase-next/service.json`, protect it
from untrusted writes, and ensure the service account can read the public-key
configuration and open the selected store. For FoundationDB, the account also
needs read access to the configured cluster file and the required runtime
library. Keep issuer private keys outside the service host; the service receives
public verification keys only.

Terminate TLS at a supported reverse proxy before exposing a listener beyond a
trusted private network. Configure connection, header and body-read timeouts
and request-rate limits there. The default example listens on loopback. A
forwarded actor header does not grant authority; `/rpc` requires a bearer token.
`GET /health` reports liveness only, not storage integrity or actor access.

Tokens use the narrow EdDSA JWT profile in the [server guide](server.md):
`alg=EdDSA`, `typ=JWT`, configured `kid`, issuer, audience, canonical subject
and tenant UUIDs, epoch, and integer issue/not-before/expiry times. The server
checks the signature, issuer, audience, time window, maximum lifetime and
duplicate fields. It does not implement interactive login or general OIDC.
Rotate keys by publishing overlapping key IDs and restarting before removing
old keys after the token window. Increment or disable a principal epoch for
store-backed revocation.

Requests are limited to 65,536 bytes and admission is bounded to 1–64 blocking
workers, including signature verification. Excess admitted work returns 429.
A deadline can leave an unknown outcome while native work continues and holds
its permit. Preserve the same operation ID and context, then reconcile through
the operation receipt; absence alone does not prove the request failed. SIGINT
and SIGTERM drain accepted work. RPC batches and notifications are unsupported,
and replies use `Cache-Control: no-store`.

Current compiled models configure no fixed population ceiling, and population
counters use u64. Shared limits remain: a 262,144-row observation budget for
full inventory and check operations, 64 MiB backups, 1,024 receipts, 200,000
mutation work units, 64 commands, 32 returning IDs or page rows, and 128 query
visits. Redb-connected end-to-end checks cover 5,001
and 10,001 records in scoped tests; these checks do not establish unrestricted
or production capacity, or replicated failover. Before a binary or model
change, stop the old writer, retain verified backups and the matching compatible
binary, and validate restored state with that binary. Model identity includes
configured limits. Old stores with earlier identities or codecs are rejected;
there is no automatic migration. See [storage lifecycle](storage.md) for
backup, reset, receipt-retention and recovery semantics.
