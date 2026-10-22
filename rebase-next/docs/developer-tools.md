# Composable developer workflow

D5 contract: offline model and fixture tools produce JSON; one stateless client
submits public operations to the authenticated backend. There is no fixture RPC,
hidden session cache, automatic mutation retry or alternate database writer.
The calculation and equipment compiled models use the same client and operator
commands. Select equipment with a leading `--model equipment` on the backend
CLI; the HTTP client learns the selected model identity from the server.

`model public`, `model developer`, `model explain` and `model validate` use the
same prepared declarations and native bindings as the engine. Public catalogs
exclude private roles and fixture recipes. The developer catalog names the
design-owned recipes. Schema validation checks input shape and exact bindings;
reference existence, authority, causal settlement and global invariants are
checked in the real mutation transaction.

`fixture plan causal-diamond --namespace <uuid>` produces a mutation draft with
stable UUIDv5 identities. The namespace and fixture label determine identities;
use a different namespace for a separate instance. Remapping follows declared
reference fields, including arrays and optional nested references. Every input
passes the prepared schema/native binder and every reference has a typed target
in the recipe. It does not write a store or reserve an operation ID.

The client binds a draft to an authenticated session once and saves the exact
mutation before sending. A saved plan identifies endpoint, model, store, tenant,
actor, original operation context and operation UUID, but contains no token.
Application/status check the destination identity and retain the original
request. Archive expiry is surfaced; it never obtains a replacement context for
an uncertain old operation. Record versions are authored explicitly, and a
conflict requires the developer to inspect current state and author a new intent.

## Use the tools

Build the binary and start the authenticated service using the
[server guide](server.md). Save its issued token in a private file, then:

```sh
rebase-next fixture list
rebase-next model explain Adjustment
rebase-next fixture plan causal-diamond --namespace 00000000-0000-4000-8000-000000000100 > draft.json
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt prepare draft.json seed.plan.json
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt apply seed.plan.json
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt status seed.plan.json
```

`prepare` creates a private, fully written file without overwriting an existing
path. Inspect it before `apply`. If a response is lost, use `status` or reapply
that same file. A new `prepare` call creates a **new intended operation**. It is
not a retry mechanism. A refreshed bearer token for the same identity may be
used with the existing plan. `operation_expired` requires archive reconciliation;
`not_observed` does not establish that the operation failed. Receipt projections
can become `null` when their records change or access is revoked.

Use `call <method> [params.json]` for any ordinary RPC, including bounded pages,
root reads and graph administration. It makes exactly one call; params default
to `{}`. For a page, preserve `cursor`, `exhausted` and `visited`. For existence,
preserve `unknown`. A client-side result limit must not imply full enumeration.
Drafts can also be authored directly:

```json
{
  "model": "MODEL_FROM_PUBLIC_CATALOG",
  "commands": [{"op":"update","id":"RECORD_UUID","if_version":"2","set":{"at":"30"},"unset":[]}],
  "returning": ["RECORD_UUID"]
}
```

The model catalog supplies contracts, schemas, mutable fields, public roots and
capabilities. Obtain the current record and its version with `records.get`,
author a draft, then prepare and submit it. Command envelopes are checked again
by the server; the client does not duplicate schema or calculation rules.
Both models declare 4,096 public sources, 8,192 active private outputs and 16,384
retained output identity reservations. Each mutation remains limited to 64
commands, 32 returning IDs and 200,000 charged engine work units. Populate larger
stores through separate bounded mutations, reading current versions for later
edits; the source count does not increase per-operation or receipt limits.

Python 3.11+ and its standard library are sufficient. Ordinary imports expose
the same functions as the CLI:

```python
from tools.client import call, prepare, save_plan, execute

catalog = call(url, token, "model.describe", {})
plan = prepare(url, token, draft)
save_plan("new-operation.plan.json", plan)
result = execute(url, token, plan)
receipt = execute(url, token, plan, status=True)
```

No function retains tokens, sessions, cursors or plans globally. `call` caps
requests at 64 KiB and replies at 2 MiB, rejects duplicate/malformed responses,
checks response IDs/framing, and never follows redirects. HTTP and transport
failures surface explicitly; uncertain outcomes retain the caller's plan.
Use HTTPS outside a trusted local network. These filesystem plans contain
authored data and identity/context metadata, so keep them private.

## Repeatable acceptance

```sh
python3 -B tools/test_client.py -v
python3 -B tools/harness.py --binary target/native-slice/build/debug/rebase-next --out target/my-harness --writes 0
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --out target/my-capacity
```

The harness and TLS control require OpenSSL. The harness creates its own issuer keys and secured store,
uses the generated recipe over real HTTP, and stops its own server. Choose a
new output directory each run. It retains the store, private credentials, saved
plans, archive and a JSON result for inspection; the token expires in ten minutes.
The report verifies literal source arithmetic, namespace separation, stale edits,
destination/model fences, replay/status after restart, redacted obsolete receipt
projections and archive expiry. The independent fault peer exercises lost,
truncated, misidentified, ambiguous and duplicate-key replies plus redirects.
A real TLS peer verifies trusted-certificate and matching-hostname enforcement.
Earlier native acceptance remains dated evidence. The [deployment workload](deployment.md)
extends the same harness; omit `--writes 0` to fill the catalog's declared source
maximum in batches of at most 64 commands and run its default 128 atomic moves.
Its revision checks adapt to the number of fill batches.

`capacity.py` defaults to both equipment and calculation at 64, 256, 1,024 and
4,096 public sources. Use `--models equipment` or `--populations 64 256` to narrow
a run. It checks source arithmetic, selective updates, fanout, lifecycle,
authorization, replay, pages, restart and verified restore. Its `result.json`
records work/byte counts and observed fanout outcomes. A `work_limit` result for
an oversized closure is checked for complete logical rollback and no success
receipt; it does not increase the fixed 200,000-unit budget. The
[population result](../research/24-population-scaling-result.md) records executed
acceptance and observed boundary brackets.

Release 0.4.0 changes store/codec formats to 4 and model identities to calculation
behavior `rebase-calculation-contract-4` or equipment behavior
`equipment-reservations-3`, combined with the selected resolved declarations.
Older saved plans remain bound to their original destination and context; they
cannot be retargeted to a new-format store. See [storage upgrades](storage.md#data-identity-and-upgrades).
