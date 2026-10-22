# Run and use the local prototype

This is the independently buildable ReBase Next prototype. It uses one bundled
calculation model, exact values and a local redb store. It contains no runtime
imports from the original ReBase or MetaSol projects.

## Build and demonstrate

From the repository root:

```sh
cd rebase-next
export CARGO_TARGET_DIR=target/native-slice/build
cargo build --locked --bin rebase-next
target/native-slice/build/debug/rebase-next demo target/my-first-demo
```

The demo requires a **new directory**; choose another name for another run.
It creates `demo.redb`, `inspect.html`, separate public/developer model catalogs,
a request/response transcript and `result.json`. Open `inspect.html` in a browser.
The inspector is an offline snapshot with expandable details and no network
connection. Its local developer view includes private records and role bindings.

The workflow creates fourteen authored sources and five private outputs, then
moves two prefix readers atomically. The published values change as follows:

| Publication | Initial | After moving the readers |
| --- | ---: | ---: |
| A | 30 | 20 |
| Left = 2 × A | 60 | 40 |
| Right = 3 × A | 90 | 60 |
| Final = Left + Right | 150 | 100 |

It also demonstrates a budget-limited `exists=unknown`, stale-version rejection,
zero-valued feedback rejection, durable replay/status and reopening the store.
All operations use the same public operation adapter. Only initialization and
the final trusted developer snapshot use their dedicated local tooling paths.

## Model and developer tools

```sh
target/native-slice/build/debug/rebase-next model public
target/native-slice/build/debug/rebase-next model developer
target/native-slice/build/debug/rebase-next model explain Adjustment
target/native-slice/build/debug/rebase-next model view > target/model.html
target/native-slice/build/debug/rebase-next model validate 7 model-moment.json
target/native-slice/build/debug/rebase-next inspect target/my-first-demo/demo.redb
target/native-slice/build/debug/rebase-next inspect target/my-first-demo/demo.redb --html > target/inspection.html
```

For the validation example, `model-moment.json` contains `{"at":"10"}`.
Preparation/export/explain/view do not open a store or activate a model. Output
goes to stdout. Shell redirection is the caller's choice; use a fresh output path.
Preparation compiles the authored self-contained Draft 2020-12 schemas and checks
the explicit codes, references, memberships, queries, formulas and publications.
Formats are disabled; UUID patterns plus native binding enforce canonical UUIDs.
Schema defaults/readOnly annotations do not create fields or grant authority.

Only the bundled compiled model is supported. Its semantic fingerprint binds
the schemas/declarations to the native core's source/dependency fingerprint and
codec. HTML/CSS and source-location labels are presentation. The core fingerprint
is deliberately conservative: even a core formatting/dependency-file change can
require a new disposable store. An incompatible store is refused; no automatic
migration or reset is provided.

| Code | Contract | Role |
| ---: | --- | --- |
| 1 | Rule | Direct coefficient |
| 2 | Curve | Unit pair and quote root |
| 3 | Quote | Unique dated rate |
| 4 | Account | Native history and nonnegative complete-time prefixes |
| 5 | Subsidiary | Reporting history |
| 6 | Posting | Native/reporting contributions from coefficient and dated rate |
| 7 | Moment | Shared authored time |
| 8 | Entry | Authored history contribution |
| 9 | Adjustment | Strict prefix, target difference and optional private output |
| 10 | Basis | One/two source totals, factor and private output roles |
| 11 | Pin | Trusted research-fixture contract, unavailable through the local API |
| 12 | Output | Engine-managed private contribution |

All input fields are required. Basis feedback is explicitly `null` when inactive.
Updates replace whole named fields through `set`; `unset` must be empty in this
model. Unit codes are immutable. Exact amounts, times and versions are canonical
decimal strings. Codes/counts/limits are JSON integers. Native binding applies
the declared i64/i128 ranges in addition to JSON Schema validation.

## Start a fresh store and process API

```sh
target/native-slice/build/debug/rebase-next init target/new.redb \
  --tenant 00000000-0000-4000-8000-000000000001 \
  --actor 00000000-0000-4000-8000-000000000002
target/native-slice/build/debug/rebase-next rpc target/new.redb
```

`init` requires a new file; its parent directory must exist. `rpc` requires an
existing compatible store. One process owns the file; close the process before
opening the store in another command. The API accepts one JSON-RPC 2.0 object
per input line and produces one response per output line. IDs are strings of
1–128 bytes. EOF closes the process. Batches and notifications reject without
executing their operations; a JSON-RPC batch is not a transaction.

The process acts as the initialized local actor/tenant. Requests cannot change
that identity, select a model implementation, enable fixture mode or write raw
storage. This local process/file trust boundary is not a login service. There
is no HTTP listener or production tenant/permission administration.

Start with:

```json
{"jsonrpc":"2.0","id":"model","method":"model.describe","params":{}}
```

Use the returned `model` identity in every other operation. The public catalog
includes input schemas, published fields, permitted predicates and limits.

| Method | Params besides `model` |
| --- | --- |
| `records.get` | `id` |
| `records.mutate` | `context` from `session.describe`, `operation_id`, `commands`, `returning` UUID array |
| `operations.status` | original `context`, `operation_id` |
| `records.page` | `query`, `limit`, `visit_budget`, nullable `cursor` |
| `records.exists` | `query`, `visit_budget`, nullable `cursor` |
| `roots.read` | `owner`, `slot`, `read` |

Unknown fields and duplicate object keys reject. Input is bounded to 65,536
bytes before parsing. `get` returns a public envelope or `null`; private and
absent identities both return `null`. Public operations expose no private role
IDs, tree links, signing material or raw receipt tables.

## Client example

This Python client opens the completed demo, reads an actual version and edits
one source. All arithmetic remains on the engine; values stay strings.

```python
import json, subprocess, uuid

p = subprocess.Popen(
    ["target/native-slice/build/debug/rebase-next", "rpc",
     "target/my-first-demo/demo.redb"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

def call(method, params):
    request = {"jsonrpc": "2.0", "id": str(uuid.uuid4()),
               "method": method, "params": params}
    p.stdin.write(json.dumps(request) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())

model = call("model.describe", {})["result"]["model"]
source = "00000000-0000-4000-8000-000000000060"  # Adjustment P
record = call("records.get", {"model": model, "id": source})["result"]
context = call("session.describe", {})["operation_context"]
operation_id = str(uuid.uuid4())  # Retain this ID and request until reconciled.
params = {
    "model": model, "context": context, "operation_id": operation_id,
    "commands": [{"op": "update", "id": source,
                  "if_version": record["version"],
                  "set": {"target": "25"}, "unset": []}],
    "returning": [source]
}
print(call("records.mutate", params))
print(call("operations.status", {"model": model, "context": context, "operation_id": operation_id}))
p.stdin.close()
p.wait()
```

One `records.mutate` is atomic. Create supplies `op`, `id`, `contract`, `fields`;
update supplies `op`, `id`, `if_version`, `set`, `unset`; delete supplies `op`,
`id`, `if_version`. A command may refer to earlier creations in that mutation.
Forward references reject. Every source ID may occur in only one command.
The returned `result.records` contains settled public records/nulls for the
requested IDs, alongside the confirmed operation ID and revision.

Same operation ID and normalized content replays its original confirmed result
without applying it again. Changed content rejects with `operation_conflict`.
Data, public index and receipt commit together. A stale editor version requires
review, not an automatic replacement version. On `outcome_unknown`, retain the
operation ID and request, reopen and reconcile. `not_observed` is not proof of
failure. The local store retains up to 1024 receipts without eviction; reaching
that bound rejects new mutations, while existing receipts can still replay.

## Query and publication semantics

```json
{"path":"records.by_id","contract":9,"equals":{"field":"target","value":"20"}}
```

`contract` and `equals` may be `null`. Equality requires one public contract and
a scalar field listed in its `predicate_fields`; arrays/nested objects and
derived/private fields are not predicates. The only order is ascending public
record UUID. Pages contain distinct public records. Every visited candidate,
including a filter rejection, consumes the budget.

An empty page may carry a cursor. `exists` returns `yes` on a match, `no` only
after exhausting the remaining scope, and `unknown` if its budget ends first.
There is no extra uncounted lookahead: a page that ends exactly at its limit may
need one final empty continuation to establish exhaustion.

Cursors are HMAC authenticated and bind the store, model, actor/tenant, exact
query, last visited public ID and global mutation revision. Limit/budget may
change when resuming. Any new committed mutation, even a semantic no-op,
invalidates a cursor with `query_changed`. A receipt replay does not. Cursors
survive reopening while their revision remains current. Each page uses one fresh
snapshot; this is not a frozen multi-request export.

Root reads use one of:

```json
{"kind":"summary"}
{"kind":"before","at":"20"}
{"kind":"latest","at":"20"}
```

Account slot 2 allows summary and strict `before`; Subsidiary slot 3 allows
summary; Curve slot 1 allows summary and `latest`. A financial summary publishes
count, sum, complete-time minimum, and first/last time. `before` excludes **all**
equal-time occurrences, including at i64 extrema. `latest` returns a public quote
ID/rate or `null`. Root results include the root revision and store revision.
These publications include declared private contributions without exposing their
private record identities. Record-list filtering does not redefine a root sum.

## Bounds and validation

The prototype permits at most 64 authored records, 16 each of Quote/Posting/
Adjustment/Basis, 48 active private outputs and 256 lifetime role reservations.
It allows 64 commands, 32 returning IDs, page limit 32, visit budget 128 and
200,000 mutation work units. Calculated i128 overflow rejects. This is bounded
acceptance, not a throughput or production-capacity claim.

```sh
CARGO_TARGET_DIR=target/native-slice/build cargo test --locked --all-targets
cargo fmt --all -- --check
CARGO_TARGET_DIR=target/native-slice/build cargo clippy --locked --all-targets -- -D warnings
CARGO_TARGET_DIR=target/native-slice/build cargo run --locked --example local_acceptance
# Use the emitted observation path:
python3 -B research/experiments/local_prototype.py --actual target/local-prototype/run-.../local-observations.json
```

The local observer is privileged and used only for disposable acceptance stores.
Its complete application-table images include test-store signing material; it
is absent from RPC and from the normal inspector. The checker independently
derives sources/outputs, every subtree, public index membership and receipt
results/content hashes. Earlier native corpora still test the wider causal and
original settlement matrix; their commands are in the research result papers.

Production identity/DAG authorization, distributed adapters, external effects,
general decimal rounding, arbitrary model loading/migrations and a full
accounting/frontend port remain separate future work.
