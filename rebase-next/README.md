# ReBase Next

**A bounded calculation backend with reusable compiled models and developer tools.**
One Rust executable provides exact connected calculations, private outputs,
ordered aggregates and historical invariants, transactional DAG authority,
authenticated JSON-RPC, replay receipts and verified storage recovery. A small
stateless Python client and model-driven fixtures make it directly usable from
scripts. The calculation and equipment reservation models share the engine,
authority and tools. All implementation and dependencies stay inside this directory.

```sh
cd rebase-next
export CARGO_TARGET_DIR=target/native-slice/build
cargo build --locked --release --bin rebase-next
python3 -B tools/harness.py --binary target/native-slice/build/release/rebase-next --out target/my-first-run --writes 128 --readers 4
```

The harness needs Python 3.11+ and OpenSSL. It creates a new secured store and
its own credentials, runs the public API workflow and bounded workload, checks
restart/restore, then stops its server. The directory retains a usable store,
saved plans and `result.json`. Use a new output directory for each run.
Packaged releases include `bin/rebase-next`; use `--binary bin/rebase-next`
to run the harness without building Rust locally.

| Task | Guide |
| --- | --- |
| Author a compiled model or select one for a store | [Compiled models](docs/compiled-models.md) |
| Use exact fractional rates and explicit rounding in a native model | [Exact values](docs/exact-values.md) |
| Run the equipment allocation scenario | [Equipment](docs/equipment.md) |
| Run, install and understand the supported limits | [Deployment](docs/deployment.md) |
| Prepare fixtures, inspect the model, compose API calls and retain mutation plans | [Developer tools](docs/developer-tools.md) |
| Configure HTTP, identity, credentials and rotation | [Server](docs/server.md) |
| Check, back up, restore, reset or archive receipts | [Storage lifecycle](docs/storage.md) |
| Exact command/query shapes and the offline inspector | [Operation reference](docs/local-prototype.md) |
| Current acceptance and remaining capability gates | [0.4 population result](research/24-population-scaling-result.md) |

The supported deployment is **one embedded redb process, one tenant and
one selected compiled model**, with up to 4,096 public source records, 8,192 active
private outputs, 16,384 retained output identity reservations, and explicit work,
query and receipt limits. Trusted Rust modules author models; arbitrary behavior
loading, distributed storage, a full accounting port, external effects and a
frontend are separate future gates. Read the resource envelope before choosing a workload; these are enforced bounds, not a
claim of general production capacity.

The population probe runs both models at 64, 256, 1,024 and 4,096 public sources:

```sh
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --out target/my-capacity-run
```

It checks source arithmetic, selective updates, fanout, rollback, replay,
authorization, restart and verified restore through the real HTTP process.
Each mutation retains the 200,000 work-unit budget; larger causal closures can
reject atomically. Store/codec format 4 and the new model identities require a
new store; format 3 has no implicit migration. See [upgrades](docs/storage.md#data-identity-and-upgrades).

`rebase-next --help` lists operator commands. Select equipment with
`rebase-next --model equipment <command>`; calculation is the default. Use the
same selector for every command against that store. Pure model commands need no store.
`fixture plan` produces authored inputs; `tools/client.py` sends the ordinary
public operations. Stored plans retain the original actor/store/receipt context
across retries. Filesystem operator tools remain separate from the HTTP API.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release --all-targets
python3 -B tools/test_client.py -v
```

For continuation, read [CONTEXT.md](CONTEXT.md) and the
[current result](research/24-population-scaling-result.md). The research papers
distinguish user intent, proposals, mathematical facts and executed evidence.
[The original discussion index](research/sources.md),
[model/mathematics](research/01-model-and-mathematics.md),
[storage semantics](research/02-transactions-and-storage.md),
[access/query contract](research/03-access-and-queries.md),
[system audit](research/06-system-audit.md) and
[research gates](research/08-research-workflow.md) preserve the broader design.
Earlier evidence remains dated; unchanged semantic contracts do not require
repeating a whole-project audit.
