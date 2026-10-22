# ReBase Next

**0.2.0: a bounded, deployable calculation backend and developer toolkit.**
One Rust executable provides exact connected calculations, private outputs,
ordered aggregates and historical invariants, transactional DAG authority,
authenticated JSON-RPC, replay receipts and verified storage recovery. A small
stateless Python client and model-driven fixtures make it directly usable from
scripts. All implementation and dependencies stay inside this directory.

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
| Run, install and understand the supported limits | [Deployment](docs/deployment.md) |
| Prepare fixtures, inspect the model, compose API calls and retain mutation plans | [Developer tools](docs/developer-tools.md) |
| Configure HTTP, identity, credentials and rotation | [Server](docs/server.md) |
| Check, back up, restore, reset or archive receipts | [Storage lifecycle](docs/storage.md) |
| Exact command/query shapes and the offline inspector | [Operation reference](docs/local-prototype.md) |
| Measured release acceptance and remaining capability gates | [0.2 result](research/18-release-result.md) |

The supported deployment is **one embedded redb process, one tenant and the
bundled compiled model**, with up to 64 public source records and explicit work,
query and receipt limits. Arbitrary models, distributed storage, a full accounting
port, external effects and a frontend are separate future gates. Read the
resource envelope before choosing a workload; these are enforced bounds, not a
claim of general production capacity.

`rebase-next --help` lists operator commands. Pure model commands need no store.
`fixture plan` produces authored inputs; `tools/client.py` sends the ordinary
public operations. Stored plans retain the original actor/store/receipt context
across retries. Filesystem operator tools remain separate from the HTTP API.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release --all-targets
python3 -B tools/test_client.py -v
```

For continuation, read [CONTEXT.md](CONTEXT.md) and the relevant
[release checkpoint](research/17-deployable-backend.md). The research papers
distinguish user intent, proposals, mathematical facts and executed evidence.
[The original discussion index](research/sources.md),
[model/mathematics](research/01-model-and-mathematics.md),
[storage semantics](research/02-transactions-and-storage.md),
[access/query contract](research/03-access-and-queries.md),
[system audit](research/06-system-audit.md) and
[research gates](research/08-research-workflow.md) preserve the broader design.
Earlier evidence remains dated; unchanged semantic contracts do not require
repeating a whole-project audit.
