# ReBase Next

**A bounded calculation backend with reusable compiled models and developer tools.**
One Rust executable provides exact connected calculations, private outputs,
ordered aggregates and historical invariants, transactional DAG authority,
authenticated JSON-RPC, replay receipts and verified storage recovery. A small
stateless Python client and model-driven fixtures make it directly usable from
scripts. Calculation, equipment reservation and bounded invoicing share the engine,
authority and tools. All implementation and dependencies stay inside this directory.
This checkout's package source is 0.9.0 and includes native index families, dimensioned measurements and declared published-parent values.
The last verified deployment bundle is 0.6.0; source capabilities do not imply
that a release bundle has passed deployment acceptance.

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
to run the harness without building Rust locally. The [deployment guide](docs/deployment.md#build-and-verify-a-release-bundle)
shows how to build a committed source bundle and verify its extracted tools.
For the paid/refunded invoicing workflow in an extracted bundle:

```sh
mkdir -p target
python3 -B tools/invoicing.py --binary bin/rebase-next --out target/my-invoicing-run
```

| Task | Guide |
| --- | --- |
| Author a compiled model or select one for a store | [Compiled models](docs/compiled-models.md) |
| Use exact fractional rates and explicit rounding in a native model | [Exact values](docs/exact-values.md) |
| Run the equipment allocation scenario | [Equipment](docs/equipment.md) |
| Run invoice pricing, tax-on-tax, credits, payments and refunds | [Invoicing](docs/invoicing.md) |
| Run, install and understand the supported limits | [Deployment](docs/deployment.md) |
| Add native index summaries or run the measurement model | [Native indexes](docs/native-indexes.md) |
| Use exact financial windows in reactive reads and public root reads | [Exact time windows](docs/reactive-windows.md) |
| Prepare fixtures, inspect the model, compose API calls and retain mutation plans | [Developer tools](docs/developer-tools.md) |
| Configure HTTP, identity, credentials and rotation | [Server](docs/server.md) |
| Check, back up, restore, reset or archive receipts | [Storage lifecycle](docs/storage.md) |
| Exact command/query shapes and the offline inspector | [Operation reference](docs/local-prototype.md) |
| Last verified deployment bundle | [0.6 deployment result](research/29-deployment-result.md) |
| Current source capability gate | [G4d-a published values](research/36-value-dependencies-gate.md) |

The supported deployment is **one embedded redb process, one tenant and
one selected compiled model**. Calculation/equipment allow up to 4,096 public source records, 8,192 active
private outputs, 16,384 retained output identity reservations, and explicit work,
query and receipt limits. Trusted Rust modules author models; arbitrary behavior
loading, distributed storage, a full accounting port, external effects and a
frontend are separate future gates. Invoicing initially supports 64 public
sources/256 outputs/512 retained roles; see its guide for the bounded workflow.
Read the resource envelope before choosing a workload; these are enforced bounds,
not a claim of general production capacity.

The population probe runs both models at 64, 256, 1,024 and 4,096 public sources:

```sh
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --out target/my-capacity-run
```

It checks source arithmetic, selective updates, fanout, rollback, replay,
authorization, restart and verified restore through the real HTTP process.
Each mutation retains the 200,000 work-unit budget; larger causal closures can
reject atomically. The 0.9.0 source retains store/codec format 6 and changes
the invoicing identity for IssueShare; other model identities match 0.8.0. It has no implicit migration from 0.6.0;
keep matching binaries with their stores. See [upgrades](docs/storage.md#data-identity-and-upgrades).

`rebase-next --help` lists operator commands. Select equipment with
`rebase-next --model equipment <command>` or invoicing with
`rebase-next --model invoicing <command>`; calculation is the default. Use the
same selector for every command against that store. `--model measurement` selects
the 64-source dimensioned statistics model. Pure model commands need no store.
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
[current release result](research/29-deployment-result.md). The research papers
distinguish user intent, proposals, mathematical facts and executed evidence.
[The original discussion index](research/sources.md),
[model/mathematics](research/01-model-and-mathematics.md),
[storage semantics](research/02-transactions-and-storage.md),
[access/query contract](research/03-access-and-queries.md),
[system audit](research/06-system-audit.md) and
[research gates](research/08-research-workflow.md) preserve the broader design.
Earlier evidence remains dated; unchanged semantic contracts do not require
repeating a whole-project audit.
