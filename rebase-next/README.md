# ReBase Next

**G10 status (2026-10-26):** N1–N5 are accepted within bounded scopes. `tools/node/` provides
ordinary ESM functions for configuration, native model/store access, authenticated
services, client workflows, scoped operator lifecycle and receipt-gated
population, experiments, bounded workloads, observations and source-only
checking. The [N4 result](research/69-node-experiment-result.md) records its
evidence and incomplete obligations: Measurement query result/selection,
equal-time mixed-sign Equipment prefix extrema and physical tree structure.
The [N5 release](research/71-node-lifecycle-result.md) verifies committed-source
packages, 122 extracted Node tests and redb/SurrealKV/local FoundationDB
lifecycle checks. N6's [complete-backup source checker](research/72-node-complete-backup-contract.md)
now binds Equipment, Measurement and Quantity expectations to physical trees;
complete Equipment history needs a retained identity witness. The
[signed-ingress example](research/73-node-signed-ingress-contract.md) adds
ordinary Node HMAC/HTTP composition and durable retry checks. Bounded
invoicing/IssueShare and retirement remain in N6. Ordered-storage work remains pending. Python workflow
deletion waits for N6 replacement controls. See the [G10 program](research/56-node-and-index-redesign-program.md),
[Node contract](research/57-node-developer-contract.md), [storage plan](research/58-ordered-storage-redesign.md)
and [capability inventory](research/59-node-capability-inventory.md).

Compose the native host functions directly from JavaScript. This N1 model-only
example returns the selected compiled model's public catalog and closes its
owned host. For an N2 authenticated Equipment workflow, see the complete
[ordinary function example](tools/node/examples/n2-equipment-workflow.mjs):

```js
import { resolve } from 'node:path';
import { parseEnvironment, resolveConfig } from './tools/node/config.mjs';
import { openNative } from './tools/node/native.mjs';

const config = resolveConfig({
  defaults: {
    native: {
      binary: resolve('target/verification-build/debug/rebase-next'),
      environment: {},
    },
  },
  environment: parseEnvironment(process.env),
  overrides: {
    native: {
      configuration: {
        model: 'equipment',
        backend: { kind: 'redb', cluster_file: null },
        target: null,
        operator_methods: [],
      },
    },
  },
});

const native = await openNative(config);
try {
  const catalog = await native.catalog({ scope: 'public' });
  console.log(catalog);
} finally {
  await native.close();
}
```

The binary path must resolve to a built executable. See the complete
[N1 model-catalog example](tools/node/examples/n1-model-catalog.mjs).
The N2 function composition example shows the Equipment model, scoped operator,
local authenticated service, saved plan and status recovery:
[N2 Equipment workflow](tools/node/examples/n2-equipment-workflow.mjs).
The N3 example composes a caller-owned population proposal with a prepared model
and client: [N3 population workflow](tools/node/examples/n3-population.mjs).

**A bounded calculation backend with reusable compiled models and developer tools.**
One Rust executable provides exact connected calculations, private outputs,
ordered aggregates and historical invariants, transactional DAG authority,
authenticated JSON-RPC, replay receipts and verified storage recovery. A small
stateless Python client and model-driven fixtures make it directly usable from
scripts. Calculation, equipment reservation, sensor measurement and bounded
external work share the engine, authority and tools. Existing bounded invoicing
remains available. All implementation and dependencies stay inside this directory.
This checkout's package source is 0.16.0 and includes native index families,
reactive dimensioned reports and latest-observation selection, declared published-parent values and bounded fake-provider
work with signed events and reconciliation after restore. Shared storage now uses
opaque mutation tokens, scoped query epochs and bounded receipt allocation slots;
the [G7 result](research/51-storage-conformance-result.md) records accepted
FoundationDB, redb and standalone SurrealKV conformance and its limits.
A [self-explaining workshop](docs/workshop.md) adds independent checks, bounded
exploration and replay across four small examples.
G8.4 verifies 0.16.0 redb-only and all-feature release packages through extracted
workflows; see the [G8 results](research/53-workload-deployment-result.md) for
artifact hashes and acceptance limits. The 0.6.0 deployment result remains
historical evidence.

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
to run the harness without building Rust locally. The [deployment guide](docs/deployment.md)
shows how to build a committed source bundle and verify its extracted tools.
For an existing non-accounting sensor-report and selection workflow using the
current checkout's executable:

```sh
mkdir -p target
python3 -B tools/observation_selection.py --binary target/native-slice/build/release/rebase-next --out target/my-sensor-run
```

| Task | Guide |
| --- | --- |
| Compose the Node native configuration and model-catalog functions | [N1 result and limits](research/63-node-native-host-result.md) · [example module](tools/node/examples/n1-model-catalog.mjs) |
| Author a compiled model or select one for a store | [Compiled models](docs/compiled-models.md) |
| Use exact fractional rates and explicit rounding in a native model | [Exact values](docs/exact-values.md) |
| Run the equipment allocation scenario | [Equipment](docs/equipment.md) |
| Run invoice pricing, tax-on-tax, credits, payments and refunds | [Invoicing](docs/invoicing.md) |
| Run, install and understand the supported limits | [Deployment](docs/deployment.md) |
| Add native index summaries or run the measurement model | [Native indexes](docs/native-indexes.md) |
| Commit and run bounded external work | [External work](docs/external-effects.md) |
| Use exact financial windows in reactive reads and public root reads | [Exact time windows](docs/reactive-windows.md) |
| Prepare fixtures, inspect the model, compose API calls and retain mutation plans | [Developer tools](docs/developer-tools.md) |
| Configure HTTP, identity, credentials and rotation | [Server](docs/server.md) |
| Check, back up, restore, reset or archive receipts | [Storage lifecycle](docs/storage.md) |
| Exact command/query shapes and the offline inspector | [Operation reference](docs/local-prototype.md) |
| Verified release packages | [N5 Node/native package result](research/71-node-lifecycle-result.md) · [historical G8.4 package result](research/53-workload-deployment-result.md#g84--current-extracted-release-packages) |
| Accepted storage adapters | [G7 result](research/51-storage-conformance-result.md) · [Backend usage](docs/storage-backends.md) |
| Operational assurance | [G8 results](research/53-workload-deployment-result.md) · [Workload guide](docs/workloads.md) · [Plan](research/52-workload-deployment-plan.md) |
| Compose bounded population with the existing mutation client | [Population guide](docs/population.md) · [G9 results](research/55-population-tooling-result.md) |
| Source verification | [G7.5 coordination](research/50-scoped-coordination-result.md) · [G7.6 conformance](research/51-storage-conformance-result.md) · [V1 workshop](research/44-workshop-verification-result.md) |
| Run the self-explaining verification suite | [Workshop guide](docs/workshop.md) |

The G8.4 redb-only package supports redb without optional backend features; its
all-feature package supports redb, FoundationDB and standalone SurrealKV. Extracted
smoke/recovery checks cover one tenant and one selected compiled model; see the
[package results](research/53-workload-deployment-result.md#g84--current-extracted-release-packages)
and [backend usage](docs/storage-backends.md) for verification boundaries.
Calculation/equipment allow up to 4,096 public source records, 8,192 active
private outputs, 16,384 retained output identity reservations, and explicit work,
query and receipt limits. Trusted Rust modules author models; arbitrary behavior
loading, a full accounting port, live-provider adapters and a frontend are separate
future gates. TiKV and G6 remain deferred; G8.0–G8.5 are accepted within their
recorded boundaries. G9’s composable population API and live Equipment/Quantity
examples are accepted, including isolated source-tooling and optional-provider
checks. See the [population guide](docs/population.md) for current scope
and limits. G6, TiKV and frontend remain deferred. Exact workload results and
bounds are documented. Invoicing initially supports 64 public
sources/256 outputs/512 retained roles; see its guide for the bounded workflow.
Read the resource envelope before choosing a workload; these are enforced bounds,
not a claim of general production capacity.

The [workshop](docs/workshop.md) now walks through, checks, explores and replays
non-accounting examples with independent source expectations and native/process
controls. Equipment, measurement, quantity and effect-demo remain separate
stores. Broader accounting is deferred; bounded invoicing remains an existing
regression workflow. See the [result and limits](research/44-workshop-verification-result.md).

The population probe runs both models at 64, 256, 1,024 and 4,096 public sources:

```sh
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --out target/my-capacity-run
```

It checks source arithmetic, selective updates, fanout, rollback, replay,
authorization, restart and verified restore through the real HTTP process.
Each mutation retains the 200,000 work-unit budget; larger causal closures can
reject atomically. The 0.16.0 source uses store format 10 /native codec 7 /
effect codec 4 /API 4. All six compiled model behavior identities change with
the token and coordination contract; formulas retain their declared meaning.
There is no implicit migration from earlier formats;
keep matching binaries with their stores. See [upgrades](docs/storage.md#data-identity-and-upgrades).

`rebase-next --help` lists operator commands. Select equipment with
`rebase-next --model equipment <command>` or invoicing with
`rebase-next --model invoicing <command>`; calculation is the default. Use the
same selector for every command against that store. `--model measurement` selects
the 64-source dimensioned statistics model. Pure model commands need no store.
`--model effect-demo` selects bounded Account/Dispatch work. Its fake worker is optional;
restored stores permit explicit reconciliation-only activation.
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
[G10 program](research/56-node-and-index-redesign-program.md). The research papers
distinguish user intent, proposals, mathematical facts and executed evidence.
[The original discussion index](research/sources.md),
[model/mathematics](research/01-model-and-mathematics.md),
[storage semantics](research/02-transactions-and-storage.md),
[access/query contract](research/03-access-and-queries.md),
[system audit](research/06-system-audit.md) and
[research gates](research/08-research-workflow.md) preserve the broader design.
Earlier evidence remains dated; unchanged semantic contracts do not require
repeating a whole-project audit.
