# N2 — Node workflow, services and operator result

Status: **N2 accepted on 2026-10-25 within the recorded adapter and execution
bounds.** N2 extends the private host contract with native model and fixture
operations, same-owner service lifecycle, scoped identity issuance and explicit
backup, restore, archive and reset operations. Node ESM functions now compose
the host, an authenticated JSON-RPC client, model preparation/rendering and a
private operator. The wire additions are frozen in the
[N2 contract](64-service-operator-contract.md) and
[protocol fixtures](fixtures/n2-native-protocol.json).

Use the ordinary exported function from the JavaScript REPL or another ESM
module. Node 24 is required; install the package's pinned dependencies and build
the native executable first. Pass absolute paths explicitly:

```js
import { runEquipmentWorkflow } from './tools/node/examples/n2-equipment-workflow.mjs';

const result = await runEquipmentWorkflow({
  binary: '/workspace/ReBase/rebase-next/target/n2-native-default/rebase-next',
  storePath: '/tmp/rebase-equipment.redb',
  planPath: '/tmp/rebase-equipment-plan.json',
  backupPath: '/tmp/rebase-equipment-backup.json',
});
console.log(result.outcome, result.mutation);
```

The function creates an owned Equipment redb store, starts an authenticated
loopback service on an OS-selected port, issues an Ed25519 credential, prepares
and saves a caller-owned Pool/Delivery plan, executes it, renders the selected
store and takes an explicit backup. It stops the service and closes the native
host in `finally`. If execution returns `outcome_unknown`, it queries the
original saved plan's status and returns the unresolved result without
refreshing or replaying a new intent. `savePlan` publishes write-once; if the
target was linked but directory durability cannot be confirmed, its
`plan_durability_unknown` error marks it published so the caller retains and
reconciles it. A `plan_cleanup_failed` error reports temporary cleanup residue
separately. Neither condition means publication safely failed. Callers own path
selection and cleanup. Private PEM key material is not included in saved plans
or automatic inspection output.
This is a module export, not a project-specific command parser.

`tools/node/` verification used Node.js 24.22.1 and npm 11.19.1. The final full
suite passed 58/58 tests, with zero failures or skips, against the frozen default
binary `target/n2-native-default/rebase-next` (SHA-256
`74b816d1f72dff333c76633420da35e5e08daf3c087a06abc6d38a07cd39ae5e`). The exact
command, with explicit Node binary selection, was
`PATH=/tmp/node24.22.1/bin:$PATH REBASE_NODE_N1_BINARY=/workspace/ReBase/rebase-next/target/n2-native-default/rebase-next REBASE_NODE_N2_BINARY=/workspace/ReBase/rebase-next/target/n2-native-default/rebase-next npm test`.
The 3,231.638149 ms run is retained in
[the Node execution log](evidence/2026-10-25-n2-node-final.log), SHA-256
`6a7c2c9e0616b4abfcba8546a06c5faa9d95f28dadd9e4270af352866815ff53`. An earlier
full attempt omitted the explicit binary variables and selected a mutable
all-features debug binary; two native integration cases hit EPIPE (56/58). The
captured context identified artifact selection, not a source regression. The
corrected run above passes using the frozen default artifact. Independent review
found no remaining Node findings.

Native verification used Rust/Cargo 1.95.0, the shared offline Cargo cache and
two build jobs. `cargo fmt --all -- --check`, default and all-features scoped
Clippy with `-D warnings`, 20 default integration tests, 21 all-features
integration tests, and seven focused all-features unit tests passed. There
were 48 executions over 28 unique controls. The final default binary is
`target/n2-native-default/rebase-next` (SHA-256
`74b816d1f72dff333c76633420da35e5e08daf3c087a06abc6d38a07cd39ae5e`); the
FoundationDB+SurrealKV binary is `target/n2-native-all/rebase-next` (SHA-256
`dd15140864a59b933511d394ef953adf045f6a6708e4e9b60f71db390f27c63a`). The
88 Cargo/source/model runtime inputs have aggregate SHA-256
`1378f90fcfb7ce47e072dec41910df4e8431e1c9d773fb947735cdf6639ae85d`.
Exact commands, artifact paths, fingerprints and cleanup are in the
[N2 evidence record](evidence/2026-10-25-n2-node-workflow.json).

The exact executed temporary probe is preserved byte-for-byte in [the bounded
adapter trial script](experiments/n2-native-adapter-trial.mjs), SHA-256
`7a3f1c781effce76642f0b0b712451e54428cdeb10062fc726233c4281c9f57b`. The fresh
real adapter trial used the all-features binary and passed native
SurrealKV and FoundationDB create, HTTP mutation, replay, same-owner inspection,
backup, archive, isolated restore, create-only refusal and reset-fence checks.
The FoundationDB trial also verified concurrent transactional hosts and
configuration retry after a wrong store UUID. A separate Node 24 smoke check
reported FoundationDB shared transactional ownership. Trial data and logs stay
under the ignored `target/n2-native-adapters/` directory. The owned FoundationDB
process was stopped, its listener was absent, and no owned application host
remained. The trial's `configure_retry: false` value for SurrealKV means that
case was not attempted; it is not a failure.

N2 does not claim effect-quarantine coverage from the adapter trial; restore
reuses the existing native quarantine and integrity path, while the focused
native unit control covers pre-start restore reconciliation and prevents an
empty lookup from authorizing submission. A native process supports one
FoundationDB `Host`; several independent embedded FoundationDB host owners in
one process remain unsupported. The local adapter trial is not multi-host
latency evidence. No historical capacity campaign was repeated and no storage
format or business semantics version changed. Existing unknown intents remain
immutable; recovery and scope races do not infer rollback from a lost response.

N3 population, N4 workloads, N5 packaging, N6 Python/legacy CLI retirement and
S0–S3 ordered-storage redesign remain pending. G6 expansion, frontend, live
providers, TiKV, populated migrations and unrestricted capacity remain
deferred.
