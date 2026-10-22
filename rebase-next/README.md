# ReBase Next local prototype

**The confirmed usable local prototype is complete.** One Rust executable
provides exact causal calculations, a prepared model, separate public/developer
catalogs, transactional mutation receipts, bounded reads and a runnable demo with
an offline developer inspector. [The result](research/16-local-prototype-result.md)
records acceptance; [the guide](docs/local-prototype.md) explains every command
and public operation.

```sh
cd rebase-next
export CARGO_TARGET_DIR=target/native-slice/build
cargo build --locked --bin rebase-next
target/native-slice/build/debug/rebase-next demo target/my-first-demo
```

Choose a new directory for each demo. Open its `inspect.html`; the same folder
contains a usable `demo.redb`, model catalogs and the operation transcript.
`rebase-next rpc <store.redb>` serves JSON-RPC over stdin/stdout. The prototype
uses a fixed local actor/tenant; production authentication, distributed storage
and a full accounting/UI port remain separate scope.

This directory is independently buildable and movable. It loads no original
ReBase compiler, gateway, accounting build or MetaSol frontend. All generated
artifacts stay under `target/`. For new development, read [CONTEXT.md](CONTEXT.md)
and the relevant paper below. The original discussion is indexed in
[research/sources.md](research/sources.md).

| Read when working on | Paper |
| --- | --- |
| Records, participation, aggregates, causality and cost | [Model and mathematics](research/01-model-and-mathematics.md) |
| Snapshot, staging, guards, retry, atomicity and effects | [Transactions and storage](research/02-transactions-and-storage.md) |
| Principal DAG, readers, indexed queries and API boundaries | [Access and queries](research/03-access-and-queries.md) |
| Stack choices, declarations, module structure and next steps | [Implementation proposal](research/04-implementation.md) |
| Executed evidence and its limits | [Rust feasibility](research/05-feasibility.md) |
| Documentation, past failures and what a stack change affects | [Whole-system review](research/06-system-audit.md) |
| Model lifecycle, API, exact values, tooling and query behavior | [Contract wireframes](research/07-contract-wireframes.md) |
| Bounded scenarios, research decisions and minimum verification | [Research workflow](research/08-research-workflow.md) |
| Moved prefix readers, required outputs, identity and feedback | [M3/M5 causal contract](research/09-causal-settlement.md) |
| Source-derived inventories, tree verification and corruption controls | [M6 checker contract](research/10-independent-checker.md) |
| First native commands, state, settlement and implementation stages | [M1/M2/M4 implementation plan](research/11-native-slice-plan.md) |
| Native execution, independent acceptance, work counts and remaining limits | [M1/M2/M4 result](research/12-native-slice.md) |
| Completed local prototype contract and stages | [P1–P4 plan](research/13-local-prototype-plan.md) |
| Concrete model/tooling/API/demo boundaries | [Local interface contract](research/14-local-interface-contract.md) |
| Native prefix calculations, private outputs and independent acceptance | [P1 result](research/15-causal-native-result.md) |
| Current runnable scope, evidence and future boundary | [Local prototype result](research/16-local-prototype-result.md) |

```sh
CARGO_TARGET_DIR=target/native-slice/build cargo test --locked --all-targets
CARGO_TARGET_DIR=target/native-slice/build cargo run --locked --example local_acceptance
# Use the observation path printed by the example:
python3 -B research/experiments/local_prototype.py --actual target/local-prototype/run-.../local-observations.json
```

The toolchain and dependencies are pinned locally. Acceptance harnesses create
fresh redb databases, remove their owned stores and retain complete observations
for independent checking. The demo intentionally retains its usable store.
The build cache is reusable; no distributed cluster is needed.

The papers distinguish **user intent**, **current implementation**, **proposal**,
**mathematical consequence**, and **executed evidence**. A passed small example
does not certify the proposed complete runtime or establish throughput.

For research-only edits, check links, scope and unchanged evidence fingerprints;
do not rerun the Rust proof or the original database suites without a relevant
change. The [final evidence](research/evidence/2026-10-22-local-prototype.json)
records current execution. Earlier audits and evidence retain their dated scope.

The separate bounded research model runs with
`python3 research/experiments/m3_m5.py` from this directory. It checks the M3/M5
wireframe using exact source scans and enumerated orders; it adds no Rust/runtime
dependency. [Its evidence](research/evidence/2026-10-22-m3-m5.json) is separate
from the dated October 21 Rust evidence.

`python3 -B research/experiments/m6.py` runs the synthetic snapshot checker. It
reuses the M3/M5 source oracle and checks missing inventories, tree damage, exact
caches and incomplete verification. [Its evidence](research/evidence/2026-10-22-m6.json)
records five valid, 28 invalid-state and two incomplete controls; no database or
native mutation engine is exercised.
