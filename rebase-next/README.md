# ReBase stack redesign research

Read [CONTEXT.md](CONTEXT.md) first. It is the compact reference for the intended
system, settled corrections, open decisions and the next research boundary.
The source discussion is indexed in [research/sources.md](research/sources.md).

**Current phase: bounded native experiment accepted (October 22).** The
[scenario/gate register](research/08-research-workflow.md) routes continuation;
use the [system review](research/06-system-audit.md) and
[wireframes](research/07-contract-wireframes.md) for the affected boundaries.
M3/M5's bounded causal review and M6's independent checker contract are complete.
The [native slice result](research/12-native-slice.md) closes the
[M1/M2/M4 plan](research/11-native-slice-plan.md) through S1–S5: typed staging,
linked trees, fixed settlement and real redb observation. The independent source
oracle verified 68 cases / 93 operations, including 40 complete-state rejections.

This directory is independently buildable and movable. It contains a research
proposal and bounded Rust/Python experiments; it does not load the existing
compiler, gateway, accounting build or frontend.

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

```sh
cd rebase-next
CARGO_TARGET_DIR=target/native-slice/build cargo test --locked --all-targets
CARGO_TARGET_DIR=target/native-slice/build cargo run --locked --example native_slice
# Use the observation path printed by the example:
python3 -B research/experiments/native_slice.py --actual target/native-slice/run-.../native-observations.json
```

The toolchain is pinned locally. The example creates fresh redb databases under
`target/native-slice/`, closes/removes them and retains raw observations for the
independent checker. The build cache is reusable. There is no application server
or distributed cluster to install. `Cargo.lock` records dependencies.

The papers distinguish **user intent**, **current implementation**, **proposal**,
**mathematical consequence**, and **executed evidence**. A passed small example
does not certify the proposed complete runtime or establish throughput.

For research-only edits, check links, scope and unchanged evidence fingerprints;
do not rerun the Rust proof or the original database suites without a relevant
change. The [October 22 audit](research/evidence/2026-10-22-context-audit.json)
retains the current inspection and verification scope.

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
