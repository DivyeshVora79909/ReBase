# ReBase stack redesign research

Read [CONTEXT.md](CONTEXT.md) first. It is the compact reference for the intended
system, settled corrections, open decisions and the next research boundary.
The source discussion is indexed in [research/sources.md](research/sources.md).

**Current phase: research and contract wireframes (October 22).** Start the
continuation with the [system review](research/06-system-audit.md), then the
[wireframes](research/07-contract-wireframes.md) and
[scenario/gate register](research/08-research-workflow.md). Runtime implementation
planning follows closure of the relevant semantic questions.

This directory is independently buildable and movable. It contains a research
proposal and a small Rust feasibility check; it does not load the existing
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

```sh
cd rebase-next
cargo test --locked
cargo run --locked --example feasibility
```

The toolchain is pinned locally. The example uses a disposable redb file, removes
it on completion, and prints its results. There is no application server or
distributed cluster to install for this check. `Cargo.lock` records dependencies.

The papers distinguish **user intent**, **current implementation**, **proposal**,
**mathematical consequence**, and **executed evidence**. A passed small example
does not certify the proposed complete runtime or establish throughput.

For research-only edits, check links, scope and unchanged evidence fingerprints;
do not rerun the Rust proof or the original database suites without a relevant
change. The [October 22 audit](research/evidence/2026-10-22-context-audit.json)
retains the current inspection and verification scope.
