# ReBase stack redesign research

Read [CONTEXT.md](CONTEXT.md) first. It is the compact reference for the intended
system, settled corrections, open decisions and the next implementation boundary.
The source discussion is indexed in [research/sources.md](research/sources.md).

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
