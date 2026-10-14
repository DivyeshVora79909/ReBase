# Integrity repair verification — October 14, 2026

The integrity repair passed its fresh accounting acceptance and targeted tree
gates on a disposable native SurrealKV database. The complete machine-readable
results and source fingerprints are in
[accounting evidence](2026-10-14-integrity-accounting.json) and
[FX regression evidence](2026-10-14-integrity-fx.json).

The full acceptance ran on SurrealDB **3.3.0** and Node **24.19.0**. Its compiled
schema contains **69 tables** and is **5,124,663 bytes**, SHA-256
`8515e1c503e886640ce0383b2fc3045999b3fc70ea1094b47f6e99a63c44d464`. It
snapshotted every compiled table, audit records and all private read metadata.
The run passed **103 source-oracle checkpoints, 105 structural verifications,
90 exact value queries and 51 full rollback snapshots**, followed by populated
schema reapplication and child-first cleanup. The total elapsed time was
**14m36s**: schema application 44.7s, setup 3.5s, scenarios 10m02s, reapplication
91.3s, and cleanup 133.8s.

The maintained
[`probe:accounting-integrity-fx`](../../../dev-tools/accounting/integrity-fx-probe.js) regression
passed **44 source writes, 31 individually checked cleanup deletes, 76
checkpoints, 46 exact value queries and 2 complete rollback snapshots** in
1m58s. It reproduces the second-sale FX index failure and the converted purchase
issue with base tax, tax-on-tax, an issue adjustment, and both linked tax
adjustments. Both former valid writes commit. The final net-tax child is
`-1.10 EUR`; its reporting conversion selects the USD/INR quote for its own
effective time. Each write is checked against the rational accounting model,
all compiled-table snapshot, business AVL oracle and private read oracle.

The typed-tree seeded campaign passed seeds **20261014, 7 and 1031** with **252
mutation checkpoints, 1,570 ordered reads and 108 exact rejection snapshots**.
It includes move/reparent and branch off/on metamorphic histories, insert/delete,
populated schema reapplication, and competing writers (one commit, five rejected
claims, five conflict retries).

The strengthened read oracle accepted its valid and row-permuted controls and
rejected 15 injected structural or coverage corruptions. The observed-read probe
passed 50 checkpoints and 7 rejections; its interval traversal visited 24 nodes
for 68 ranges. The temporal-tree probe passed 240 randomized mutations and 25
conflict retries. The ordered-tree probe passed 22 mutations, 683 typed reads
and pages, and 10 rollback cases. Boundary, derived-order, required-output,
causal-output, compiler, architecture, authentication, tenant-auth, tenant-record,
reader-index and runtime probes also passed.

Fresh build and validation passed for both `all-in-accounting` and `all-in-one`.
`npm run test:dev-tools` passed all **34** tests, including the read-oracle
fault controls. `git diff --check` and syntax checks for changed JavaScript files
passed.

The repository-wide `npm run verify` was inspected but not run. It includes
unrelated live, service and payment-provider probes; this packet ran the targeted
database, compiler, accounting, permission, tenant and runtime checks listed
above. No application `.env`, live database, provider service or deployment was
used. The cloud environment was already configured, so no secrets or setup
configuration were changed.

These are bounded correctness tests, not a production migration or a throughput
benchmark. The accounting oracle independently reconstructs the financial
equations and tree contributions; exact expected logical-read inventory is
independently authored in the observed-read fixture, while accounting checks the
values and full structure of every currently registered read. Transactions that
change subscription membership pay one bottom-up pass over each affected read
group; ordinary writes do not rebuild unrelated groups.
