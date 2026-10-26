# Bounded workload and deployment checks

**N6 status:** this guide records workload semantics and dated G8 campaign
evidence. N6 Node bootstrap and retirement acceptance are pending; no Python
workflow command here is a current run procedure. See the [G10 program](../research/56-node-and-index-redesign-program.md),
[Node contract](../research/57-node-developer-contract.md),
[storage contract](../research/58-ordered-storage-redesign.md) and
[capability inventory](../research/59-node-capability-inventory.md).

Earlier G8 workloads used the ordinary authenticated client, owned backend
processes and source-only arithmetic. Their bounded claims and exclusions are
recorded in the [dated results](../research/53-workload-deployment-result.md);
they are not N6 or current deployment acceptance.

The current public functions include `runWorkload`, `checkRun`, `explore` and `logicalReplay`; see [developer tools](developer-tools.md) for the caller-owned Node API.

The historical G7 executable enabled both optional adapters and required
`libfdb_c` even for redb. Current model and backend selection is explicit in
`rebase-service-1`; FoundationDB uses a nonempty namespace label and an absolute
cluster-file path. See [backend setup](storage-backends.md).

The same operations compose directly:

The current public functions include `runWorkload`, `checkRun`, `explore` and `logicalReplay`; see [developer tools](developer-tools.md) for the caller-owned Node API.

The retired campaign's `complete_epoch` performed the quiescent rollback control, original-intent
receipt reconciliation, existing engine-work observation and final complete
thirteen-table check. `g8_observe.sample`, `check_resources`, `read_jsonl` and
`JsonlWriter` are usable without the runner. Reports describe trusted functions
and values; they never execute code from an artifact.

The retired `g8_check.check_directory(directory)` independently consumed the saved raw
trace, source observations, samples and complete images. The CLI `check` uses
that function and requires the completed epoch's `result.json` with its adjacent
private evidence. It does not accept a cached pass without the required raw files.
`g8_cycles.run_cycles(state)` also composes alone; its own source, receipt and
complete-image checks run before it returns. Standalone lifecycle results are
separate from the memory-epoch raw checker.

The default profile is equipment, seed 8042, one sequential writer and two
readers, 64 reusable source IDs including six fixture records, 30 seconds of
warmup, 300 measured seconds, a 30-second read-only cooldown and one-second
samples. New work is paced at at most two actions/second; replays consume action
time but allocate no receipt. There are at most three actual pending client
operations within the eight-operation configured bound. The 800-new-operation
measurement ceiling, fixture receipt, 61 possible warmup/cleanup operations and
32 reserved slots fit below 1,024. Infeasible duration/rate/floor combinations
reject before initialization. A run cannot stop CRUD early and count the rest of
the clock as successful work.

The default measurement requires 100 successful creates, updates and deletes,
500 reads, ten original-ID replays, ten no-ops, ten expected invariant rejections
and ten stale edits. Planned complete cycles guarantee these classes before
seeded mixing. The short smoke profile declares smaller floors and eight measured
seconds; it establishes no five-minute claim.

Public CRUD reuses Delivery UUIDs from the finite pool. Reservation updates
activate/deactivate an existing producer, so private outputs churn while four
retained role identities remain stable. Recreating a deleted Reservation with
the same producer UUID rejects under the existing storage contract. `churn`
finishes the continuous epoch before offline archive/restart, then executes two
full receipt allocation/archive cycles with original-ID replay, unchanged-state
overflow rejection, expiry and resumed CRUD. It never resets the store.

G8.0 host calibration uses 12 available CPUs and about 15.3 GiB physical memory.
The short redb baseline used about 35 MiB application RSS and 28 MiB controller
RSS. These predeclared defaults deliberately leave room for the bounded later
profiles; exceeding one fails rather than adjusting the threshold during a run.

| Resource | Budget |
| --- | --- |
| Application / controller RSS and high-water RSS | 512 MiB each |
| Owned FoundationDB RSS and high-water RSS | 1 GiB |
| Application / controller / database descriptors | 256 / 128 / 512 |
| Application / controller / database threads | 96 / 32 / 64 |
| Physical backend growth during an epoch | 512 MiB |
| All owned artifacts, including disposable embedded store files | 128 MiB |
| Each private action/read stream / sample stream | 32 MiB / 8 MiB |
| Maximum sample gap / sampler overhead | 3 seconds / 250 ms per sample |
| Comparable cooldown RSS growth, application / controller / database | 16 / 16 / 64 MiB |

CPU seconds, PID start identities, RSS/high-water, FDs, threads, physical bytes,
logical public/output/retained-role/receipt inventories and observer overhead are
recorded separately for the controller, application and database. Constant
inventory cooldown windows support the limited growth verdict. Missing comparable
windows report `unsupported`; missing required samples report `incomplete`.
Caches, WAL and retained reservations are not presumed to shrink immediately.

Private JSONL traces retain each original plan before submission and the response
after completion. They preserve operation IDs and contexts for replay. JSON
results, raw sample/read streams, complete backups and a readable summary remain
in the owned directory. Byte/row bounds prevent silent evidence truncation.
Published checkpoint summaries omit credentials and complete backup contents.
Exit codes are 0 for pass, 1 for failure and 2 for incomplete evidence.

## Finite overload and database-service recovery

G8.2 is accepted on all three adapters. The overload profile uses bounded lazy
producers, 2/16/128 offered actions per second, one/four/eight clients, one native
permit and at most eight pending submissions. Equipment and Quantity retain
their own explicit source oracles. The reusable scheduler is
`g8_pressure.bounded_step(requests, submit, ...)`; hooks observe offers,
submissions and completions without changing scheduling code.

The current public functions include `runWorkload`, `checkRun`, `explore` and `logicalReplay`; see [developer tools](developer-tools.md) for the caller-owned Node API.

Reports retain counts, latency distributions, achieved elapsed rates, queue/drain
observations, resources and actual n/m/r. Whole action time, queue/request time
and native work counters have different meanings; unsupported counters remain
unsupported. A finite paced rate is observed load, not maximum capacity.
Partial-input sockets are voluntarily closed; this is not proof of an arbitrary
connection/body-read deadline. The native timeout/permit correctness case is
separate matching accepted evidence, supplied by the checkpoint coordinator.

G8.3 interrupts only the verified disposable FoundationDB helper, keeps the
application PID alive, makes ordinary authenticated database calls, restores the
service even after exceptions, and reconciles the original operation IDs.
It is not a replica failover or native commit-ack injection. Embedded backends
have no independent network database service. Start the helper before this command:

The current public functions include `runWorkload`, `checkRun`, `explore` and `logicalReplay`; see [developer tools](developer-tools.md) for the caller-owned Node API.

`g8_faults.run_outage(state)` and `check_outage_directory(directory)` also
compose directly. Offline checks recompute source/receipt outcomes, complete
images, resource budgets and final artifact bytes. Keep result files in their
original evidence directories. Missing required data cannot pass. CLI exit codes
remain 0 passed, 1 failed and 2 incomplete.

See [deployment](deployment.md) for current package and extracted-workflow
commands. No general fake-data generator is implied by the current workload
profiles. G9 population tooling is documented in the
[accepted results](../research/55-population-tooling-result.md); G10 planning
and its next checkpoint are in the [current program](../research/56-node-and-index-redesign-program.md).

G6, TiKV, frontend, live providers, migrations, million-record envelope expansion,
native commit-ack injection, replicated failover and disk/power-loss infrastructure
remain outside these profiles. The existing bounds and the exact plan in
[paper 52](../research/52-workload-deployment-plan.md) apply.
