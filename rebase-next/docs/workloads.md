# Bounded workload and deployment checks

`tools/g8.py` is the operational entry point. It uses the ordinary authenticated
client, owned `Backend` processes and the workshop's source-only arithmetic.
Use a fresh private output directory for each run. The current acceptance is
[G8.0–G8.1](../research/53-workload-deployment-result.md); later checkpoints require
their own executed evidence.

```sh
export LD_LIBRARY_PATH="$PWD/target/g7-environment/root/usr/lib"
python3 -B tools/g8.py smoke --binary target/g75-accepted/rebase-next --backend redb --out target/my-g8-smoke
python3 -B tools/g8.py check --result target/my-g8-smoke/result.json
# One continuous memory epoch, then two separate full receipt/archive cycles.
python3 -B tools/g8.py churn --binary target/g75-accepted/rebase-next --backend redb --out target/my-g8-churn
```

The retained G7 executable enables both optional adapters and needs `libfdb_c`
even for redb. A default redb-only executable needs no FoundationDB SDK. Select
`--backend surrealkv` or `--backend foundationdb --cluster-file
target/g7-environment/fdb.cluster`. FoundationDB resource runs require the
explicitly owned helper service and observe its real data/log directories.
Start it with `python3 -B tools/fdb_cluster.py start` and stop it after the run.
Namespaces are distinct new output paths; they are not database data paths.

The same operations compose directly:

```python
from g8_workload import prepare, profile, run, check, check_sources, offline

state = prepare(binary, new_directory, settings=profile(smoke=True))
try:
    result = run(state)
    check(result)
    check_sources(state)             # separate source-only oracle
    complete = offline(state, "complete")  # stops the process outside timing
finally:
    state["backend"].stop()
```

Import from the adjacent `tools` directory, for example with `PYTHONPATH=tools`.
`complete_epoch` also performs the quiescent rollback control, original-intent
receipt reconciliation, existing engine-work observation and final complete
thirteen-table check. `g8_observe.sample`, `check_resources`, `read_jsonl` and
`JsonlWriter` are usable without the runner. Reports describe trusted functions
and values; they never execute code from an artifact.

`g8_check.check_directory(directory)` independently consumes the saved raw
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

G6, TiKV, frontend, live providers, migrations, million-record envelope expansion,
native commit-ack injection, replicated failover and disk/power-loss infrastructure
remain outside these profiles. The existing bounds and the exact plan in
[paper 52](../research/52-workload-deployment-plan.md) apply.
