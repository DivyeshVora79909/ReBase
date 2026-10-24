# G8 workload and deployment results

G8 implementation is explicitly assigned on 2026-10-25, on existing `main`.
Verified checkpoints are committed locally; the user requested no pushes.
[Paper 52](52-workload-deployment-plan.md) owns the scope and fault boundaries.
G7.0–G7.6 remain accepted and are reused where fingerprints and obligations match.

## G8.0 — bounded composition and preflight

The implementation provides ordinary prepare/run/check functions, one thin CLI,
finite seeded equipment trajectories, a source-only oracle, bounded private
streams, separate process/file observations, receipt-room preflight and explicit
resource checks. No core, wire, storage format or server endpoint changes.
The client only adds the observed HTTP status to its existing error objects;
it still makes one request, preserves saved contexts and never retries.

The [G8.0 evidence](evidence/2026-10-25-g80-workload-inputs.json) records short
real HTTP profiles and CLI/function composition equivalence. The accepted
executable remains G7.5's optimized feature-enabled binary, SHA-256
`288232e18700d24ef63c7db785f3aff51426a4c6e35b579a949f846d5a36b632`.
All accepted core/Cargo fingerprints match. Changed client/tool fingerprints are
identified separately; unchanged G7 native campaigns are not repeated.

Twenty-one focused Python controls cover feasible/unknown/unbounded inputs, missing
backend/SDK, missing/truncated observations, original PID continuity and resource
budget violations, including an injected excessive-growth checker control. Six
existing client controls pass with the added HTTP-status observation. An actual
missing-native-library preflight returns a clear failure. This is a negative
control, not an unsupported successful run.

Two initial failed smoke trials remain retained: an invalid interval produced
`invalid_input`, so the deliberate invariant witness now uses valid simultaneous
reservations whose complete-time balance becomes negative; the complete integrity
count includes native private outputs, so its expectation now checks public
sources plus active outputs. Neither correction changes product behavior.

[The guide](../docs/workloads.md) records the exact default profiles and budgets.
The short baseline selects budgets before any G8.1 measurement. It is labeled
short smoke evidence and establishes no 300-second acceptance yet. Continuous
memory epochs and offline receipt/archive lifecycles remain separate.

## Continuation

Next is G8.1: default 300-second epochs on all three selected adapters and two
real full receipt/archive cycles per adapter, then G8.2–G8.5 in checkpoint order.
One coordinator owns Cargo (two jobs, incremental off, matching shared cache).
Delegated files have explicit ownership; load measurements use one host/cluster
at a time. G6, TiKV, frontend, million-record expansion and unprovided native
commit-ack, replicated and power-loss fault infrastructure remain deferred.
