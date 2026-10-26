# The ReBase workshop

Run a small set of ordinary model workflows and compare the stored results with
simple source-side expectations. Each chapter uses its own disposable store.
The chapters are related examples; they do not share records or commit across
stores.

Build this checkout (source 0.15 or later); the historical 0.6 release bundle
does not contain this suite or the Quantity model:

The [N4 intent replay example](../tools/node/examples/n4-original-intent-replay.mjs) shows current logical replay composition; the public experiment functions are listed in [developer tools](developer-tools.md).

The walkthrough writes `result.json` and `summary.md`. The JSON keeps the exact
plans, observations, expected values, and source fingerprint. The Markdown is a
readable report of the same steps. UUIDs and exact quantities are strings in
JSON; contract and unit codes are numbers. Work totals describe measured work,
not the order in which the engine ran.

## Walkthrough

Use a new output directory for every run:

The [N4 intent replay example](../tools/node/examples/n4-original-intent-replay.mjs) shows current logical replay composition; the public experiment functions are listed in [developer tools](developer-tools.md).

The equipment chapter uses Pool `101`, Delivery `205`, and Reservation `410`.
At the E0 baseline, a delivery of 10 at time 0 gives A 8 units over `[10,30)`
and B 2 over `[20,40)`. Reservations read strictly before their start. Raising
the delivery to 12 gives A 8 and B 4. Moving A's end to 15 releases its units
before B starts, so B gets 7. A release exactly at 20 is outside B's strict
prefix; moving it to 19 is inside it. Two same-time reservations that make the
full history negative reject, while adding one alongside a delivery increase
is accepted after the final batch settles.

The sensor chapter uses Instrument `101`, Observation `211`, ObservationReport
`307`, and LatestObservation `419`. For observations `(0,5)`, `(10,12)`, and
`(20,-2)`, a report over `[0,20)` with threshold 5 has count 2, sum 17, minimum
5, maximum 12, and a true predicate. Moving the last observation to 15 brings
it into the report, making count 3 and the predicate false. An empty `[10,10)`
report publishes its declared unit, absent extrema, and false. A selector before
the first observation has an absent value; inserting an eligible observation
makes it present.

The quantity chapter uses Source `101`, Scale `205`, and Join `309`. Source 12
feeds exact half and third scales, so L=6, R=4, and Join=10. Editing Source to
18 gives 9, 6, and 15. Source 13 rejects atomically because the exact scales
would be fractional. Retargeting L to Join with factor zero still rejects with
`feedback`: the declared publication graph is cyclic even when the numeric
result might stay unchanged.

The service chapter uses Account and Dispatch with a fixed fake provider. It
checks two literal worker stories, including quota 12 edited to 10 in the
same mutation that creates a three-unit dispatch; confirmed success leaves
quota 7 exactly once. If quota 2 blocks applying a confirmed success, the
success fact remains recorded. Repairing quota to 5 applies that same fact once
and leaves quota 2 without another provider submission. The fake provider is a
test fixture, not a live integration.

## Checks and exploration

The check mode maps native test evidence to the workshop capabilities. It can
use a cached manifest of test executables whose binary and source fingerprints
match the current checkout:

The [N4 intent replay example](../tools/node/examples/n4-original-intent-replay.mjs) shows current logical replay composition; the public experiment functions are listed in [developer tools](developer-tools.md).

The default preparation path builds the Rust harnesses once when Cargo is available; when
it is unavailable, the report keeps native evidence incomplete. A missing
native harness exits 2 and is reported as incomplete. A failed walkthrough or
exact-value check exits 1. Subsequent runs can pass
`--native-manifest target/workshop-check/native-build/manifest.json` to reuse
those artifacts; their executable, runtime binary and source hashes must match.
Check also runs the existing full worker and signed-ingress process controls.

Explore quantities with a reproducible seed:

The [N4 intent replay example](../tools/node/examples/n4-original-intent-replay.mjs) shows current logical replay composition; the public experiment functions are listed in [developer tools](developer-tools.md).

The exploration is bounded and seeded, not exhaustive. It saves `exploration/artifact.json`
with the actions and plans. Replay it in a new output directory to reconstruct
the same logical actions against a fresh store, with newly bound contexts:

The [N4 intent replay example](../tools/node/examples/n4-original-intent-replay.mjs) shows current logical replay composition; the public experiment functions are listed in [developer tools](developer-tools.md).

On a mismatch, exploration retains the original and a bounded span-reduced
failure. Shrinking preserves the failure class and its valid preconditions; it
does not guarantee a globally smallest case. Original plans remain valid only
for their original target/context. Logical replay obtains new contexts for new
intents, then resends each repeated intent unchanged within that new run.

Earlier workshop campaigns imported case, oracle and exploration functions from
Python tooling, now retired. The current public JavaScript functions are listed
in [developer tools](developer-tools.md). `Scenario` in the historical campaign
owned one disposable backend. Reports contain final inventories and
measured counters, not an invented execution trace. Artifacts and credentials
stay in private fixture directories; do not publish a complete run directory.

Keep each `--out` path new; reports and artifacts are retained there. G6
accounting, G7 distributed storage, G8 release expansion, and frontend work
remain deferred.
