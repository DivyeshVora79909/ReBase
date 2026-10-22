# From the accepted native slice to a usable local prototype

**Completed P1–P4, 2026-10-22.** [Paper 16](16-local-prototype-result.md) and its
evidence record acceptance; [the guide](../docs/local-prototype.md) runs it.
The plan below preserves the completion contract. The user confirmed a usable local
prototype with the calculation engine, model tooling, mutation/query API and a
demonstrable workflow. Continue through the stages below without treating each
stage as a new permission boundary. Existing ReBase/MetaSol remain read-only.
The accepted starting point is `2109687`; paper 12 and its evidence stay dated.

## 1. Completion contract

A fresh checkout must build one local executable, explain/export its supported
model without opening a store, create a named disposable demo, run exact
transactional mutations and bounded reads, and demonstrate the resulting values.
Developer inspection must distinguish public contracts from private roles.
Invalid input, stale versions, feedback and invalid histories must fail without
partial publication. Restart must preserve accepted state and model identity.

The prototype uses an explicit local actor/tenant and embedded redb. It is not
a production authentication service or a distributed adapter. General money
rounding, untrusted behavior, externally delivered effects, migrations and a
full accounting/UI port retain their existing gates. These exclusions do not
excuse leaving a claimed local command or workflow unfinished.

| Stage | Concrete result and acceptance |
| --- | --- |
| P1: native causal settlement | Implement paper 9's moved readers, managed outputs and reporting diamond in the same transaction/tree engine. Compare complete real snapshots against an independent source oracle; test private identity/lifecycle, late rejection and reopen. |
| P2: prepared model and tooling | Resolve supported declarations, schemas, stable codes and trusted behavior before use. Export separate public/developer catalogs and explanations. Model changes reject incompatible stores; offline tooling does not activate or mutate them. |
| P3: local runtime and API | A reusable redb adapter and runnable local interface provide exact create/update/delete, get, root reads, bounded page/exists and explicit mutation outcomes. Protect private state, enforce versions and bind resumptions to the promised snapshot/revision boundary. |
| P4: demonstrable workflow and closure | Supply an executable demo and developer view using those same operations. Exercise input, mutation, stale/error, restart and inspection paths. Record independent evidence and update routing with the actual supported limits. |

## 2. P1 model extension

Keep ordinary typed modules and reuse the point workspace and linked AVL code.
New calculation shape depends only on authored values or a direct `Moment.at`;
ordered results never choose their own future query/root/key. Account roots use
the existing history slot and unit checks, so original postings can feed causal
readers. Their quote/coefficient calculations form an earlier fixed stratum.

| Code | Authored fields and meaning |
| --- | --- |
| 7 Moment | Exact `at`; a direct date source. |
| 8 Entry | `account`, exact `at`, exact bounded `amount`; one authored history contribution. |
| 9 Adjustment | `account`, `moment`, exact `offset`, exact bounded `target`, boolean `post`. Resolve time with checked addition. Calculate `delta = target - before(account, time)`. A distinct validation query reads the same strict prefix and requires it nonnegative. |
| 10 Basis | One or two ordered `sources`, exact factor 1–3, `account`, exact `at`, and nullable `feedback`. Calculate factor times the sum of named whole-root reads. The normal required output posts at `account/at`; optional feedback describes an additional zero-valued output with a declared dependency on this value. |
| 11 Pin | Trusted fixture-only `output` reference with REJECT deletion semantics; ordinary client operations cannot create or address this contract. |
| 12 Output | Engine-only `producer`, `role`, `account`, exact `at/amount`. One separately identified private record and one history membership. Public mutations and ordinary get/page must not expose it. |

Feedback is either `null` or `{account, at}` and keeps its declared dependency
even when the emitted amount is zero. Each basis source position keeps its own
query slot, including equal source roots. Account units must agree. All exact
numbers retain canonical strings, checked arithmetic and the full `i64` time
range. Entry amounts/adjustment targets/offsets have explicit bounded inputs;
calculated `i128` overflow rejects the attempt.

Limits remain explicit: 64 authored records, at most 16 of each calculated
source kind, 16 quotes/postings, and a bounded number of lifetime output
reservations. Private outputs are counted separately. These limits bound the
experiment; they are not advertised capacity.

## 3. Discovery, ordering and lifecycle algorithm

1. Stage authored commands and point-owned reverse references. Earlier staged
   creations remain visible; forward references and already deleted targets
   reject. Install new empty headers. Delay final inbound deletion decisions
   until managed outputs have been reconciled.
2. Finish quote/posting changes and authored entries using the existing paths.
   Collect logically affected roots. Seed causal work with changed readers/bases,
   direct readers of changed moments and old/new root subscribers.
3. Expand the closure through old/new output destinations and subscriber lists.
   Conservative per-root discovery is acceptable within the declared limits;
   mutation discovery must not enumerate the whole physical database.
4. Resolve final query bounds and output positions for the closure. Build edges
   from each pending final output to each calculation query that actually
   consumes its root/time. Validation queries create no calculation edges.
   Reject cycles in this final graph, including zero feedback. Old/new union
   only discovers work; it never decides feedback.
5. Detach every old managed occurrence of the affected closure. Retain final
   pending shapes separately; absence from the working tree is not a settled
   zero. Evaluate ready sources in a deterministic topological order and install
   their outputs. Prefix lookup excludes every equal-time occurrence and uses
   subtree aggregates without timestamp sentinels.
6. Refresh terminal queries, apply final reference/lifecycle checks, validate
   complete account histories, stamp semantic versions and root revisions,
   encode final dirty keys, and release results only after successful commit.

Role identity is `(producer UUID, role code)` with a transactionally allocated,
collision-checked UUID. Retain reservations across disable/reenable. A second
private index prevents public creations from claiming an inactive reserved ID.
Deletion retires its role reservations so an old identity cannot silently become
a new private output. Causal source identities with retired roles cannot be
recreated; ordinary source reuse retains paper 11's version rules. Reservation
work is bounded and belongs to the same atomic state as source/output changes.
Use OS UUID randomness in the executable and explicit allocation sequences in
the test adapter to exercise collisions and failure deterministically.

## 4. Independent evidence and affected surfaces

Extend the source oracle and raw checker for the new contracts, query bounds,
role reservations and private record inventory. Expected output bindings come
from the independent command/allocation history, never from native role maps.
Preserve the earlier M3/M5 arithmetic oracle and M6 controls unchanged. The new
native corpus must include the baseline, swap, one-reader move, reparent,
disable/reenable, zero value, same-time readers, shared moment edits, diamond,
zero feedback, surviving pin and parent-first lifecycle operations.

Keep a disconnected component to test that native discovery leaves unrelated
source versions and roots untouched. Exercise allocation collisions, private
write attempts, timestamp overflow, work exhaustion and abort after physical
writes. Export every application row, including retired reservations. Reopen
and run the same checker; an unobserved namespace is incomplete, never valid.

Changing the codec/model inputs intentionally invalidates the previous source
fingerprint; preserve its dated evidence and produce a new result for the
extended implementation. The existing 93 native operations remain a focused
integration regression once these capabilities are connected. Run only the
affected boundary while developing, then the locked integrated suite, format
and Clippy once ready. All artifacts stay under `rebase-next/target/`.

P2–P4 must define their concrete request/catalog/cursor shapes before coding
them. The existing API/tooling and lifecycle papers supply requirements rather
than a reason to add an unbounded framework or silently assume production
authority. Current progress belongs in CONTEXT and the final execution report.
