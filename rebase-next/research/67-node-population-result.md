# N3 — Node population and scenario functions

Status: **N3 accepted on 2026-10-25 within the recorded population and workload
bounds.** N3 adds four ordinary exports in `tools/node/population.mjs`:
`preparePopulation`, `propose`, `accept` and `reject`. They operate on a prepared
native model and caller-owned state. They do not create a service, submit a
mutation, refresh stale context, or retry a lost request. Native validation and
receipts remain authoritative.

An ordinary caller composes the functions in JavaScript, retaining the exact
proposal and saved plan until the result is known:

```js
import { preparePopulation } from './tools/node/population.mjs';
import { commitPopulationProposal } from './tools/node/examples/n3-population.mjs';

const state = preparePopulation(model, { Source: 1, Scale: 1, Join: 1 }, {
  seed: 'quantity-demo',
  batchSize: 1,
  strategies: {
    Source: () => ({ value: '12' }),
    Scale: () => ({ factor: { numerator: '1', denominator: '2' }, rounding: 'half_even' }),
    Join: () => ({}),
  },
});
const result = await commitPopulationProposal({
  model, client, state, context: {}, planPath: '/tmp/source.plan.json',
});
```

`commitPopulationProposal` is an example composition helper. The package's
population API remains the four functions above. Callers choose quotas, seeds,
clocks, typed existing anchors, strategy and rule callbacks, context reads,
selection behavior, and plan paths. Proposal state advances only after binding
the exact saved plan and accepting a committed response whose operation ID and
ordered returned IDs match. A known native no-commit error can release a bound
proposal; unknown outcomes retain the original plan for caller reconciliation.
The example helper checks status after an unknown execute result and accepts
only a confirmed committed receipt; unresolved status returns the original
state, proposal and plan to the caller. No hidden retry or generated parent is
added.

The focused N3 suite passed on Node 24.22.1 with the unchanged N2 native binary
`target/n2-native-default/rebase-next`, SHA-256
`74b816d1f72dff333c76633420da35e5e08daf3c087a06abc6d38a07cd39ae5e`. The
focused `npm run test:n3` run passed 10 tests: eight semantic/contract controls
and two real workflows, with no failures or skips. Root's final full Node 24 run
passed 68/68 tests with zero failures or skips against the same frozen native
binary; the exact command, duration and retained output are in the
[N3 evidence](evidence/2026-10-25-n3-population.json). The combined client,
model and N3 controls passed 23/23; a separate client/model check passed 13/13
after the example's status reconciliation update. Independent Sol review
verified eight controls and the frozen source with no blockers. Syntax checks
passed. No Rust source changed and no Cargo build was run. Final source
fingerprints and commands are in the evidence record.

The Equipment workflow begins with a real committed Pool anchor, uses a custom
typed selector to create a Delivery, then submits a deliberately invalid
Reservation using stale context. Native `invalid_input` rejects it without
advancing population state. The test verifies the saved original plan remains
bound through an uncertain result, refuses plan rebinding, and only advances
after an exact receipt. Each committed operation returns one record.

The Quantity workflow commits a Source whose public value is exact string `12`.
An asynchronous parent read derives a rational `24/12` Scale target from that
observed value. A concurrent update changes the parent to
`1000000000000000000`; native validation returns `overflow` and the Scale quota
does not advance. After restoring the Source to `12`, a fresh read derives the
correct `6/12` rational, then Scale and Join commit. The returned native receipt
uses `{status:'committed', result:{operation_id, revision, records}}`; the
population code checks the exact operation ID and ordered record IDs before it
advances quotas, pools, reference usage or the attempt cursor.

Semantic controls cover seeded generator isolation across interleaved states,
explicit clocks, async callback serialization, typed anchor projections,
custom selectors, quotas and command/byte limits, nested wildcard and optional
references, self and polymorphic targets, blocked prerequisites, large exact
decimal strings, malformed or mutated plans, rebound plans, reordered receipts,
unknown outcome retention, and exact single advancement. `json-schema-faker`
produces base shape only; explicit strategies handle unsupported or unsuitable
values. The Equipment and Quantity real store trajectories use explicit
strategies; a separate Faker-generated Equipment proposal is shape-checked but
not claimed as a globally valid business operation. Schema validity does not
guarantee global validity, and native checks remain required.

Generation of `n` records requires at least O(n) work. Default typed pool
selection indexes retained IDs; a custom reference selector currently receives
a materialized view of compatible pool rows and therefore costs O(pool size)
time and memory for that operation. No universal constant-time or validity
claim is made. The final full-suite stdout is retained in the evidence directory;
no receipt dump or transient database image was kept. Test-created stores,
plans and backups were removed in `finally`. Failed intermediate trials
were corrected before the final runs: an undefined clock was placed in strategy
context, a proposal digest included itself, the client response wrapper was
misread, a native rejection was expected under a stale error code, and an
attempt-count assertion ran before acceptance. The exact final source, tests and
example are fingerprinted in the evidence record.

N4 experiments and independent checking are next. N5 packaging and N6 Python
and legacy CLI retirement remain pending. No Python workflow is deleted before
N6. S0–S3 ordered-storage work and deferred G6, frontend, live providers, TiKV,
populated migrations and unrestricted capacity remain pending or deferred.
