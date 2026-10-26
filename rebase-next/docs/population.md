# Bounded population

The public Node population helpers generate caller-owned proposals from a
prepared native model. They do not submit mutations or decide whether a
reference, permission, invariant or capacity limit is valid. The server remains
authoritative. The current helper surface is `preparePopulation`, `propose`,
`accept` and `reject` from [`tools/node/index.mjs`](../tools/node/index.mjs).
The complete [N3 example](../tools/node/examples/n3-population.mjs) shows one
composition. N6 bootstrap and release acceptance remain pending.

Population state is bounded by the compiled catalog's public record limit and
the caller's declared per-contract counts. Preparation validates the public
contract schemas, builds reproducible generators from a seed and keeps explicit
strategies separate from generated values. A proposal uses the current
operation context and caller-supplied relationships; the helper does not infer
authority from generated records. The server checks final records and all
cross-record rules transactionally.

Keep the proposal, exact operation plan and receipt together. A plan captures
its model, store, tenant, actor, credential epoch, context, operation ID and
commands. `accept` advances local population state only after the matching
definite commit receipt; `reject` returns the proposal to the appropriate local
state only for a definite no-commit result. Timeouts, transport loss and other
unknown outcomes require receipt reconciliation with the same plan and context.
They must not be treated as rejection or retried under a new operation ID.

`preparePopulation` does not persist jobs or provide crash recovery. Persist
client plans separately using `savePlan`; after restart, reload the exact plan
and ask the service for its operation status. It cannot turn a partial proposal
into a durable server-side population job.

## Model bounds

Calculation and Equipment each permit up to 4,096 public source records, 8,192
active private outputs and 16,384 retained output identity reservations. The
200,000 work-unit budget, query visit limit and receipt capacity still apply;
large causal closures can reject atomically. Invoicing is separately bounded
at 64 public sources, 256 outputs and 512 retained roles. These are enforced
model limits, not performance claims. See [Equipment](equipment.md),
[Invoicing](invoicing.md), [workload limits](workloads.md), and the dated
[G9 population evidence](../research/55-population-tooling-result.md) for its
original campaign results. The older Python value-provider workflow is retired;
use explicit authored strategies or the current caller-owned Node generator.
