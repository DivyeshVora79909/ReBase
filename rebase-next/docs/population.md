# Bounded population

The public Node population helpers generate caller-owned proposals from a
prepared native model. They do not submit mutations or decide whether a
reference, permission, invariant or capacity limit is valid. The server remains
authoritative. The current helper surface is `preparePopulation`, `propose`,
`accept` and `reject` from [`tools/node/index.mjs`](../tools/node/index.mjs).
The complete [N3 example](../tools/node/examples/n3-population.mjs) shows one
composition. N6 bootstrap and release acceptance are accepted within their
documented bounds; this does not claim unrestricted production capacity.

Population state uses u64 counters. Current compiled models configure no fixed
population ceiling; mutation work, query and receipt limits still apply. Full
inventory and check operations have a 262,144-row observation budget; this is
not a population admission ceiling. Preparation validates the public
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

Current models have no configured fixed public-record, output or reservation
ceilings. Other limits apply to their respective operations: full inventory
and check operations have a 262,144-row observation budget; mutations have a
200,000 work-unit budget and 64-command maximum; queries have 128 visits; the
active receipt window is 1,024; and returns and pages have 32-row limits. Large
causal closures can reject atomically. Computed model identity includes configured
limits; changing identity requires a new compatible store, and old stores are
rejected without automatic migration. See [Equipment](equipment.md),
[Invoicing](invoicing.md), [workload limits](workloads.md), and the dated
[G9 population evidence](../research/55-population-tooling-result.md) for its
original campaign results. Redb-connected end-to-end checks now cover 5,001 and
10,001 records in scoped tests, without claiming unrestricted or production
capacity. The older Python value-provider workflow is retired;
use explicit authored strategies or the current caller-owned Node generator.
