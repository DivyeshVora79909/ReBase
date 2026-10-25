import { savePlan } from '../client.mjs';
import { accept, propose } from '../population.mjs';

/**
 * Compose one population mutation from ordinary Node functions.
 *
 * The caller creates `model` with prepareModel(native.catalog(...)), connects a
 * client, and owns `state` from preparePopulation. `context` may read through
 * that client after typed references have been selected. The caller chooses
 * where to save the original plan and can retain `state`, `proposal`, and
 * `plan` if execution has an unknown outcome.
 */
export async function commitPopulationProposal({ model, client, state, context, planPath }) {
  const proposal = await propose(state, context);
  const plan = await client.prepare({
    model: model.identity,
    commands: proposal.commands,
    returning: proposal.returning,
  });
  await savePlan(planPath, plan);
  state.pending.plan = plan;
  let receipt;
  let reconciled = false;
  try {
    receipt = await client.execute(plan);
  } catch (error) {
    if (error.code !== 'outcome_unknown') throw error;
    let status;
    try {
      status = await client.status(plan);
    } catch (statusError) {
      return { outcome: 'unknown', state, proposal, plan, statusError };
    }
    if (status.status !== 'committed') return { outcome: 'unknown', state, proposal, plan, status };
    receipt = status;
    reconciled = true;
  }
  accept(state, proposal, plan, receipt);
  return { outcome: 'committed', reconciled, state, proposal, plan, receipt };
}
