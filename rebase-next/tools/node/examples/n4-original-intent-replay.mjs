/**
 * Keep original-intent replay beside the scenario that owns its saved plans.
 * Known outcomes resend the exact saved plan. An uncertain write asks the
 * existing status operation and is never inferred rolled back or retried.
 */
export async function replayOriginalIntents(client, intents) {
  if (!client || typeof client.execute !== 'function' || typeof client.status !== 'function') {
    throw new TypeError('client must expose execute(plan) and status(plan)');
  }
  if (!Array.isArray(intents)) throw new TypeError('intents must be an array of saved plans and outcomes');
  const results = [];
  for (const { id, plan, outcomeUnknown = false } of intents) {
    if (!plan?.request?.operation_id || typeof plan.request.context !== 'string') {
      results.push({ id, status: 'incomplete', reason: 'original plan, operation ID or context was not retained' });
      continue;
    }
    if (outcomeUnknown) {
      const outcome = await client.status(plan);
      results.push({ id, status: outcome?.status === 'committed' ? 'status-reconciled' : 'incomplete', outcome, plan,
        ...(outcome?.status === 'committed' ? {} : { reason: 'original operation has no confirmed committed receipt; reconcile again without resubmission' }) });
      continue;
    }
    try {
      const outcome = await client.execute(plan);
      results.push({ id, status: outcome?.status === 'committed' ? 'original-plan-resubmitted' : 'incomplete', outcome, plan,
        ...(outcome?.status === 'committed' ? {} : { reason: 'original operation has no confirmed committed receipt; reconcile again without resubmission' }) });
    } catch (error) {
      if (error?.code !== 'outcome_unknown' && error?.name !== 'OutcomeUnknownError') throw error;
      const outcome = await client.status(plan);
      results.push({ id, status: outcome?.status === 'committed' ? 'status-reconciled' : 'incomplete', outcome, plan,
        ...(outcome?.status === 'committed' ? {} : { reason: 'original operation has no confirmed committed receipt; reconcile again without resubmission' }) });
    }
  }
  return Object.freeze({ status: results.some(row => row.status === 'incomplete') ? 'incomplete' : 'complete',
    results: Object.freeze(results) });
}
