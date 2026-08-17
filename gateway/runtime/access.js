function values(value) {
  return Array.isArray(value) ? value.map(String) : [];
}

function canAccessJob(actor, job) {
  if (!actor?.id || !job?.actor) return false;
  const owner = String(job.actor);
  return owner === String(actor.id) || values(actor.dominates).includes(owner);
}

function hasCapability(actor, capability) {
  return Boolean(capability) && values(actor?.capabilities).includes(capability);
}

module.exports = {
  canAccessJob,
  hasCapability,
};
