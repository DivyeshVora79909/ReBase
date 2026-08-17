// Privileged persistence and bounded authorization queries. Handlers never
// receive these queries or an unrestricted database connection.

const { readPredicate } = require("../../src/security-policy");

const actorFields = `
  id,
  permissions,
  z_access_index,
  array::distinct(array::flatten(parent_groups.capabilities ?? [])) AS capabilities,
  array::distinct(array::flatten([dominates ?? [], parent_groups.dominates ?? []])) AS dominates,
  parent_groups
`;

const actor = `
  RETURN (SELECT ${actorFields}
    FROM type::record($caller) LIMIT 1)[0];
`;

function resolveRecords(tables) {
  const tablePermission = tables
    .map((table) => `(record::tb(id) = '${table}' AND '${table}_select' IN $actor.permissions)`)
    .join(" OR ") || "false";
  const readable = readPredicate({ actor: "$actor" });
  return `
    LET $actor = (SELECT ${actorFields} FROM type::record($caller) LIMIT 1)[0];
    LET $record_ids = $ids.map(|$value| type::record($value));
    RETURN {
      auth: $actor,
      records: (SELECT * FROM $record_ids WHERE (${tablePermission}) AND ${readable})
    };
  `;
}

const createJob = `
  LET $now = time::now();
  LET $job_id = type::record('edge_job', rand::uuid::v7($now));
  LET $outbox_id = type::record('edge_outbox', rand::uuid::v7($now));
  LET $created = (CREATE $job_id CONTENT {
    capability: $capability,
    actor: type::record($caller),
    records: $records,
    args: $args,
    status: 'queued',
    max_attempts: $max_attempts,
    idempotency_key: $key
  })[0];
  CREATE $outbox_id CONTENT {
    job_id: $job_id,
    topic: 'edge.job',
    envelope: { jobId: <string>$job_id, capability: $capability },
    status: 'pending'
  };
  RETURN $created;
`;

const jobState = `
  RETURN {
    actor: (SELECT id, dominates FROM type::record($caller) LIMIT 1)[0],
    job: (SELECT * FROM type::record($job_id) LIMIT 1)[0]
  };
`;

const cancelJob = `
  LET $target = type::record($job_id);
  RETURN (UPDATE $target SET status = 'cancelled', finished_at = time::now(),
    lease_owner = NONE, lease_expires_at = NONE
    WHERE status IN ['queued', 'waiting'])[0];
`;

const cancelPendingOutbox = `
  UPDATE edge_outbox SET status = 'failed', last_error = 'JOB_CANCELLED'
    WHERE job_id = type::record($job_id) AND status = 'pending';
`;

const claimOutbox = `
  LET $jobs = SELECT * FROM edge_job
    WHERE status = 'waiting' AND next_run_at <= time::now()
    ORDER BY next_run_at LIMIT $limit;
  FOR $job IN $jobs {
    LET $promoted = (UPDATE $job.id SET status = 'queued'
      WHERE status = 'waiting' AND revision = $job.revision
        AND next_run_at <= time::now())[0];
    IF $promoted {
      LET $outbox_id = type::record('edge_outbox', rand::uuid::v7());
      CREATE $outbox_id CONTENT {
        job_id: $job.id,
        topic: 'edge.job',
        envelope: { jobId: <string>$job.id, capability: $job.capability },
        status: 'pending'
      };
    };
  };
  LET $ids = SELECT VALUE id FROM edge_outbox
    WHERE (status = 'pending' AND available_at <= time::now())
      OR (status = 'publishing' AND lease_expires_at <= time::now())
    ORDER BY available_at LIMIT $limit;
  FOR $id IN $ids {
    UPDATE $id SET status = 'publishing', lease_owner = $worker,
      lease_expires_at = time::now() + 1m, attempts += 1
      WHERE (status = 'pending' AND available_at <= time::now())
        OR (status = 'publishing' AND lease_expires_at <= time::now());
  };
  RETURN SELECT * FROM $ids
    WHERE status = 'publishing' AND lease_owner = $worker;
`;

const markOutboxPublished = `
  LET $target = type::record($id);
  RETURN (UPDATE $target SET status = 'published', published_at = time::now(),
    lease_owner = NONE, lease_expires_at = NONE
    WHERE lease_owner = $worker AND revision = type::uuid($revision)
      AND status = 'publishing')[0];
`;

const outbox = `RETURN (SELECT * FROM type::record($id) LIMIT 1)[0];`;

const failQueuedJob = `
  UPDATE type::record($job_id) SET status = 'failed',
    error = { code: 'OUTBOX_PUBLISH_FAILED', message: $message },
    finished_at = time::now()
    WHERE status = 'queued';
`;

const markOutboxFailed = `
  LET $target = type::record($id);
  RETURN (UPDATE $target SET
    status = IF $terminal THEN 'failed' ELSE 'pending' END,
    last_error = $message,
    lease_owner = NONE,
    lease_expires_at = NONE,
    available_at = time::now() + 1m
    WHERE lease_owner = $worker AND revision = type::uuid($revision)
      AND status = 'publishing')[0];
`;

const claimJob = `
  LET $target = type::record($id);
  RETURN (UPDATE $target SET status = 'running', lease_owner = $worker,
    lease_expires_at = time::now() + 10m, attempts += 1
    WHERE status = 'queued'
      OR (status = 'waiting' AND next_run_at <= time::now())
      OR (status = 'running' AND lease_expires_at <= time::now()))[0];
`;

const finishJob = `
  LET $target = type::record($id);
  RETURN (UPDATE $target SET status = $status, result = $result, error = $error,
    lease_owner = NONE, lease_expires_at = NONE,
    finished_at = IF $status IN ['succeeded', 'failed', 'cancelled'] THEN time::now() ELSE NONE END
    WHERE lease_owner = $worker AND revision = type::uuid($revision)
      AND status = 'running')[0];
`;

const retryJob = `
  LET $target = type::record($id);
  RETURN (UPDATE $target SET status = 'waiting', error = $error,
    lease_owner = NONE, lease_expires_at = NONE,
    next_run_at = time::now() + type::duration($delay)
    WHERE lease_owner = $worker AND revision = type::uuid($revision)
      AND status = 'running')[0];
`;

const webhook = `
  RETURN (SELECT * FROM edge_webhook_receipt
    WHERE dedupe_key = $key LIMIT 1)[0];
`;

const reclaimWebhook = `
  LET $target = type::record($id);
  RETURN (UPDATE $target SET status = 'processing', attempts += 1,
    lease_owner = $lease_owner, lease_expires_at = time::now() + 5m,
    result = NONE, error = NONE
    WHERE revision = type::uuid($revision)
      AND (status = 'failed' OR lease_expires_at <= time::now()))[0];
`;

const createWebhook = `
  LET $id = type::record('edge_webhook_receipt', rand::uuid::v7());
  RETURN (CREATE $id CONTENT {
    dedupe_key: $dedupe_key,
    capability: $capability,
    provider: $provider,
    provider_event_id: $provider_event_id,
    status: 'processing',
    attempts: 1,
    lease_owner: $lease_owner,
    lease_expires_at: time::now() + 5m
  })[0];
`;

const finishWebhook = `
  RETURN (UPDATE edge_webhook_receipt SET status = $status,
    result = $result, error = $error,
    lease_owner = NONE, lease_expires_at = NONE
    WHERE dedupe_key = $key AND lease_owner = $lease_owner
      AND status = 'processing')[0];
`;

const appendLog = `
  LET $id = type::record('edge_log', rand::uuid::v7());
  RETURN (CREATE $id CONTENT {
    request_id: $request_id,
    job_id: IF $job_id THEN type::record($job_id) ELSE NONE END,
    capability: $capability,
    phase: $phase,
    outcome: $outcome,
    actor: IF $actor THEN type::record($actor) ELSE NONE END,
    provider: $provider,
    duration_ms: $duration_ms,
    error_code: $error_code,
    data: $data
  })[0];
`;

module.exports = {
  actor,
  appendLog,
  cancelJob,
  cancelPendingOutbox,
  claimJob,
  claimOutbox,
  createJob,
  createWebhook,
  failQueuedJob,
  finishJob,
  finishWebhook,
  jobState,
  markOutboxFailed,
  markOutboxPublished,
  outbox,
  reclaimWebhook,
  resolveRecords,
  retryJob,
  webhook,
};
