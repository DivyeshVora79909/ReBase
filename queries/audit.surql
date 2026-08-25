-- Append an operational action from a trusted worker/admin session.
LET $now = time::now();
CREATE audit_action CONTENT {
    at: $now,
    source: 'cloudflare.worker',
    action: 'example.completed',
    status: 'success',
    actor: NONE,
    target: NONE,
    correlation: NONE,
    data: {}
};

-- Recent mutation history for one record uses the target index.
SELECT * FROM audit_mutation
WHERE target = test_primitive:example
ORDER BY id DESC
LIMIT 100;

-- UUIDv7 boundaries narrow the scan. The one-millisecond padding avoids
-- excluding records whose random UUID bits fall outside an exact boundary;
-- the at predicate preserves the precise requested window.
LET $from_at = time::now() - 24h;
LET $until_at = time::now();
LET $from_id = rand::uuid::v7($from_at - 1ms);
LET $until_id = rand::uuid::v7($until_at + 1ms);
SELECT * FROM type::record('audit_mutation', $from_id)..type::record('audit_mutation', $until_id)
WHERE at >= $from_at AND at < $until_at;
