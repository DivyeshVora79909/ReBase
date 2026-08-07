# Permission Query Performance

These findings were measured on SurrealDB 3.2.0. Re-run `npm run benchmark` after changing SurrealDB versions, ownership representation, ACL indexes, or common query shapes.

## Security boundary

Polymorphic ownership uses `record<user | groups>`. Every resource materializes its mixed readers as strings:

```surrealql
readers_index = readers.map(|$reader| <string>$reader)
```

The authoritative readers-mode RLS predicate is:

```surrealql
readers_index CONTAINSANY $auth.z_access_index
```

`z_access_index` contains the authenticated user, immediate parents, and dominated users/groups.

## Observed plans

### Dynamic ACL array

```surrealql
SELECT id FROM resource
WHERE readers_index CONTAINSANY $auth.z_access_index
LIMIT 50
EXPLAIN FULL;
```

SurrealDB 3.2 reports `TableScan` for the dynamic auth array. Correct RLS does not imply an index scan.

### Scalar ACL branches

```surrealql
LET $r0 = $auth.z_access_index[0];
LET $r1 = $auth.z_access_index[1];

SELECT id FROM resource
WHERE readers_index CONTAINS $r0
   OR readers_index CONTAINS $r1
LIMIT 50;
```

Scalar branches can use `readers_index.*` and cost approximately `O(m log n + candidates)`, where `m` is access-index length and `n` is table size.

### Selective business filter and sort

```surrealql
SELECT * FROM invoice
WHERE status = 'posted'
ORDER BY created_at DESC
LIMIT 50;
```

A matching composite business index can reduce candidates before RLS is applied as a residual filter. This is normally the best query shape when the business predicate is selective.

## Practical policy

- Lead with selective business filters and matching sort indexes.
- Use scalar ACL fan-out for permission-dominated queries with a narrow access index.
- A dynamic ACL scan can be competitive for small tables, wide ACLs, and early limits.
- Benchmark counts, exports, first-page queries, and rare-reader queries separately.
- Confirm index use with `EXPLAIN FULL`; response time alone does not prove the plan.
- Keep indexes on `readers_index.*`, not directly on mixed record arrays.

On a 5,000-row synthetic table, representative median database times were approximately 13.2 ms for the dynamic auth scan, 3.3 ms for scalar reader branches, and 0.6 ms for a selective composite business index. Treat these as directional, not universal.
