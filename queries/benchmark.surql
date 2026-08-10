-- @name Exact reader lookup
SELECT id FROM test_primitive
WHERE readers_index CONTAINS <string>$auth
LIMIT 50;

-- @name Dynamic owner access
SELECT id FROM test_primitive
WHERE owned_by = $auth
   OR owned_by IN $auth.parent_groups
   OR owned_by IN $auth.dominates
LIMIT 50;

-- @name Reader and owner access
SELECT id FROM test_primitive
WHERE readers_index CONTAINS <string>$auth
   OR owned_by = $auth
   OR owned_by IN $auth.parent_groups
   OR owned_by IN $auth.dominates
LIMIT 50;

-- @name Business filter and authorization
SELECT id, a_enum, updated_at FROM test_primitive
WHERE a_enum = 'active'
  AND (
    readers_index CONTAINS <string>$auth
    OR owned_by = $auth
    OR owned_by IN $auth.parent_groups
    OR owned_by IN $auth.dominates
  )
ORDER BY updated_at DESC
LIMIT 50;
