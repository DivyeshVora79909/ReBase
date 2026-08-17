-- @name Exact reader lookup
SELECT id FROM test_primitive
WHERE readers_index CONTAINSANY $auth.z_access_index
LIMIT 50;

-- @name Dynamic owner access
SELECT id FROM test_primitive
WHERE <string>owned_by IN $auth.z_access_index
LIMIT 50;

-- @name Reader and owner access
SELECT id FROM test_primitive
WHERE readers_index CONTAINSANY $auth.z_access_index
   OR <string>owned_by IN $auth.z_access_index
LIMIT 50;

-- @name Business filter and authorization
SELECT id, a_enum, updated_at FROM test_primitive
WHERE a_enum = 'active'
  AND (
    readers_index CONTAINSANY $auth.z_access_index
    OR <string>owned_by IN $auth.z_access_index
  )
ORDER BY updated_at DESC
LIMIT 50;
