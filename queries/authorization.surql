-- @name Current identity state
RETURN $auth;
SELECT id, parents, parent_groups, permissions, dominates, z_access_index FROM ONLY $auth;

-- @name Visible users and groups
SELECT id, name, parents FROM user ORDER BY name;
SELECT id, name, parents, role FROM groups ORDER BY name;

-- @name Owned and reader-visible primitives
SELECT id, owned_by, readers, readers_index, a_string
FROM test_primitive
ORDER BY id
LIMIT 100;

-- @name Ownership update probe
UPDATE test_primitive:replace_me
SET a_string = 'updated from workbench'
RETURN AFTER;

-- @name Ownership transfer probe
UPDATE test_primitive:replace_me
SET owned_by = user:replace_me
RETURN AFTER;

CREATE user:admin
SET email = 'divy.r.vora14@gmail.com', name = 'Divyesh Vora', password = crypto::argon2::generate('password'), parents = [groups:root], login_access = true, username = 'divyeshvora_123'
RETURN AFTER;