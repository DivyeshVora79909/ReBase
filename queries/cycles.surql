-- @name Inspect authorization DAG
SELECT id, parents, dominates FROM user ORDER BY id;
SELECT id, parents, dominates FROM groups ORDER BY id;

-- @name Attempt direct self cycle
UPDATE user:replace_me SET parents = [user:replace_me] RETURN AFTER;

-- @name Attempt descendant cycle
UPDATE groups:replace_parent SET parents = [user:replace_descendant] RETURN AFTER;

-- @name Restore parents
UPDATE user:replace_me SET parents = [groups:root] RETURN AFTER;
