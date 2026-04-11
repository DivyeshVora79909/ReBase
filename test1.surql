USE NS main DB main;

-- STEP 1: SETUP HIERARCHY (Root -> Admin -> Managers -> Alice/Bob)
CREATE groups:root SET name = 'System Admins', role =[
    'node_create', 'node_select', 'node_update', 'node_delete',
    'link_create', 'link_select', 'link_delete'
];

CREATE user:admin SET name = 'Super Admin', email = 'admin@example.com';
UPDATE user:admin SET password = crypto::argon2::generate("admin123");
RELATE groups:root -> link -> user:admin;

CREATE groups:managers SET name = 'Managers', role =['node_select', 'node_update'];
RELATE user:admin -> link -> groups:managers;

CREATE user:alice SET name = 'Alice', email = 'alice@example.com';
CREATE user:bob SET name = 'Bob', email = 'bob@example.com';

RELATE groups:managers -> link -> user:alice;
RELATE groups:managers -> link -> user:bob;

-- STEP 2: RUN THE IDIOMATIC GRAPH CALCULATIONS
UPDATE user SET 
    dominates   = id.{..+collect}->link->(?).sort(),
    parents     = id<-link<-groups.distinct().sort(),
    permissions = (id<-link<-groups.role ??[]).flatten().distinct().sort();

SELECT id, dominates, parents, permissions FROM user;

-- STEP 3: TEST SAFE DELETION (Bob gets a 2nd parent, so deleting 1 is okay)
RELATE user:admin -> link -> user:bob;
LET $safe_link_to_delete = (SELECT VALUE id FROM link WHERE in = groups:managers AND out = user:bob LIMIT 1)[0];
DELETE $safe_link_to_delete;

-- Verify Bob's only parent is now user:admin
SELECT id, <-link<-groups AS bobs_parents FROM user:bob;

-- EXCEPTION TEST 1: ORPHAN CHECK
LET $last_link = (SELECT VALUE id FROM link WHERE in = user:admin AND out = user:bob LIMIT 1)[0];
DELETE $last_link;

-- EXCEPTION TEST 2: CYCLE CHECK
RELATE user:alice -> link -> user:admin;






-- ── After any link is created/deleted, refresh the affected node's RBAC cache ──
DEFINE EVENT OVERWRITE link_refresh_target ON TABLE link
    WHEN $event IN ["CREATE", "DELETE"] THEN {
    LET $target = IF $event = "CREATE" { $after.out } ELSE { $before.out };
    IF meta::tb($target) = 'user' {
        UPDATE $target SET last_refreshed_at = time::now();
    };
};



-- ── When a group's role changes, refresh every member user's RBAC cache ──
DEFINE EVENT OVERWRITE group_role_changed ON TABLE groups WHEN $event = "UPDATE"
    AND $before.role != $after.role THEN {

    -- Collect every user that is a transitive member of this group
    LET $affected_users = ($after.id.{..+collect}->link->user ?? []);

    FOR $u IN $affected_users {
        UPDATE $u SET last_refreshed_at = time::now();
    };
};