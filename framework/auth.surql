-- Authorization graph and principal fields.
-- Authentication identities and challenges are declared in authentication.surql.

-- A design has one database and any number of explicitly provisioned tenants.
-- The compiler replaces this function with the design's complete permission set.
DEFINE FUNCTION OVERWRITE fn::rebase::tenant_permissions() {
    RETURN ['node_create', 'node_select', 'node_update', 'node_delete'];
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE rebase_tenant SCHEMAFULL PERMISSIONS
    FOR select WHERE $auth AND id = $auth.tenant
    FOR create, delete NONE
    FOR update WHERE $auth AND id IN $auth.parents AND 'node_update' IN $auth.permissions;
DEFINE FIELD OVERWRITE id ON rebase_tenant TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();
DEFINE FIELD OVERWRITE name ON rebase_tenant TYPE string VALUE string::trim($value ?? '') ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE tenant ON rebase_tenant TYPE record<rebase_tenant> VALUE $this.id READONLY;
DEFINE FIELD OVERWRITE role ON rebase_tenant TYPE array<string> VALUE fn::rebase::tenant_permissions()
    PERMISSIONS FOR create, update NONE;
DEFINE FIELD OVERWRITE authorization_depth ON rebase_tenant TYPE int VALUE 0 PERMISSIONS FOR create, update NONE COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE authorization_revision ON rebase_tenant TYPE int DEFAULT 0 ASSERT $value >= 0 PERMISSIONS NONE COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE created_at ON rebase_tenant TYPE datetime VALUE $before OR time::now() READONLY;

-- Closure pairs use exact record keys. Native relation adjacency is used only
-- when graph maintenance needs all ancestors or descendants. Record users can
-- inspect their own pairs but cannot write authorization state.
DEFINE TABLE OVERWRITE rebase_access TYPE RELATION
    IN rebase_tenant | rebase_user | rebase_group OUT rebase_user | rebase_group
    SCHEMAFULL PERMISSIONS FOR select WHERE in = $auth FOR create, update, delete NONE;
DEFINE FIELD OVERWRITE in ON rebase_access TYPE record<rebase_tenant | rebase_user | rebase_group>
    REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE out ON rebase_access TYPE record<rebase_user | rebase_group>
    REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE tenant ON rebase_access TYPE record<rebase_tenant>
    VALUE $this.in.tenant ASSERT $value = $this.out.tenant;

DEFINE FUNCTION OVERWRITE fn::rebase::dominates($actor: record, $target: record) {
    RETURN $actor != $target AND record::exists(type::record('rebase_access', [$actor, $target]));
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::rebase::can_access($actor: record, $target: record) {
    RETURN $actor = $target OR $target IN $actor.parent_groups OR fn::rebase::dominates($actor, $target);
} PERMISSIONS FULL;

-- Readers are immediate owners, never another record's read_by. Keep the first
-- incomparable candidate; a later descendant replaces its ancestor. Groups are
-- the explicit way to represent deliberate shared access across branches.
DEFINE FUNCTION OVERWRITE fn::rebase::reader_owner($source: record) {
    RETURN IF record::tb($source) IN ['rebase_tenant', 'rebase_user', 'rebase_group']
        THEN $source ELSE $source.owned_by END;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::choose_reader($candidates: array, $fallback: record) {
    RETURN $candidates.filter(|$candidate| $candidate != NONE).fold(NONE, |$chosen, $candidate| {
        RETURN IF $chosen = NONE OR fn::rebase::dominates($chosen, $candidate)
            THEN $candidate ELSE $chosen END;
    }) ?? $fallback;
} PERMISSIONS FULL;

-- Replaced by the compiler with bounded REFERENCE backlink routes.
DEFINE FUNCTION OVERWRITE fn::rebase::refresh_readers($principals: array<record>) {
    RETURN NONE;
} PERMISSIONS NONE;

-- A direct parent can be usable for ownership without granting node_select.
-- Valid DAG membership already proves its tenant, so no hidden owner read is
-- needed for a record client's derived fields. System writes read the owner.
DEFINE FUNCTION OVERWRITE fn::rebase::owner_tenant($owner: record) {
    IF $auth AND fn::rebase::can_access($auth, $owner) { RETURN $auth.tenant; };
    RETURN $owner.tenant;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::rebase::principal_tenant($parents: array<record>) {
    LET $tenants = array::distinct($parents.map(|$parent| fn::rebase::owner_tenant($parent)));
    IF $tenants.len() != 1 OR $tenants[0] = NONE { THROW 'ERR_TENANT_PARENTS'; };
    RETURN $tenants[0];
} PERMISSIONS FULL;

-- USER
DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth AND tenant = $auth.tenant AND 'node_create' IN $auth.permissions
    FOR select WHERE $auth AND tenant = $auth.tenant AND (id = $auth OR ('node_select' IN $auth.permissions AND fn::rebase::dominates($auth, id)))
    FOR update WHERE $auth AND tenant = $auth.tenant AND (id = $auth OR ('node_update' IN $auth.permissions AND fn::rebase::dominates($auth, id)))
    FOR delete WHERE $auth AND tenant = $auth.tenant AND 'node_delete' IN $auth.permissions AND fn::rebase::dominates($auth, id)
    COMMENT '@rebase-members fn::rebase::username_members';

    DEFINE FIELD OVERWRITE id ON rebase_user TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();
    DEFINE FIELD OVERWRITE name ON rebase_user TYPE string VALUE {
        LET $clean_name = string::trim($value ?? "");
        IF !$clean_name { THROW "VALIDATION_ERR: Invalid Name"; };
        RETURN $clean_name;
    };

    DEFINE FIELD OVERWRITE username ON rebase_user TYPE option<string> DEFAULT NONE VALUE {
        IF $value = NONE { RETURN NONE; };
        LET $clean_username = string::lowercase(string::trim($value));
        IF !string::matches($clean_username, /^[a-z0-9][a-z0-9_.-]{8,31}$/) {
            THROW "VALIDATION_ERR: Invalid username";
        };
        RETURN $clean_username;
    } ;

    DEFINE FIELD OVERWRITE login_access ON rebase_user TYPE bool DEFAULT true
        PERMISSIONS FOR update WHERE id != $auth;

    -- A password is one credential option, not the authenticated-state flag.
    -- NONE is valid while a delivered email/phone challenge or OAuth is used.
    DEFINE FIELD OVERWRITE password ON rebase_user TYPE option<string>
        DEFAULT NONE
        PERMISSIONS FOR select NONE FOR create, update NONE
        ;

    -- Incremented by authentication events when a credential/identity changes.
    -- It is private and is used to fence outstanding challenges.
    DEFINE FIELD OVERWRITE authentication_revision ON rebase_user TYPE int
        DEFAULT 1
        VALUE {
            IF $before = NONE { RETURN 1; };
            RETURN $value;
        }
        ASSERT $value >= 1
        PERMISSIONS FOR select NONE FOR create WHERE true FOR update NONE
         COMMENT '@rebase-system';

    DEFINE FIELD OVERWRITE parents ON rebase_user TYPE array<record<rebase_tenant | rebase_user | rebase_group>>
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE array::distinct($value ?? [])
        -- Validate only edges introduced or removed by this mutation. Existing
        -- edges may be invisible to a dominating actor.
        ASSERT $value.len() > 0
            AND array::all(array::difference($value ?? [], $before ?? []), |$parent|
                IF $auth THEN fn::rebase::can_access($auth, $parent) ELSE record::exists($parent) END)
        REFERENCE ON DELETE REJECT
        PERMISSIONS FOR update WHERE id != $auth
        COMMENT '@rebase-reference-delta';

    DEFINE FIELD OVERWRITE tenant ON rebase_user TYPE record<rebase_tenant>
        VALUE IF $before != NONE THEN $before ELSE fn::rebase::principal_tenant($this.parents) END
        READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;
    DEFINE FIELD OVERWRITE authorization_depth ON rebase_user TYPE int DEFAULT 1
        VALUE IF $before = NONE THEN 1 ELSE $value END ASSERT $value >= 1
        PERMISSIONS FOR create WHERE true FOR update NONE COMMENT '@rebase-system';

    DEFINE FIELD OVERWRITE parent_groups ON rebase_user TYPE array<record<rebase_tenant | rebase_group>>
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) IN ['rebase_tenant', 'rebase_group']))
        PERMISSIONS FOR create, update NONE
        ;

    DEFINE FIELD OVERWRITE permissions ON rebase_user TYPE array<string>
        VALUE array::distinct(array::flatten($this.parent_groups.role ?? [])).filter(|$permission| $permission != NONE)
        PERMISSIONS FOR create, update NONE
        ;

    DEFINE FIELD OVERWRITE created_at ON rebase_user TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON rebase_user TYPE datetime VALUE IF $before = NONE THEN time::now() ELSE $value END
        PERMISSIONS FOR select, create WHERE true FOR update NONE ;
    DEFINE FIELD OVERWRITE created_by ON rebase_user TYPE option<record<rebase_user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON rebase_user TYPE option<record<rebase_user>>
        PERMISSIONS FOR select WHERE true FOR create, update NONE ;
    REMOVE INDEX IF EXISTS idx_user_username ON rebase_user;

-- GROUPS
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth AND tenant = $auth.tenant AND 'node_create' IN $auth.permissions
    FOR select WHERE $auth AND tenant = $auth.tenant AND 'node_select' IN $auth.permissions AND fn::rebase::can_access($auth, id)
    FOR update WHERE $auth AND tenant = $auth.tenant AND 'node_update' IN $auth.permissions AND fn::rebase::dominates($auth, id)
    FOR delete WHERE $auth AND tenant = $auth.tenant AND 'node_delete' IN $auth.permissions AND fn::rebase::dominates($auth, id)
    ;

    DEFINE FIELD OVERWRITE id ON rebase_group TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();
    DEFINE FIELD OVERWRITE name ON rebase_group TYPE string VALUE {
        LET $clean_name = string::trim($value ?? "");
        IF !$clean_name { THROW "VALIDATION_ERR: Invalid Name"; };
        RETURN $clean_name;
    };
    DEFINE FIELD OVERWRITE role ON rebase_group TYPE array<string> DEFAULT [] VALUE array::distinct($value ?? []);
    DEFINE FIELD OVERWRITE parents ON rebase_group TYPE array<record<rebase_tenant | rebase_user | rebase_group>>
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE array::distinct($value ?? [])
        ASSERT $value.len() > 0
            AND array::all(array::difference($value ?? [], $before ?? []), |$parent|
                IF $auth THEN fn::rebase::can_access($auth, $parent) ELSE record::exists($parent) END)
        REFERENCE ON DELETE REJECT
        PERMISSIONS FOR update WHERE id != $auth
        COMMENT '@rebase-reference-delta';

    DEFINE FIELD OVERWRITE tenant ON rebase_group TYPE record<rebase_tenant>
        VALUE IF $before != NONE THEN $before ELSE fn::rebase::principal_tenant($this.parents) END
        READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;
    DEFINE FIELD OVERWRITE authorization_depth ON rebase_group TYPE int DEFAULT 1
        VALUE IF $before = NONE THEN 1 ELSE $value END ASSERT $value >= 1
        PERMISSIONS FOR create WHERE true FOR update NONE COMMENT '@rebase-system';
    DEFINE FIELD OVERWRITE parent_groups ON rebase_group TYPE array<record<rebase_tenant | rebase_group>>
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) IN ['rebase_tenant', 'rebase_group']))
        PERMISSIONS FOR create, update NONE
        ;

    DEFINE FIELD OVERWRITE created_at ON rebase_group TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON rebase_group TYPE datetime VALUE IF $before = NONE THEN time::now() ELSE $value END
        PERMISSIONS FOR select, create WHERE true FOR update NONE ;
    DEFINE FIELD OVERWRITE created_by ON rebase_group TYPE option<record<rebase_user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON rebase_group TYPE option<record<rebase_user>>
        PERMISSIONS FOR select WHERE true FOR create, update NONE ;

-- Authorization/reader maintenance is not a principal profile edit.
DEFINE EVENT OVERWRITE principal_touch ON rebase_user WHEN $event = 'CREATE' OR ($event = 'UPDATE' AND (
    $before.name != $after.name OR $before.username != $after.username OR $before.parents != $after.parents
    OR $before.login_access != $after.login_access OR $before.password != $after.password
)) THEN { UPDATE $after.id SET updated_at = time::now(), updated_by = $auth RETURN NONE; };
DEFINE EVENT OVERWRITE principal_touch ON rebase_group WHEN $event = 'CREATE' OR ($event = 'UPDATE' AND (
    $before.name != $after.name OR $before.role != $after.role OR $before.parents != $after.parents
)) THEN { UPDATE $after.id SET updated_at = time::now(), updated_by = $auth RETURN NONE; };

-- Parent mutations are rare control-plane writes. The tenant revision is a
-- transaction conflict fence: concurrent DAG changes cannot both commit from
-- different snapshots. Closure deltas retain alternate paths in a diamond.
DEFINE FUNCTION OVERWRITE fn::rebase::refresh_access($principal: record, $tenant: record) {
    UPDATE $tenant SET authorization_revision += 1;
    LET $principal_row = (SELECT * FROM $principal)[0];
    IF fn::rebase::principal_tenant($principal_row.parents) != $tenant { THROW 'ERR_TENANT_PARENTS'; };
    IF $principal IN $principal_row.parents OR array::any($principal_row.parents,
        |$parent| fn::rebase::dominates($principal, $parent)) { THROW 'ERR_CYCLE'; };

    LET $affected = array::distinct(array::concat([$principal], $principal->rebase_access.out));
    -- Depth is updated here, never by a field VALUE before this sort. Existing
    -- depths therefore place a moved node before all of its old descendants.
    LET $nodes = (SELECT id, parents, authorization_depth FROM $affected ORDER BY authorization_depth ASC, id ASC);
    FOR $node IN $nodes {
        LET $ancestors = array::distinct(array::flatten($node.parents.map(|$parent|
            array::concat([$parent], $parent<-rebase_access.in))));
        LET $existing = $node.id<-rebase_access.in;
        FOR $removed IN array::complement($existing, $ancestors) {
            DELETE type::record('rebase_access', [$removed, $node.id]);
        };
        FOR $added IN array::complement($ancestors, $existing) {
            LET $edge = type::record('rebase_access', [$added, $node.id]);
            RELATE $added->$edge->$node.id;
        };
        UPDATE $node.id SET authorization_depth = 1 + math::max($node.parents.authorization_depth);
    };
    fn::rebase::refresh_readers($affected);
    RETURN NONE;
} PERMISSIONS NONE;

DEFINE EVENT OVERWRITE principal_access ON rebase_user
WHEN $event IN ['CREATE', 'UPDATE'] AND $before.parents != $after.parents THEN {
    LET $role_parents = $after.parents.filter(|$parent| record::tb($parent) IN ['rebase_tenant', 'rebase_group']);
    LET $permissions = array::distinct(array::flatten($role_parents.role ?? []));
    IF $auth AND array::complement($permissions, $auth.permissions ?? []).len() > 0 {
        THROW 'ERR_PRIVILEGE_ESCALATION';
    };
    fn::rebase::refresh_access($after.id, $after.tenant);
};
DEFINE EVENT OVERWRITE principal_access ON rebase_group
WHEN $event IN ['CREATE', 'UPDATE'] AND $before.parents != $after.parents THEN {
    fn::rebase::refresh_access($after.id, $after.tenant);
};
DEFINE EVENT OVERWRITE principal_access_delete ON rebase_user WHEN $event = 'DELETE' THEN {
    UPDATE $before.tenant SET authorization_revision += 1;
};
DEFINE EVENT OVERWRITE principal_access_delete ON rebase_group WHEN $event = 'DELETE' THEN {
    UPDATE $before.tenant SET authorization_revision += 1;
};

-- Privilege escalation prevention.
DEFINE EVENT OVERWRITE prevent_role_escalation ON TABLE rebase_group WHEN $event IN ["CREATE", "UPDATE"] AND $before.role != $after.role THEN {
    LET $unauthorized = array::complement($after.role ?? [], $auth.permissions ?? []);
    IF $unauthorized AND $auth { THROW "ERR_PRIVILEGE_ESCALATION"; };
};

-- Permission propagation remains independent from authentication state.
DEFINE EVENT OVERWRITE cascade_permissions_downward ON TABLE rebase_group WHEN $event = "UPDATE" AND $before.role != $after.role THEN {
    UPDATE $after.tenant SET authorization_revision += 1;
    LET $children_users = $after.id<~(rebase_user FIELD parents);
    IF $children_users { UPDATE $children_users; };
};
DEFINE EVENT OVERWRITE cascade_permissions_downward ON rebase_tenant
WHEN $event = 'UPDATE' AND $before.role != $after.role THEN {
    UPDATE $after.id SET authorization_revision += 1;
    LET $children_users = $after.id<~(rebase_user FIELD parents);
    IF $children_users { UPDATE $children_users; };
};
