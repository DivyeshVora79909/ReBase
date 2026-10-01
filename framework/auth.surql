-- Authorization graph and principal fields.
-- Authentication identities and challenges are declared in authentication.surql.

-- USER
DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL PERMISSIONS
    FOR create WHERE 'node_create' IN $auth.permissions
    FOR select WHERE id = $auth OR ('node_select' IN $auth.permissions AND id IN $auth.dominates)
    FOR update WHERE id = $auth OR ('node_update' IN $auth.permissions AND id IN $auth.dominates)
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates
    ;

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
        ;

    DEFINE FIELD OVERWRITE parents ON rebase_user TYPE array<record<rebase_user | rebase_group>>
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE array::distinct($value ?? [])
        -- Validate only edges introduced or removed by this mutation. Existing
        -- edges may be invisible to a dominating actor.
        ASSERT $value.len() > 0
            AND array::all(array::difference($value ?? [], $before ?? []), |$parent| record::exists($parent))
        REFERENCE ON DELETE REJECT
        PERMISSIONS FOR update WHERE id != $auth
        COMMENT '@rebase-reference-delta';

    DEFINE FIELD OVERWRITE parent_groups ON rebase_user TYPE array<record<rebase_group>>
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) = 'rebase_group'))
        PERMISSIONS FOR create, update NONE
        ;

    DEFINE FIELD OVERWRITE permissions ON rebase_user TYPE array<string>
        VALUE array::distinct(array::flatten($this.parent_groups.role ?? [])).filter(|$permission| $permission != NONE)
        PERMISSIONS FOR create, update NONE
        ;

    DEFINE FIELD OVERWRITE dominates ON rebase_user TYPE array<record<rebase_user | rebase_group>> VALUE {
        LET $ch_users = $this.id<~(rebase_user FIELD parents);
        LET $ch_groups = $this.id<~(rebase_group FIELD parents);

        RETURN array::distinct(array::flatten([
            $ch_users,
            array::flatten($ch_users.dominates),
            $ch_groups,
            array::flatten($ch_groups.dominates)
        ])).filter(|$node| $node != NONE);
    }
    PERMISSIONS FOR create, update NONE
    ;

    DEFINE FIELD OVERWRITE created_at ON rebase_user TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON rebase_user TYPE datetime VALUE IF $before = NONE THEN time::now() ELSE $value END
        PERMISSIONS FOR select, create WHERE true FOR update NONE ;
    DEFINE FIELD OVERWRITE created_by ON rebase_user TYPE option<record<rebase_user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON rebase_user TYPE option<record<rebase_user>>
        PERMISSIONS FOR select WHERE true FOR create, update NONE ;
    DEFINE FIELD OVERWRITE z_access_index ON rebase_user TYPE array<string>
        VALUE array::distinct(array::concat(
            [<string>$this.id],
            ($this.parent_groups ?? []).map(|$node| <string>$node),
            ($this.dominates ?? []).map(|$node| <string>$node)
        ))
        PERMISSIONS FOR create, update NONE
        ;

    DEFINE INDEX OVERWRITE idx_user_username ON rebase_user COLUMNS username UNIQUE;

-- GROUPS
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL PERMISSIONS
    FOR create WHERE 'node_create' IN $auth.permissions
    FOR select WHERE 'node_select' IN $auth.permissions AND (id IN $auth.dominates OR id IN $auth.parent_groups)
    FOR update WHERE 'node_update' IN $auth.permissions AND id IN $auth.dominates
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates
    ;

    DEFINE FIELD OVERWRITE name ON rebase_group TYPE string VALUE {
        LET $clean_name = string::trim($value ?? "");
        IF !$clean_name { THROW "VALIDATION_ERR: Invalid Name"; };
        RETURN $clean_name;
    };
    DEFINE FIELD OVERWRITE role ON rebase_group TYPE array<string> DEFAULT [] VALUE array::distinct($value ?? []);
    DEFINE FIELD OVERWRITE parents ON rebase_group TYPE array<record<rebase_user | rebase_group>>
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE array::distinct($value ?? [])
        ASSERT id = rebase_group:root OR ($value.len() > 0
            AND array::all(array::difference($value ?? [], $before ?? []), |$parent| record::exists($parent)))
        REFERENCE ON DELETE REJECT
        PERMISSIONS FOR update WHERE id != $auth
        COMMENT '@rebase-reference-delta';

    DEFINE FIELD OVERWRITE parent_groups ON rebase_group TYPE array<record<rebase_group>>
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) = 'rebase_group'))
        PERMISSIONS FOR create, update NONE
        ;

    DEFINE FIELD OVERWRITE dominates ON rebase_group TYPE array<record<rebase_user | rebase_group>> VALUE {
        LET $ch_users = $this.id<~(rebase_user FIELD parents);
        LET $ch_groups = $this.id<~(rebase_group FIELD parents);

        RETURN array::distinct(array::flatten([
            $ch_users,
            array::flatten($ch_users.dominates),
            $ch_groups,
            array::flatten($ch_groups.dominates)
        ])).filter(|$node| $node != NONE);
    }
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

-- Cycle detection for the authorization graph.
DEFINE EVENT OVERWRITE prevent_cycle ON TABLE rebase_user WHEN $event IN ["CREATE", "UPDATE"] AND $before.parents != $after.parents THEN {
    IF $after.id IN ($after.parents ?? []) OR ($after.parents ?? []) CONTAINSANY ($before.dominates ?? []) {
        THROW "ERR_CYCLE";
    };
};

DEFINE EVENT OVERWRITE prevent_cycle ON TABLE rebase_group WHEN $event IN ["CREATE", "UPDATE"] AND $before.parents != $after.parents THEN {
    IF $after.id IN ($after.parents ?? []) OR ($after.parents ?? []) CONTAINSANY ($before.dominates ?? []) {
        THROW "ERR_CYCLE";
    };
};

-- Privilege escalation prevention.
DEFINE EVENT OVERWRITE prevent_role_escalation ON TABLE rebase_group WHEN $event IN ["CREATE", "UPDATE"] AND $before.role != $after.role THEN {
    LET $unauthorized = array::complement($after.role ?? [], $auth.permissions ?? []);
    IF $unauthorized AND $auth { THROW "ERR_PRIVILEGE_ESCALATION"; };
};

-- Permission propagation remains independent from authentication state.
DEFINE EVENT OVERWRITE cascade_permissions_downward ON TABLE rebase_group WHEN $event = "UPDATE" AND $before.role != $after.role THEN {
    LET $children_users = $after.id<~(rebase_user FIELD parents);
    IF $children_users { UPDATE $children_users; };
};

DEFINE EVENT OVERWRITE upward_propagation_trigger ON TABLE rebase_user WHEN $event THEN {
    IF $before.parents != $after.parents {
        LET $parents_to_ping = array::union($before.parents ?? [], $after.parents ?? []);
        IF $parents_to_ping { UPDATE $parents_to_ping; };
    };
    IF $before.dominates != $after.dominates {
        IF $after.parents { UPDATE $after.parents; };
    };
};

DEFINE EVENT OVERWRITE upward_propagation_trigger ON TABLE rebase_group WHEN $event THEN {
    IF $before.parents != $after.parents {
        LET $parents_to_ping = array::union($before.parents ?? [], $after.parents ?? []);
        IF $parents_to_ping { UPDATE $parents_to_ping; };
    };
    IF $before.dominates != $after.dominates {
        IF $after.parents { UPDATE $after.parents; };
    };
};

-- Framework bootstrap; project-specific root permissions are added by the compiler.
UPSERT rebase_group:root SET
    name = name ?? 'System Admins',
    role = role ?? ['node_create', 'node_select', 'node_update', 'node_delete'];
