-- USER
DEFINE TABLE OVERWRITE user SCHEMAFULL PERMISSIONS
    FOR create WHERE 'node_create' IN $auth.permissions
    FOR select WHERE id = $auth OR ('node_select' IN $auth.permissions AND id IN $auth.dominates)
    FOR update WHERE id = $auth OR ('node_update' IN $auth.permissions AND id IN $auth.dominates)
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates
    COMMENT '@rebase-audit';

    DEFINE FIELD OVERWRITE name ON user TYPE string VALUE {
        LET $clean_name = string::trim($value ?? "");
        IF !$clean_name { THROW "VALIDATION_ERR: Invalid Name"; };
        RETURN $clean_name;
    };
    DEFINE FIELD OVERWRITE email ON user TYPE string VALUE {
        LET $clean_email = string::trim($value ?? "");
        IF !string::is_email($clean_email) { THROW "VALIDATION_ERR: Invalid email"; };
        RETURN string::lowercase($clean_email);
    } COMMENT '@rebase-change-log';
    DEFINE FIELD OVERWRITE username ON user TYPE option<string> DEFAULT NONE VALUE {
        IF $value = NONE { RETURN NONE; };
        LET $clean_username = string::lowercase(string::trim($value));
        IF !string::matches($clean_username, /^[a-z0-9][a-z0-9_.-]{8,31}$/) {
            THROW "VALIDATION_ERR: Invalid username";
        };
        RETURN $clean_username;
    } COMMENT '@rebase-change-log';

    DEFINE FIELD OVERWRITE login_access ON user TYPE bool DEFAULT true PERMISSIONS FOR update WHERE id != $auth;
    DEFINE FIELD OVERWRITE password ON user TYPE option<string> PERMISSIONS NONE COMMENT '@rebase-audit-redact';
    DEFINE FIELD OVERWRITE invite_token ON user TYPE uuid
        VALUE rand::uuid::v7()
        PERMISSIONS NONE
        COMMENT '@rebase-audit-redact';
    DEFINE FIELD OVERWRITE invite_expires_at ON user TYPE datetime
        DEFAULT time::now() + 24h
        PERMISSIONS
            FOR select WHERE true
            FOR create WHERE true
            FOR update WHERE id != $auth;

    DEFINE FIELD OVERWRITE parents ON user TYPE array<record<user | groups>> 
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE array::distinct($value ?? [])
        -- `array::difference` is the native symmetric difference: validate only
        -- edges introduced or removed by this mutation. Existing edges may be
        -- invisible to a dominating actor and must not make an unrelated update fail.
        ASSERT $value.len() > 0
            AND array::all(array::difference($value ?? [], $before ?? []), |$parent| record::exists($parent))
        REFERENCE ON DELETE REJECT 
        PERMISSIONS FOR update WHERE id != $auth
        COMMENT '@rebase-reference-delta';

    DEFINE FIELD OVERWRITE parent_groups ON user TYPE array<record<groups>> 
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) = 'groups'))
        PERMISSIONS FOR create, update NONE
        COMMENT '@rebase-audit-omit';

    DEFINE FIELD OVERWRITE permissions ON user TYPE array<string> 
        VALUE array::distinct(array::flatten($this.parent_groups.role ?? [])).filter(|$permission| $permission != NONE)
        PERMISSIONS FOR create, update NONE
        COMMENT '@rebase-audit-omit @rebase-change-log';

DEFINE FIELD OVERWRITE dominates ON user TYPE array<record<user | groups>> VALUE {
        LET $ch_users = $this.id<~(user FIELD parents);
        LET $ch_groups = $this.id<~(groups FIELD parents);

        RETURN array::distinct(array::flatten([
            $ch_users, 
            array::flatten($ch_users.dominates), 
            $ch_groups, 
            array::flatten($ch_groups.dominates)
        ])).filter(|$node| $node != NONE);
    }
    PERMISSIONS FOR create, update NONE
    COMMENT '@rebase-audit-omit';

    DEFINE FIELD OVERWRITE created_at ON user TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON user TYPE datetime VALUE time::now() COMMENT '@rebase-audit-omit';
    DEFINE FIELD OVERWRITE created_by ON user TYPE option<record<user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON user TYPE option<record<user>> VALUE $auth COMMENT '@rebase-audit-omit';
    DEFINE FIELD OVERWRITE z_access_index ON user TYPE array<string>
        VALUE array::distinct(array::concat(
            [<string>$this.id],
            ($this.parent_groups ?? []).map(|$node| <string>$node),
            ($this.dominates ?? []).map(|$node| <string>$node)
        ))
        PERMISSIONS FOR create, update NONE
        COMMENT '@rebase-audit-omit';

    DEFINE INDEX OVERWRITE idx_user_email ON user COLUMNS email UNIQUE;
    DEFINE INDEX OVERWRITE idx_user_username ON user COLUMNS username UNIQUE;
    DEFINE INDEX OVERWRITE idx_user_invite_token ON user COLUMNS invite_token UNIQUE;

-- GROUPS
DEFINE TABLE OVERWRITE groups SCHEMAFULL PERMISSIONS
    FOR create WHERE 'node_create' IN $auth.permissions
    FOR select WHERE 'node_select' IN $auth.permissions AND (id IN $auth.dominates OR id IN $auth.parent_groups)
    FOR update WHERE 'node_update' IN $auth.permissions AND id IN $auth.dominates
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates
    COMMENT '@rebase-audit';

    DEFINE FIELD OVERWRITE name ON groups TYPE string VALUE {
        LET $clean_name = string::trim($value ?? "");
        IF !$clean_name { THROW "VALIDATION_ERR: Invalid Name"; };
        RETURN $clean_name;
    };
    DEFINE FIELD OVERWRITE role ON groups TYPE array<string> DEFAULT [] VALUE array::distinct($value ?? []);
    DEFINE FIELD OVERWRITE parents ON groups TYPE array<record<user | groups>> 
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE array::distinct($value ?? [])
        ASSERT id = groups:root OR ($value.len() > 0
            AND array::all(array::difference($value ?? [], $before ?? []), |$parent| record::exists($parent)))
        REFERENCE ON DELETE REJECT 
        PERMISSIONS FOR update WHERE id != $auth
        COMMENT '@rebase-reference-delta';

    DEFINE FIELD OVERWRITE parent_groups ON groups TYPE array<record<groups>> 
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) = 'groups'))
        PERMISSIONS FOR create, update NONE
        COMMENT '@rebase-audit-omit';

    DEFINE FIELD OVERWRITE dominates ON groups TYPE array<record<user | groups>> VALUE {
        LET $ch_users = $this.id<~(user FIELD parents);
        LET $ch_groups = $this.id<~(groups FIELD parents);

        RETURN array::distinct(array::flatten([
            $ch_users, 
            array::flatten($ch_users.dominates), 
            $ch_groups, 
            array::flatten($ch_groups.dominates)
        ])).filter(|$node| $node != NONE);
    }
    PERMISSIONS FOR create, update NONE
    COMMENT '@rebase-audit-omit';

    DEFINE FIELD OVERWRITE created_at ON groups TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON groups TYPE datetime VALUE time::now() COMMENT '@rebase-audit-omit';
    DEFINE FIELD OVERWRITE created_by ON groups TYPE option<record<user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON groups TYPE option<record<user>> VALUE $auth COMMENT '@rebase-audit-omit';

-- 1. Cycle Detection
DEFINE EVENT OVERWRITE prevent_cycle ON TABLE user WHEN $event IN ["CREATE", "UPDATE"] AND $before.parents != $after.parents THEN {
    IF $after.id IN ($after.parents ?? []) OR ($after.parents ?? []) CONTAINSANY ($before.dominates ?? []) {
        THROW "ERR_CYCLE";
    };
};

DEFINE EVENT OVERWRITE prevent_cycle ON TABLE groups WHEN $event IN ["CREATE", "UPDATE"] AND $before.parents != $after.parents THEN {
    IF $after.id IN ($after.parents ?? []) OR ($after.parents ?? []) CONTAINSANY ($before.dominates ?? []) {
        THROW "ERR_CYCLE";
    };
};

-- 2. State Machine (Email updates invalidate credentials and open a new invite window)
DEFINE EVENT OVERWRITE user_state_machine ON TABLE user WHEN $event = "UPDATE" AND $before.email != $after.email THEN {
    UPDATE $after.id SET
        password = NONE,
        invite_expires_at = time::now() + 24h;
};

-- 3. Privilege Escalation Prevention
DEFINE EVENT OVERWRITE prevent_role_escalation ON TABLE groups WHEN $event IN ["CREATE", "UPDATE"] AND $before.role != $after.role THEN {
    LET $unauthorized = array::complement($after.role ?? [], $auth.permissions ?? []);
    IF $unauthorized AND $auth { THROW "ERR_PRIVILEGE_ESCALATION"; };
};

-- 4. Downward Propagation
DEFINE EVENT OVERWRITE cascade_permissions_downward ON TABLE groups WHEN $event = "UPDATE" AND $before.role != $after.role THEN {
    LET $children_users = $after.id<~(user FIELD parents);
    IF $children_users { UPDATE $children_users; };
};

-- 5. Upward Propagation Triggers
DEFINE EVENT OVERWRITE upward_propagation_trigger ON TABLE user WHEN $event THEN {
    IF $before.parents != $after.parents {
        LET $parents_to_ping = array::union($before.parents ?? [], $after.parents ?? []);
        IF $parents_to_ping { UPDATE $parents_to_ping; };
    };
    IF $before.dominates != $after.dominates {
        IF $after.parents { UPDATE $after.parents; };
    };
};

DEFINE EVENT OVERWRITE upward_propagation_trigger ON TABLE groups WHEN $event THEN {
    IF $before.parents != $after.parents {
        LET $parents_to_ping = array::union($before.parents ?? [], $after.parents ?? []);
        IF $parents_to_ping { UPDATE $parents_to_ping; };
    };
    IF $before.dominates != $after.dominates {
        IF $after.parents { UPDATE $after.parents; };
    };
};

-- INITIALIZATION
CREATE groups:root SET
    name = 'System Admins',
    role = ['node_create', 'node_select', 'node_update', 'node_delete'];
