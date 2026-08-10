USE NS main DB main;

-- USER
DEFINE TABLE OVERWRITE user SCHEMAFULL PERMISSIONS
    FOR create WHERE 'node_create' IN $auth.permissions
    FOR select WHERE id = $auth OR ('node_select' IN $auth.permissions AND id IN $auth.dominates)
    FOR update WHERE id = $auth OR ('node_update' IN $auth.permissions AND id IN $auth.dominates)
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates;

    DEFINE FIELD OVERWRITE name ON user TYPE string VALUE {
        LET $clean_name = string::trim($value ?? "");
        IF !$clean_name { THROW "VALIDATION_ERR: Invalid Name"; };
        RETURN $clean_name;
    };
    DEFINE FIELD OVERWRITE email ON user TYPE string VALUE {
        LET $clean_email = string::trim($value ?? "");
        IF !string::is_email($clean_email) { THROW "VALIDATION_ERR: Invalid email"; };
        RETURN string::lowercase($clean_email);
    };

    DEFINE FIELD OVERWRITE login_access ON user TYPE bool DEFAULT true PERMISSIONS FOR update WHERE id != $auth;
    DEFINE FIELD OVERWRITE password ON user TYPE option<string> PERMISSIONS NONE;
    DEFINE FIELD OVERWRITE invite_token ON user TYPE uuid DEFAULT rand::uuid() PERMISSIONS NONE;
    DEFINE FIELD OVERWRITE invite_expires_at ON user TYPE datetime DEFAULT time::now() + 24h PERMISSIONS NONE;

    DEFINE FIELD OVERWRITE parents ON user TYPE array<record<user | groups>> 
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE {
            LET $incoming = array::distinct($value ?? []);
            LET $new = array::complement($incoming, $before.parents ?? []);

            IF $new AND array::complement($new, (SELECT VALUE id FROM $new)) { 
                THROW "VALIDATION_ERR: Assigned parent records do not exist."; 
            };

            RETURN $incoming;
        }
        ASSERT $value 
        REFERENCE ON DELETE REJECT 
        PERMISSIONS FOR update WHERE id != $auth;

    DEFINE FIELD OVERWRITE parent_groups ON user TYPE array<record<groups>> 
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) = 'groups'))
        PERMISSIONS FOR create, update NONE;

    DEFINE FIELD OVERWRITE permissions ON user TYPE array<string> 
        VALUE array::distinct(array::flatten($this.parent_groups.role ?? []))
        PERMISSIONS FOR create, update NONE;

DEFINE FIELD OVERWRITE dominates ON user TYPE array<record<user | groups>> VALUE {
        LET $ch_users = $this.id<~(user FIELD parents);
        LET $ch_groups = $this.id<~(groups FIELD parents);

        RETURN array::distinct(array::flatten([
            $ch_users, 
            array::flatten($ch_users.dominates), 
            $ch_groups, 
            array::flatten($ch_groups.dominates)
        ]));
    }
    PERMISSIONS FOR create, update NONE;

    DEFINE FIELD OVERWRITE created_at ON user TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON user TYPE datetime VALUE time::now();
    DEFINE FIELD OVERWRITE created_by ON user TYPE option<record<user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON user TYPE option<record<user>> VALUE $auth;
    DEFINE FIELD OVERWRITE z_access_index ON user TYPE array<string>
        VALUE array::distinct(array::concat(
            [<string>$this.id],
            ($this.parent_groups ?? []).map(|$node| <string>$node),
            ($this.dominates ?? []).map(|$node| <string>$node)
        ))
        PERMISSIONS FOR create, update NONE;

    DEFINE INDEX OVERWRITE idx_user_email ON user COLUMNS email UNIQUE;

-- GROUPS
DEFINE TABLE OVERWRITE groups SCHEMAFULL PERMISSIONS
    FOR create WHERE 'node_create' IN $auth.permissions
    FOR select WHERE 'node_select' IN $auth.permissions AND (id IN $auth.dominates OR id IN $auth.parent_groups)
    FOR update WHERE 'node_update' IN $auth.permissions AND id IN $auth.dominates
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates;

    DEFINE FIELD OVERWRITE name ON groups TYPE string VALUE {
        LET $clean_name = string::trim($value ?? "");
        IF !$clean_name { THROW "VALIDATION_ERR: Invalid Name"; };
        RETURN $clean_name;
    };
    DEFINE FIELD OVERWRITE role ON groups TYPE array<string> DEFAULT [] VALUE array::distinct($value ?? []);

    DEFINE FIELD OVERWRITE parents ON groups TYPE array<record<user | groups>> 
        DEFAULT IF $auth THEN [$auth] ELSE [] END
        VALUE {
            LET $incoming = array::distinct($value ?? []);
            LET $new = array::complement($incoming, $before.parents ?? []);

            IF $new AND array::complement($new, (SELECT VALUE id FROM $new)) { 
                THROW "VALIDATION_ERR: Assigned parent records do not exist."; 
            };

            RETURN $incoming;
        }
        ASSERT $value OR id = groups:root
        REFERENCE ON DELETE REJECT 
        PERMISSIONS FOR update WHERE id != $auth;

    DEFINE FIELD OVERWRITE parent_groups ON groups TYPE array<record<groups>> 
        VALUE array::distinct(($this.parents ?? []).filter(|$p| record::tb($p) = 'groups'))
        PERMISSIONS FOR create, update NONE;

    DEFINE FIELD OVERWRITE dominates ON groups TYPE array<record<user | groups>> VALUE {
        LET $ch_users = $this.id<~(user FIELD parents);
        LET $ch_groups = $this.id<~(groups FIELD parents);

        RETURN array::distinct(array::flatten([
            $ch_users, 
            array::flatten($ch_users.dominates), 
            $ch_groups, 
            array::flatten($ch_groups.dominates)
        ]));
    }
    PERMISSIONS FOR create, update NONE;

    DEFINE FIELD OVERWRITE created_at ON groups TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON groups TYPE datetime VALUE time::now();
    DEFINE FIELD OVERWRITE created_by ON groups TYPE option<record<user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON groups TYPE option<record<user>> VALUE $auth;


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

-- 2. State Machine (Email updates invalidate credentials and invitations)
DEFINE EVENT OVERWRITE user_state_machine ON TABLE user WHEN $event = "UPDATE" AND $before.email != $after.email THEN {
    UPDATE $after.id SET
        password = NONE,
        invite_token = rand::uuid(),
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
CREATE groups:root SET name = 'System Admins', role = [
    'node_create', 'node_select', 'node_update', 'node_delete'
];
