REMOVE DATABASE main;
DEFINE DATABASE main;
USE NS main DB main;

-- USER
DEFINE TABLE OVERWRITE user SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth != NONE AND 'node_create' IN $auth.permissions
    FOR select WHERE id = $auth OR ('node_select' IN $auth.permissions AND id IN $auth.dominates)
    FOR update WHERE id = $auth OR ('node_update' IN $auth.permissions AND id IN $auth.dominates)
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates;

DEFINE FIELD OVERWRITE name ON user TYPE string 
    VALUE $value.trim()
    ASSERT $value.len() > 0;

DEFINE FIELD OVERWRITE email ON user TYPE string
    VALUE $value.trim().lowercase()
    ASSERT string::is_email($value);

DEFINE FIELD OVERWRITE password ON user TYPE option<string> PERMISSIONS NONE;
DEFINE FIELD OVERWRITE invite_token ON user TYPE option<uuid> PERMISSIONS NONE;

DEFINE FIELD OVERWRITE dominates ON user TYPE option<array<record<user | groups>>> 
    PERMISSIONS FOR select WHERE TRUE FOR create, update WHERE NONE;

DEFINE FIELD OVERWRITE parents ON user TYPE option<array<record<groups>>> 
    PERMISSIONS FOR select WHERE TRUE FOR create, update WHERE NONE;

DEFINE FIELD OVERWRITE permissions ON user TYPE option<array<string>> 
    PERMISSIONS FOR select WHERE TRUE FOR create, update WHERE NONE;

DEFINE FIELD OVERWRITE last_deactivated_at ON user TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD OVERWRITE last_refreshed_at ON user TYPE option<datetime> DEFAULT NONE;

DEFINE FIELD OVERWRITE created_at ON user TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON user TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON user TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON user TYPE option<record<user>> VALUE $auth;

DEFINE INDEX OVERWRITE idx_user_email ON user COLUMNS email UNIQUE;

DEFINE EVENT OVERWRITE user_state_machine ON TABLE user WHEN $event = "UPDATE" THEN {
    IF $before.last_refreshed_at != $after.last_refreshed_at {
        IF $before.last_refreshed_at != NONE AND time::now() - type::datetime($before.last_refreshed_at) < 10s { 
            THROW "ERR_RATE_LIMIT"; 
        };
        UPDATE $after.id SET 
            dominates   = ($after.id.{..+collect}->link->(?) ??[]).filter(|$v| $v != NONE).sort(),
            parents     = ($after.id<-link<-groups ??[]).filter(|$v| $v != NONE).distinct().sort(),
            permissions = ($after.id<-link<-groups.role ??[]).flatten().filter(|$v| $v != NONE).distinct().sort();
    };

    IF $before.email != $after.email {
        UPDATE $after.id SET last_deactivated_at = time::now();
    };
    IF $before.last_deactivated_at != $after.last_deactivated_at {
        IF $before.last_deactivated_at != NONE AND time::now() - type::datetime($before.last_deactivated_at) < 1m { 
            THROW "ERR_RATE_LIMIT"; 
        };
        UPDATE $after.id SET password = NONE;
    };
    IF $before.password != $after.password {
        IF $after.password = NONE {
            UPDATE $after.id SET invite_token = rand::uuid();
        } ELSE {
            UPDATE $after.id SET invite_token = NONE;
        };
    };
};

DEFINE EVENT OVERWRITE user_on_create ON TABLE user WHEN $event = "CREATE" THEN {
    IF $after.password = NONE {
        UPDATE $after.id SET invite_token = rand::uuid();
    };
};

DEFINE EVENT OVERWRITE prevent_user_non_leaf_delete ON TABLE user WHEN $event = "DELETE" THEN {
    IF $before.id->link.len() > 0 { THROW "ERR_NOT_A_LEAF"; };
    DELETE link WHERE in = $before.id OR out = $before.id;
};

DEFINE EVENT OVERWRITE auto_link_creator ON TABLE user WHEN $event = "CREATE" AND $after.created_by != NONE THEN {
    RELATE ($after.created_by) -> link -> ($after.id);
};

-- GROUPS
DEFINE TABLE OVERWRITE groups SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth != NONE AND 'node_create' IN $auth.permissions
    FOR select WHERE 'node_select' IN $auth.permissions AND (id IN $auth.dominates OR id IN $auth.parents)
    FOR update WHERE 'node_update' IN $auth.permissions AND id IN $auth.dominates
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates;

DEFINE FIELD OVERWRITE name ON groups TYPE string VALUE $value.trim() ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE role ON groups TYPE array<string> VALUE (
    IF $before = NONE THEN ($value ??[]).distinct()
    ELSE IF $before.len() = 0 THEN []
    ELSE IF ($value ??[]).len() = 0 THEN $before
    ELSE $value.distinct() END
);

DEFINE FIELD OVERWRITE created_at ON groups TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON groups TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON groups TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON groups TYPE option<record<user>> VALUE $auth;

DEFINE EVENT OVERWRITE prevent_role_escalation ON TABLE groups WHEN $event IN["CREATE", "UPDATE"] THEN {
    IF $auth != NONE {
        LET $unauthorized = array::complement($after.role, $auth.permissions);
        IF $unauthorized.len() > 0 { THROW "ERR_PRIVILEGE_ESCALATION"; };
    };
};

DEFINE EVENT OVERWRITE prevent_group_non_leaf_delete ON TABLE groups WHEN $event = "DELETE" THEN {
    IF $before.id->link.len() > 0 { THROW "ERR_NOT_A_LEAF"; };
    DELETE link WHERE in = $before.id OR out = $before.id;
};

DEFINE EVENT OVERWRITE auto_link_creator_group ON TABLE groups WHEN $event = "CREATE" AND $after.created_by != NONE THEN {
    RELATE ($after.created_by) -> link -> ($after.id);
};

-- LINK
DEFINE TABLE OVERWRITE link SCHEMAFULL TYPE RELATION IN user | groups OUT user | groups PERMISSIONS
    FOR create WHERE 'link_create' IN $auth.permissions AND (in = $auth OR in IN $auth.dominates) AND out IN $auth.dominates
    FOR update NONE
    FOR select WHERE 'link_select' IN $auth.permissions AND (in = $auth OR out = $auth OR in IN $auth.dominates OR out IN $auth.dominates)
    FOR delete WHERE 'link_delete' IN $auth.permissions AND (in = $auth OR in IN $auth.dominates);

DEFINE FIELD OVERWRITE created_at ON link TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE created_by ON link TYPE option<record<user>> VALUE $before OR $auth READONLY;

DEFINE INDEX OVERWRITE idx_unique_link ON TABLE link COLUMNS in, out UNIQUE;

DEFINE EVENT OVERWRITE prevent_cycle ON TABLE link WHEN $event = "CREATE" THEN {
    LET $start = $after.out;
    LET $end = $after.in;
    LET $cycle = $start.{..+shortest=$end}->link->(?);
    IF $cycle.len() > 0 { THROW "ERR_CYCLE"; };
};

DEFINE EVENT OVERWRITE prevent_orphans ON TABLE link WHEN $event = "DELETE" THEN {
    IF $before.out != NONE AND record::exists($before.in) AND record::exists($before.out) {
        LET $other_links = (SELECT id FROM link WHERE out = $before.out AND id != $before.id LIMIT 1);
        IF $other_links.len() = 0 { THROW "ERR_LAST_EDGE"; };
    };
};

-- ACCESS METHODS
DEFINE ACCESS OVERWRITE account ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET password = crypto::argon2::generate($password), invite_token = NONE, last_refreshed_at = time::now()
        WHERE email = $email.lowercase() 
          AND invite_token = type::uuid($invite)
          AND $password.len() > 6
    )
    SIGNIN (
        UPDATE user SET last_refreshed_at = time::now()
        WHERE email = $email.lowercase() 
          AND invite_token = NONE 
          AND crypto::argon2::compare(password ?? "", $password)
    )
    AUTHENTICATE {
        IF $auth.password = NONE { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;

DEFINE ACCESS OVERWRITE update_password ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET password = crypto::argon2::generate($new_password), last_refreshed_at = time::now()
        WHERE email = $email.lowercase() 
          AND password != NONE 
          AND crypto::argon2::compare(password ?? "", $password)
          AND $new_password.len() > 6
    )
    AUTHENTICATE {
        IF $auth.password = NONE { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;

-- INITIALIZATION
CREATE groups:root SET name = 'System Admins', role = [
    'node_create', 'node_select', 'node_update', 'node_delete',
    'link_create', 'link_select', 'link_delete',
    'acc_select', 'acc_create', 'acc_update', 'acc_delete',
    'adjustment_line_select', 'adjustment_line_create', 'adjustment_line_update', 'adjustment_line_delete',
    'adjustment_note_select', 'adjustment_note_create', 'adjustment_note_update', 'adjustment_note_delete',
    'invoice_select', 'invoice_create', 'invoice_update', 'invoice_delete',
    'invoice_line_select', 'invoice_line_create', 'invoice_line_update', 'invoice_line_delete',
    'item_select', 'item_create', 'item_update', 'item_delete',
    'org_select', 'org_create', 'org_update', 'org_delete',
    'package_note_select', 'package_note_create', 'package_note_update', 'package_note_delete',
    'payment_select', 'payment_create', 'payment_update', 'payment_delete',
    'payment_allocation_select', 'payment_allocation_create', 'payment_allocation_update', 'payment_allocation_delete',
    'sl_select', 'sl_create', 'sl_update', 'sl_delete',
    'stock_acc_select', 'stock_acc_create', 'stock_acc_update', 'stock_acc_delete',
    'tax_account_select', 'tax_account_create', 'tax_account_update', 'tax_account_delete',
    'tax_line_select', 'tax_line_create', 'tax_line_update', 'tax_line_delete',
    'treasury_select', 'treasury_create', 'treasury_update', 'treasury_delete',
    'warehouse_select', 'warehouse_create', 'warehouse_update', 'warehouse_delete'
];

CREATE user:root SET name = 'Super Admin', email = 'test@admin.com';
UPDATE user:root SET password = crypto::argon2::generate("password"), invite_token = NONE;
RELATE groups:root -> link -> user:root;
UPDATE user:root SET last_refreshed_at = time::now();