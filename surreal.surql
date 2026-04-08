REMOVE DATABASE main;
DEFINE DATABASE main;
USE NS main DB main;

DEFINE TABLE OVERWRITE user SCHEMAFULL PERMISSIONS
    FOR create NONE
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
DEFINE FIELD OVERWRITE dominates ON user TYPE array<record<user | groups>> DEFAULT[] PERMISSIONS FOR update NONE;
DEFINE FIELD OVERWRITE parents ON user TYPE array<record<groups>> DEFAULT[] PERMISSIONS FOR update NONE;
DEFINE FIELD OVERWRITE permissions ON user TYPE array<string> DEFAULT[] PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE created_at ON user TYPE datetime VALUE $before OR time::now();
DEFINE FIELD OVERWRITE updated_at ON user TYPE datetime VALUE time::now();

DEFINE INDEX OVERWRITE idx_user_email ON user COLUMNS email UNIQUE;

DEFINE EVENT OVERWRITE user_state_machine ON TABLE user WHEN $event IN["CREATE", "UPDATE"] THEN {
    IF $before.email != $after.email {
        UPDATE $after.id SET 
            password = NONE, 
            invite_token = rand::uuid();
    }
    ELSE IF $before.password != $after.password {
        IF $after.password = NONE {
            UPDATE $after.id SET invite_token = rand::uuid();
        } 
        ELSE IF $before.password = NONE {
            UPDATE $after.id SET invite_token = NONE;
        };
    };
};

DEFINE EVENT OVERWRITE prevent_user_non_leaf_delete ON TABLE user WHEN $event = "DELETE" THEN {
    IF $before.id->link.len() > 0 { THROW "ERR_NOT_A_LEAF"; };
};

DEFINE TABLE OVERWRITE groups SCHEMAFULL PERMISSIONS
    FOR create NONE
    FOR select WHERE 'node_select' IN $auth.permissions AND (id IN $auth.dominates OR id IN $auth.parents)
    FOR update WHERE 'node_update' IN $auth.permissions AND id IN $auth.dominates
    FOR delete WHERE 'node_delete' IN $auth.permissions AND id IN $auth.dominates;

DEFINE FIELD OVERWRITE name ON groups TYPE string VALUE $value.trim() ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE role ON groups TYPE array<string> VALUE (
    IF $before = NONE THEN ($value ??[]).distinct()
    ELSE IF $before.len() = 0 THEN []
    ELSE IF ($value ??[]).len() = 0 THEN $before
    ELSE $value.distinct() END
)
ASSERT $value ALLINSIDE[
    'node_create', 'node_select', 'node_update', 'node_delete',
    'link_create', 'link_select', 'link_delete'
];

DEFINE FIELD OVERWRITE created_at ON groups TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON groups TYPE datetime VALUE time::now();

DEFINE EVENT OVERWRITE prevent_role_escalation ON TABLE groups WHEN $event IN["CREATE", "UPDATE"] THEN {
    IF $auth != NONE {
        LET $unauthorized = array::complement($after.role, $auth.permissions);
        IF $unauthorized.len() > 0 { 
            THROW "ERR_PRIVILEGE_ESCALATION"; 
        };
    };
};

DEFINE EVENT OVERWRITE prevent_group_non_leaf_delete ON TABLE groups WHEN $event = "DELETE" THEN {
    IF $before.id->link.len() > 0 { THROW "ERR_NOT_A_LEAF"; };
};

DEFINE TABLE OVERWRITE link SCHEMAFULL TYPE RELATION IN user | groups OUT user | groups PERMISSIONS
    FOR create WHERE 'link_create' IN $auth.permissions AND (in = $auth OR in IN $auth.dominates) AND out IN $auth.dominates
    FOR update NONE
    FOR select WHERE 'link_select' IN $auth.permissions AND (in IN $auth.dominates OR out IN $auth.dominates OR in IN $auth.parents)
    FOR delete WHERE 'link_delete' IN $auth.permissions AND in IN $auth.dominates AND out IN $auth.dominates;

DEFINE FIELD OVERWRITE created_at ON link TYPE datetime VALUE $before OR time::now() READONLY;

DEFINE EVENT OVERWRITE prevent_cycle ON TABLE link WHEN $event = "CREATE" THEN {
    LET $start = $after.out;
    LET $end = $after.in;
    LET $cycle = $start.{..+shortest=$end}->link->(?);
    IF $cycle.len() > 0 { THROW "ERR_CYCLE"; };
};

DEFINE INDEX OVERWRITE idx_unique_link ON TABLE link COLUMNS in, out UNIQUE;

DEFINE EVENT OVERWRITE prevent_orphans ON TABLE link WHEN $event = "DELETE" THEN {
    IF $before.out != NONE {
        LET $other_links = (SELECT id FROM link WHERE out = $before.out AND id != $before.id LIMIT 1);
        IF $other_links.len() = 0 { THROW "ERR_LAST_EDGE"; };
    };
};

DEFINE ACCESS OVERWRITE user ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET password = crypto::argon2::generate($password)
        WHERE email = $email.lowercase() 
          AND invite_token = type::uuid($token)
          AND $password.len() > 6
    )
    SIGNIN (
        SELECT * FROM user 
        WHERE email = $email.lowercase() 
          AND invite_token = NONE 
          AND crypto::argon2::compare(password ?? "", $password)
    )
    AUTHENTICATE {
        IF $auth.password = NONE { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;

DEFINE FUNCTION OVERWRITE fn::create_and_link(
    $parent: record<user | groups>, 
    $target_table: string, 
    $name: string, 
    $email: option<string>, 
    $roles: array<string>
) {
    IF NOT ('node_create' IN $auth.permissions AND ($parent = $auth OR $parent IN $auth.dominates)) { 
        THROW "ERR_RBAC"; 
    };
    LET $new_node = IF $target_table = 'user' {
        (CREATE ONLY user SET name = $name, email = $email)
    } ELSE {
        (CREATE ONLY groups SET name = $name, role = $roles)
    };
    RELATE $parent -> link -> $new_node;
    RETURN $new_node;
} PERMISSIONS FULL;


DEFINE FUNCTION OVERWRITE fn::deactivate_node($target: record<user>) {
    IF NOT ('node_delete' IN $auth.permissions AND ($target = $auth OR $target IN $auth.dominates)) { 
        THROW "ERR_RBAC"; 
    };
    UPDATE $target SET password = NONE;
    RETURN true;
} PERMISSIONS FULL;


DEFINE FUNCTION OVERWRITE fn::refresh_access($target: record<user>) {
    IF NOT ('node_update' IN $auth.permissions AND ($target = $auth OR $target IN $auth.dominates)) { 
        THROW "ERR_RBAC"; 
    };
    UPDATE $target SET 
        dominates   = $target.{..+collect}->link->(?).sort(),
        parents     = $target<-link<-groups.distinct().sort(),
        permissions = ($target<-link<-groups.role ??[]).flatten().distinct().sort();
    RETURN true;
} PERMISSIONS FULL;


DEFINE FUNCTION OVERWRITE fn::request_password_reset($email: string) {
    LET $user = (SELECT id, updated_at FROM user WHERE email = $email.lowercase() LIMIT 1)[0];
    IF $user {
        IF (time::now() - $user.updated_at) < 5m { THROW "ERR_RATE_LIMIT"; };
        UPDATE $user.id SET password = NONE;
    };
    RETURN true;
} PERMISSIONS FULL;


DEFINE FUNCTION OVERWRITE fn::update_password($old_password: string, $new_password: string) {
    IF $new_password.len() <= 6 { THROW "ERR_PASSWORD_LENGTH"; };
    LET $user_pass = (SELECT VALUE password FROM ONLY $auth);
    IF crypto::argon2::compare($user_pass ?? "", $old_password) = false { 
        THROW "ERR_INVALID_PASSWORD"; 
    };
    UPDATE $auth SET password = crypto::argon2::generate($new_password);
    RETURN true;
} PERMISSIONS FULL;

CREATE groups:root SET name = 'System Admins', role =[
    'node_create', 'node_select', 'node_update', 'node_delete',
    'link_create', 'link_select', 'link_delete'
];

CREATE user:root SET name = 'Super Admin', email = 'admin@example.com';
UPDATE user:root SET password = crypto::argon2::generate("admin123");
RELATE groups:root -> link -> user:root;

UPDATE user SET 
    dominates = id.{..+collect}->link->(?).sort(),
    parents = id<-link<-groups.distinct().sort(),
    permissions = (id<-link<-groups.role ??[]).flatten().distinct().sort();