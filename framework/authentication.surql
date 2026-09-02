-- Authentication data is deliberately separate from the authorization graph.
-- A principal may have zero or more delivered identities and may authenticate
-- with a password, a delivered one-time code, or OAuth when an identity is
-- currently verified.

-- A recent record token is required when a principal edits its own identities.
-- Dominating administrators retain the normal graph-based management path.
-- The ten-minute window is an access policy constant, not an auth-state field.

-- EMAIL IDENTITIES
DEFINE TABLE OVERWRITE authentication_email SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth AND ((principal = $auth AND $token.iat >= time::unix(time::now()) - 600) OR principal IN $auth.dominates)
    FOR select WHERE $auth AND (principal = $auth OR principal IN $auth.dominates)
    FOR update WHERE $auth AND ((principal = $auth AND $token.iat >= time::unix(time::now()) - 600) OR principal IN $auth.dominates)
    FOR delete WHERE $auth AND ((principal = $auth AND $token.iat >= time::unix(time::now()) - 600) OR principal IN $auth.dominates)
    COMMENT '@rebase-authentication';

    DEFINE FIELD OVERWRITE principal ON authentication_email TYPE record<user>
        ASSERT record::exists($value)
        REFERENCE ON DELETE CASCADE
        PERMISSIONS FOR update NONE;
    DEFINE FIELD OVERWRITE address ON authentication_email TYPE string VALUE {
        LET $email = string::lowercase(string::trim($value ?? ""));
        IF !string::is_email($email) { THROW "VALIDATION_ERR: Invalid authentication email"; };
        RETURN $email;
    } COMMENT '@rebase-change-log';
    DEFINE FIELD OVERWRITE label ON authentication_email TYPE option<string> DEFAULT NONE;
    DEFINE FIELD OVERWRITE priority ON authentication_email TYPE int DEFAULT 0 ASSERT $value >= 0 AND $value <= 1000;
    DEFINE FIELD OVERWRITE revision ON authentication_email TYPE int
        DEFAULT 1
        VALUE {
            IF $before = NONE { RETURN 1; };
            RETURN $value;
        }
        ASSERT $value >= 1
        PERMISSIONS FOR create WHERE true FOR update NONE
        COMMENT '@rebase-authentication-private';
    DEFINE FIELD OVERWRITE verified_revision ON authentication_email TYPE option<int> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND (principal = $auth OR principal IN $auth.dominates) FOR create, update NONE
        COMMENT '@rebase-authentication-private';
    DEFINE FIELD OVERWRITE verified_at ON authentication_email TYPE option<datetime> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND (principal = $auth OR principal IN $auth.dominates) FOR create, update NONE
        COMMENT '@rebase-authentication-private';
    DEFINE INDEX OVERWRITE idx_authentication_email_address ON authentication_email COLUMNS address UNIQUE;
    DEFINE INDEX OVERWRITE idx_authentication_email_principal ON authentication_email COLUMNS principal;

-- PHONE IDENTITIES
DEFINE TABLE OVERWRITE authentication_phone SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth AND ((principal = $auth AND $token.iat >= time::unix(time::now()) - 600) OR principal IN $auth.dominates)
    FOR select WHERE $auth AND (principal = $auth OR principal IN $auth.dominates)
    FOR update WHERE $auth AND ((principal = $auth AND $token.iat >= time::unix(time::now()) - 600) OR principal IN $auth.dominates)
    FOR delete WHERE $auth AND ((principal = $auth AND $token.iat >= time::unix(time::now()) - 600) OR principal IN $auth.dominates)
    COMMENT '@rebase-authentication';

    DEFINE FIELD OVERWRITE principal ON authentication_phone TYPE record<user>
        ASSERT record::exists($value)
        REFERENCE ON DELETE CASCADE
        PERMISSIONS FOR update NONE;
    DEFINE FIELD OVERWRITE number ON authentication_phone TYPE string VALUE {
        LET $phone = string::trim($value ?? "");
        IF !string::matches($phone, /^\+[1-9][0-9]{7,14}$/) { THROW "VALIDATION_ERR: Invalid authentication phone"; };
        RETURN $phone;
    } COMMENT '@rebase-change-log';
    DEFINE FIELD OVERWRITE label ON authentication_phone TYPE option<string> DEFAULT NONE;
    DEFINE FIELD OVERWRITE priority ON authentication_phone TYPE int DEFAULT 0 ASSERT $value >= 0 AND $value <= 1000;
    DEFINE FIELD OVERWRITE revision ON authentication_phone TYPE int
        DEFAULT 1
        VALUE {
            IF $before = NONE { RETURN 1; };
            RETURN $value;
        }
        ASSERT $value >= 1
        PERMISSIONS FOR create WHERE true FOR update NONE
        COMMENT '@rebase-authentication-private';
    DEFINE FIELD OVERWRITE verified_revision ON authentication_phone TYPE option<int> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND (principal = $auth OR principal IN $auth.dominates) FOR create, update NONE
        COMMENT '@rebase-authentication-private';
    DEFINE FIELD OVERWRITE verified_at ON authentication_phone TYPE option<datetime> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND (principal = $auth OR principal IN $auth.dominates) FOR create, update NONE
        COMMENT '@rebase-authentication-private';
    DEFINE INDEX OVERWRITE idx_authentication_phone_number ON authentication_phone COLUMNS number UNIQUE;
    DEFINE INDEX OVERWRITE idx_authentication_phone_principal ON authentication_phone COLUMNS principal;

-- ONE ACTIVE CHALLENGE PER IDENTITY
DEFINE TABLE OVERWRITE authentication_challenge SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-authentication-private';
DEFINE FIELD OVERWRITE principal ON authentication_challenge TYPE record<user>
    ASSERT record::exists($value) REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE target ON authentication_challenge TYPE record<authentication_email | authentication_phone>
    ASSERT record::exists($value) REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE principal_revision ON authentication_challenge TYPE int ASSERT $value >= 1;
DEFINE FIELD OVERWRITE target_revision ON authentication_challenge TYPE int ASSERT $value >= 1;
DEFINE FIELD OVERWRITE code_hash ON authentication_challenge TYPE string
    PERMISSIONS NONE COMMENT '@rebase-audit-redact';
DEFINE FIELD OVERWRITE attempts ON authentication_challenge TYPE int DEFAULT 0 ASSERT $value >= 0 AND $value <= 5
    PERMISSIONS NONE;
DEFINE FIELD OVERWRITE expires_at ON authentication_challenge TYPE datetime PERMISSIONS NONE;
DEFINE FIELD OVERWRITE consumed_at ON authentication_challenge TYPE option<datetime> DEFAULT NONE PERMISSIONS NONE;
DEFINE FIELD OVERWRITE created_at ON authentication_challenge TYPE datetime VALUE $before OR time::now() READONLY
    PERMISSIONS NONE;
DEFINE INDEX OVERWRITE idx_authentication_challenge_target ON authentication_challenge COLUMNS target UNIQUE;
DEFINE INDEX OVERWRITE idx_authentication_challenge_principal ON authentication_challenge COLUMNS principal;

-- These are state-invalidation triggers, not identity-presence guards. They
-- never block identity CRUD; they only fence stale verification/challenges.
-- The account revision is a fencing value, not an authentication boolean.
DEFINE EVENT OVERWRITE authentication_email_state ON TABLE authentication_email
WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
    LET $identity = IF $event = 'DELETE' THEN $before ELSE $after END;
    LET $principal = $identity.principal;
    IF $event = 'CREATE' {
        UPDATE $identity.id SET verified_revision = NONE, verified_at = NONE;
        UPDATE $principal SET authentication_revision = authentication_revision + 1;
    } ELSE IF $event = 'DELETE' {
        DELETE authentication_challenge WHERE target = $identity.id;
        UPDATE $principal SET authentication_revision = authentication_revision + 1;
    } ELSE IF $before.address != $after.address {
        UPDATE $identity.id SET
            revision = $before.revision + 1,
            verified_revision = NONE,
            verified_at = NONE;
        DELETE authentication_challenge WHERE target = $identity.id;
        UPDATE $principal SET authentication_revision = authentication_revision + 1;
    };
};

DEFINE EVENT OVERWRITE authentication_phone_state ON TABLE authentication_phone
WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
    LET $identity = IF $event = 'DELETE' THEN $before ELSE $after END;
    LET $principal = $identity.principal;
    IF $event = 'CREATE' {
        UPDATE $identity.id SET verified_revision = NONE, verified_at = NONE;
        UPDATE $principal SET authentication_revision = authentication_revision + 1;
    } ELSE IF $event = 'DELETE' {
        DELETE authentication_challenge WHERE target = $identity.id;
        UPDATE $principal SET authentication_revision = authentication_revision + 1;
    } ELSE IF $before.number != $after.number {
        UPDATE $identity.id SET
            revision = $before.revision + 1,
            verified_revision = NONE,
            verified_at = NONE;
        DELETE authentication_challenge WHERE target = $identity.id;
        UPDATE $principal SET authentication_revision = authentication_revision + 1;
    };
};

DEFINE EVENT OVERWRITE authentication_password_state ON TABLE user
WHEN $event = 'UPDATE' AND $before.password != $after.password THEN {
    UPDATE $after.id SET authentication_revision = $before.authentication_revision + 1;
    DELETE authentication_challenge WHERE principal = $after.id;
};
