-- Authentication data is deliberately separate from the authorization graph.
-- A principal may have zero or more delivered identities and may authenticate
-- with a password, a delivered one-time code, or OAuth when an identity is
-- currently verified.

-- A recent record token is required when a principal edits its own identities.
-- Dominating administrators retain the normal graph-based management path.
-- The ten-minute window is an access policy constant, not an auth-state field.

-- Platform records are provisioned by a system connection with tenant ownership.
-- Record users can manage only their own or delegated BYOC records. Provider
-- secrets stay write-only even when non-secret metadata is visible to an owner.
DEFINE TABLE OVERWRITE rebase_email_delivery_config SCHEMAFULL PERMISSIONS
    FOR select WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by)
    FOR create WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by)
    FOR update WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by)
    FOR delete WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by);
DEFINE FIELD OVERWRITE tenant ON rebase_email_delivery_config TYPE record<rebase_tenant>
    VALUE fn::rebase::owner_tenant($this.owned_by) READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;
DEFINE FIELD OVERWRITE owned_by ON rebase_email_delivery_config TYPE record<rebase_tenant | rebase_user | rebase_group>
    ASSERT IF $auth THEN fn::rebase::can_access($auth, $value) ELSE record::exists($value) END
    REFERENCE ON DELETE REJECT
    PERMISSIONS FOR select WHERE true FOR create WHERE true FOR update NONE;
DEFINE FIELD OVERWRITE api_key ON rebase_email_delivery_config TYPE string
    ASSERT $value.len() > 0 PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD OVERWRITE from_email ON rebase_email_delivery_config TYPE string
    ASSERT string::is_email($value);
DEFINE FIELD OVERWRITE from_name ON rebase_email_delivery_config TYPE string
    ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE reply_to ON rebase_email_delivery_config TYPE option<string> DEFAULT NONE
    ASSERT $value = NONE OR string::is_email($value);

DEFINE TABLE OVERWRITE rebase_sms_delivery_config SCHEMAFULL PERMISSIONS
    FOR select WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by)
    FOR create WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by)
    FOR update WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by)
    FOR delete WHERE $auth AND tenant = $auth.tenant AND record::tb(owned_by) != 'rebase_tenant' AND fn::rebase::can_access($auth, owned_by);
DEFINE FIELD OVERWRITE tenant ON rebase_sms_delivery_config TYPE record<rebase_tenant>
    VALUE fn::rebase::owner_tenant($this.owned_by) READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;
DEFINE FIELD OVERWRITE owned_by ON rebase_sms_delivery_config TYPE record<rebase_tenant | rebase_user | rebase_group>
    ASSERT IF $auth THEN fn::rebase::can_access($auth, $value) ELSE record::exists($value) END
    REFERENCE ON DELETE REJECT
    PERMISSIONS FOR select WHERE true FOR create WHERE true FOR update NONE;
DEFINE FIELD OVERWRITE account_sid ON rebase_sms_delivery_config TYPE string
    ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE auth_token ON rebase_sms_delivery_config TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD OVERWRITE api_key_sid ON rebase_sms_delivery_config TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD OVERWRITE api_key_secret ON rebase_sms_delivery_config TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD OVERWRITE from_number ON rebase_sms_delivery_config TYPE string
    ASSERT string::matches($value, /^\+[1-9][0-9]{7,14}$/);

DEFINE TABLE OVERWRITE rebase_authentication_delivery_policy SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE tenant ON rebase_authentication_delivery_policy TYPE record<rebase_tenant> READONLY
    ASSERT record::exists($value) REFERENCE ON DELETE REJECT;
DEFINE INDEX OVERWRITE idx_authentication_policy_tenant ON rebase_authentication_delivery_policy COLUMNS tenant UNIQUE;
DEFINE FIELD OVERWRITE email_configuration ON rebase_authentication_delivery_policy
    TYPE option<record<rebase_email_delivery_config>> DEFAULT NONE
    ASSERT $value = NONE OR $value.tenant = $this.tenant
    REFERENCE ON DELETE REJECT PERMISSIONS NONE;
DEFINE FIELD OVERWRITE phone_configuration ON rebase_authentication_delivery_policy
    TYPE option<record<rebase_sms_delivery_config>> DEFAULT NONE
    ASSERT $value = NONE OR $value.tenant = $this.tenant
    REFERENCE ON DELETE REJECT PERMISSIONS NONE;

-- EMAIL IDENTITIES
DEFINE TABLE OVERWRITE authentication_email SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth AND tenant = $auth.tenant AND ((owned_by = $auth AND $token.iat >= time::unix(time::now()) - 600) OR fn::rebase::dominates($auth, owned_by))
    FOR select WHERE $auth AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by))
    FOR update WHERE $auth AND tenant = $auth.tenant AND ((owned_by = $auth AND $token.iat >= time::unix(time::now()) - 600) OR fn::rebase::dominates($auth, owned_by))
    FOR delete WHERE $auth AND tenant = $auth.tenant AND ((owned_by = $auth AND $token.iat >= time::unix(time::now()) - 600) OR fn::rebase::dominates($auth, owned_by))
    COMMENT '@rebase-authentication';

    DEFINE FIELD OVERWRITE id ON authentication_email TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();
    DEFINE FIELD OVERWRITE tenant ON authentication_email TYPE record<rebase_tenant>
        VALUE fn::rebase::owner_tenant($this.owned_by) READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;
    DEFINE FIELD OVERWRITE owned_by ON authentication_email TYPE record<rebase_user> READONLY
        ASSERT record::exists($value)
        REFERENCE ON DELETE CASCADE
        PERMISSIONS FOR update NONE;
    DEFINE FIELD OVERWRITE address ON authentication_email TYPE string VALUE {
        LET $email = string::lowercase(string::trim($value ?? ""));
        IF !string::is_email($email) { THROW "VALIDATION_ERR: Invalid authentication email"; };
        RETURN $email;
    };
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
        ;
    DEFINE FIELD OVERWRITE verified_revision ON authentication_email TYPE option<int> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by)) FOR create, update NONE
        ;
    DEFINE FIELD OVERWRITE verified_at ON authentication_email TYPE option<datetime> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by)) FOR create, update NONE
        ;
    DEFINE INDEX OVERWRITE idx_authentication_email_address ON authentication_email COLUMNS tenant, address UNIQUE;
    DEFINE INDEX OVERWRITE idx_authentication_email_owner ON authentication_email COLUMNS owned_by;

-- PHONE IDENTITIES
DEFINE TABLE OVERWRITE authentication_phone SCHEMAFULL PERMISSIONS
    FOR create WHERE $auth AND tenant = $auth.tenant AND ((owned_by = $auth AND $token.iat >= time::unix(time::now()) - 600) OR fn::rebase::dominates($auth, owned_by))
    FOR select WHERE $auth AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by))
    FOR update WHERE $auth AND tenant = $auth.tenant AND ((owned_by = $auth AND $token.iat >= time::unix(time::now()) - 600) OR fn::rebase::dominates($auth, owned_by))
    FOR delete WHERE $auth AND tenant = $auth.tenant AND ((owned_by = $auth AND $token.iat >= time::unix(time::now()) - 600) OR fn::rebase::dominates($auth, owned_by))
    COMMENT '@rebase-authentication';

    DEFINE FIELD OVERWRITE id ON authentication_phone TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();
    DEFINE FIELD OVERWRITE tenant ON authentication_phone TYPE record<rebase_tenant>
        VALUE fn::rebase::owner_tenant($this.owned_by) READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;
    DEFINE FIELD OVERWRITE owned_by ON authentication_phone TYPE record<rebase_user> READONLY
        ASSERT record::exists($value)
        REFERENCE ON DELETE CASCADE
        PERMISSIONS FOR update NONE;
    DEFINE FIELD OVERWRITE number ON authentication_phone TYPE string VALUE {
        LET $phone = string::trim($value ?? "");
        IF !string::matches($phone, /^\+[1-9][0-9]{7,14}$/) { THROW "VALIDATION_ERR: Invalid authentication phone"; };
        RETURN $phone;
    };
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
        ;
    DEFINE FIELD OVERWRITE verified_revision ON authentication_phone TYPE option<int> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by)) FOR create, update NONE
        ;
    DEFINE FIELD OVERWRITE verified_at ON authentication_phone TYPE option<datetime> DEFAULT NONE
        PERMISSIONS FOR select WHERE $auth AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by)) FOR create, update NONE
        ;
    DEFINE INDEX OVERWRITE idx_authentication_phone_number ON authentication_phone COLUMNS tenant, number UNIQUE;
    DEFINE INDEX OVERWRITE idx_authentication_phone_owner ON authentication_phone COLUMNS owned_by;

-- ONE ACTIVE CHALLENGE PER IDENTITY
DEFINE TABLE OVERWRITE authentication_challenge SCHEMAFULL PERMISSIONS NONE
    ;
DEFINE FIELD OVERWRITE tenant ON authentication_challenge TYPE record<rebase_tenant>
    VALUE $this.principal.tenant READONLY PERMISSIONS NONE;
DEFINE FIELD OVERWRITE principal ON authentication_challenge TYPE record<rebase_user>
    ASSERT record::exists($value) REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE target ON authentication_challenge TYPE record<authentication_email | authentication_phone>
    ASSERT record::exists($value) AND $value.owned_by = $this.principal REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE principal_revision ON authentication_challenge TYPE int ASSERT $value >= 1;
DEFINE FIELD OVERWRITE target_revision ON authentication_challenge TYPE int ASSERT $value >= 1;
DEFINE FIELD OVERWRITE code_hash ON authentication_challenge TYPE string
    PERMISSIONS NONE ;
DEFINE FIELD OVERWRITE attempts ON authentication_challenge TYPE int DEFAULT 0 ASSERT $value >= 0 AND $value <= 5
    PERMISSIONS NONE;
DEFINE FIELD OVERWRITE expires_at ON authentication_challenge TYPE datetime PERMISSIONS NONE;
DEFINE FIELD OVERWRITE consumed_at ON authentication_challenge TYPE option<datetime> DEFAULT NONE PERMISSIONS NONE;
DEFINE FIELD OVERWRITE delivery_nonce ON authentication_challenge TYPE uuid PERMISSIONS NONE;
DEFINE FIELD OVERWRITE created_at ON authentication_challenge TYPE datetime VALUE $before OR time::now() READONLY
    PERMISSIONS NONE;
DEFINE INDEX OVERWRITE idx_authentication_challenge_target ON authentication_challenge COLUMNS target UNIQUE;
DEFINE INDEX OVERWRITE idx_authentication_challenge_principal ON authentication_challenge COLUMNS principal;

-- The challenge and this delivery request are committed together. The
-- ciphertext contains the one-time code and message content; it is opened
-- only by the static runtime handler using the separate payload-encryption key.
DEFINE TABLE OVERWRITE authentication_delivery_task SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-operation queued CREATE @rebase-adapter sendBrevoEmail @rebase-adapter getBrevoEmailEvents @rebase-adapter sendTwilioSms @rebase-adapter openAuthenticationPayload @rebase-timeout 30s';
DEFINE FIELD OVERWRITE configuration ON authentication_delivery_task
    TYPE record<rebase_email_delivery_config | rebase_sms_delivery_config> READONLY
    ASSERT $value.tenant = $this.principal.tenant
    REFERENCE ON DELETE REJECT COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE tenant ON authentication_delivery_task TYPE record<rebase_tenant>
    VALUE $this.principal.tenant READONLY PERMISSIONS NONE;
DEFINE FIELD OVERWRITE principal ON authentication_delivery_task TYPE record<rebase_user> READONLY
    REFERENCE ON DELETE CASCADE COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE target ON authentication_delivery_task
    TYPE record<authentication_email | authentication_phone> READONLY
    ASSERT $value.owned_by = $this.principal
    REFERENCE ON DELETE CASCADE COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE challenge ON authentication_delivery_task TYPE record<authentication_challenge> READONLY
    ASSERT $value.target = $this.target AND $value.principal = $this.principal
    REFERENCE ON DELETE CASCADE COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE channel ON authentication_delivery_task TYPE string READONLY
    ASSERT $value IN ['email', 'phone'] COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE principal_revision ON authentication_delivery_task TYPE int READONLY
    ASSERT $value >= 1 COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE target_revision ON authentication_delivery_task TYPE int READONLY
    ASSERT $value >= 1 COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE delivery_nonce ON authentication_delivery_task TYPE uuid READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE payload_ciphertext ON authentication_delivery_task TYPE string READONLY
    PERMISSIONS NONE COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE provider_reference ON authentication_delivery_task TYPE option<string> DEFAULT NONE
    PERMISSIONS NONE COMMENT '@rebase-operation-output';

-- These are state-invalidation triggers, not identity-presence guards. They
-- never block identity CRUD; they only fence stale verification/challenges.
-- The account revision is a fencing value, not an authentication boolean.
DEFINE EVENT OVERWRITE authentication_email_state ON TABLE authentication_email
WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
    LET $identity = IF $event = 'DELETE' THEN $before ELSE $after END;
    LET $principal = $identity.owned_by;
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
    LET $principal = $identity.owned_by;
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

DEFINE EVENT OVERWRITE authentication_password_state ON TABLE rebase_user
WHEN $event = 'UPDATE' AND $before.password != $after.password THEN {
    UPDATE $after.id SET authentication_revision = $before.authentication_revision + 1;
    DELETE authentication_challenge WHERE principal = $after.id;
};
