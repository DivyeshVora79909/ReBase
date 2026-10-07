-- The gateway verifies WebAuthn signatures and user verification with the
-- configured RP ID and origins. Record clients may rename/revoke their own
-- credentials; they cannot create credentials, keys, challenges, or exchanges.
DEFINE TABLE OVERWRITE authentication_passkey SCHEMAFULL PERMISSIONS
    FOR select WHERE $auth AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by))
    FOR create NONE
    FOR update, delete WHERE $auth AND tenant = $auth.tenant
        AND ((owned_by = $auth AND $token.iat >= time::unix(time::now()) - 600)
            OR fn::rebase::dominates($auth, owned_by))
    COMMENT '@rebase-authentication @rebase-members fn::rebase::passkey_members';
DEFINE FIELD OVERWRITE id ON authentication_passkey TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();
DEFINE FIELD OVERWRITE owned_by ON authentication_passkey TYPE record<rebase_user> READONLY
    ASSERT record::exists($value) REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE tenant ON authentication_passkey TYPE record<rebase_tenant>
    VALUE fn::rebase::owner_tenant($this.owned_by) READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;
DEFINE FIELD OVERWRITE credential_id ON authentication_passkey TYPE string READONLY
    ASSERT $value.len() > 0 AND $value.len() <= 2048 AND string::matches($value, /^[A-Za-z0-9_-]+$/);
DEFINE FIELD OVERWRITE public_key ON authentication_passkey TYPE string READONLY
    ASSERT $value.len() > 0 PERMISSIONS NONE;
DEFINE FIELD OVERWRITE user_handle ON authentication_passkey TYPE string READONLY ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE rp_id ON authentication_passkey TYPE string READONLY ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE sign_count ON authentication_passkey TYPE int DEFAULT 0 ASSERT $value >= 0
    PERMISSIONS FOR create, update NONE;
DEFINE FIELD OVERWRITE transports ON authentication_passkey TYPE array<string> DEFAULT [] READONLY;
DEFINE FIELD OVERWRITE device_type ON authentication_passkey TYPE string READONLY
    ASSERT $value IN ['singleDevice', 'multiDevice'];
DEFINE FIELD OVERWRITE backed_up ON authentication_passkey TYPE bool DEFAULT false PERMISSIONS FOR create, update NONE;
DEFINE FIELD OVERWRITE verified_at ON authentication_passkey TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD OVERWRITE label ON authentication_passkey TYPE option<string> DEFAULT NONE;
REMOVE INDEX IF EXISTS idx_authentication_passkey_credential ON authentication_passkey;
REMOVE INDEX IF EXISTS idx_authentication_passkey_owner ON authentication_passkey;
DEFINE FIELD OVERWRITE read_by ON authentication_passkey TYPE record<rebase_user> VALUE $this.owned_by PERMISSIONS FOR select, create WHERE true FOR update NONE;

DEFINE TABLE OVERWRITE authentication_passkey_challenge SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE tenant ON authentication_passkey_challenge TYPE record<rebase_tenant> READONLY
    ASSERT record::exists($value) REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE owned_by ON authentication_passkey_challenge TYPE option<record<rebase_user>> DEFAULT NONE READONLY
    ASSERT $value = NONE OR $value.tenant = $this.tenant REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE purpose ON authentication_passkey_challenge TYPE string READONLY
    ASSERT $value IN ['registration', 'authentication'];
DEFINE FIELD OVERWRITE challenge ON authentication_passkey_challenge TYPE string READONLY ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE principal_revision ON authentication_passkey_challenge TYPE option<int> DEFAULT NONE READONLY;
DEFINE FIELD OVERWRITE expires_at ON authentication_passkey_challenge TYPE datetime READONLY;
DEFINE FIELD OVERWRITE claimed_at ON authentication_passkey_challenge TYPE option<datetime> DEFAULT NONE;
DEFINE INDEX OVERWRITE idx_passkey_challenge_expiry ON authentication_passkey_challenge COLUMNS tenant, expires_at;

DEFINE TABLE OVERWRITE authentication_passkey_exchange SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE owned_by ON authentication_passkey_exchange TYPE record<rebase_user> READONLY
    ASSERT record::exists($value) REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE tenant ON authentication_passkey_exchange TYPE record<rebase_tenant>
    VALUE fn::rebase::owner_tenant($this.owned_by) READONLY;
DEFINE FIELD OVERWRITE target ON authentication_passkey_exchange TYPE record<authentication_passkey> READONLY
    ASSERT $value.owned_by = $this.owned_by REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE principal_revision ON authentication_passkey_exchange TYPE int READONLY ASSERT $value >= 1;
DEFINE FIELD OVERWRITE expires_at ON authentication_passkey_exchange TYPE datetime READONLY;
DEFINE FIELD OVERWRITE consumed_at ON authentication_passkey_exchange TYPE option<datetime> DEFAULT NONE;
DEFINE INDEX OVERWRITE idx_passkey_exchange_expiry ON authentication_passkey_exchange COLUMNS tenant, expires_at;

DEFINE EVENT OVERWRITE authentication_passkey_state ON authentication_passkey
WHEN $event IN ['CREATE', 'DELETE'] THEN {
    LET $principal = IF $event = 'DELETE' THEN $before.owned_by ELSE $after.owned_by END;
    UPDATE $principal SET authentication_revision += 1;
    DELETE authentication_challenge WHERE principal = $principal;
};

DEFINE ACCESS OVERWRITE account_passkey ON DATABASE TYPE RECORD
    SIGNIN {
        IF $tenant = NONE OR $exchange_token = NONE { RETURN NONE; };
        LET $tenant_id = type::record($tenant);
        LET $exchange_id = type::record('authentication_passkey_exchange', 'x_' + crypto::sha256($exchange_token));
        LET $exchange = (SELECT * FROM $exchange_id)[0];
        IF $exchange = NONE OR $exchange.tenant != $tenant_id OR $exchange.consumed_at != NONE
            OR $exchange.expires_at < time::now() OR !$exchange.owned_by.login_access
            OR $exchange.principal_revision != $exchange.owned_by.authentication_revision
            OR !record::exists($exchange.target) { RETURN NONE; };
        LET $consumed = (UPDATE $exchange_id SET consumed_at = time::now()
            WHERE consumed_at = NONE AND expires_at >= time::now() RETURN AFTER)[0];
        IF $consumed = NONE { RETURN NONE; };
        RETURN $exchange.owned_by;
    }
    AUTHENTICATE {
        IF !$auth OR !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;
