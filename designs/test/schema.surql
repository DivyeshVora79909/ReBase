USE NS main DB main;

-- 1. SYSTEM TABLES (Reactivity Registration via Lateral Data Links)
DEFINE TABLE OVERWRITE user SCHEMAFULL COMMENT '@rebase-principal user';
DEFINE FIELD a_favorite_primitive ON user TYPE option<record<test_primitive>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_friends ON user TYPE array<record<user>> DEFAULT [];
DEFINE FIELD a_watched_items ON user TYPE option<array<record<test_primitive | test_tree>>> DEFAULT NONE;

DEFINE TABLE OVERWRITE groups SCHEMAFULL COMMENT '@rebase-principal group';
DEFINE FIELD a_associated_primitive ON groups TYPE option<record<test_primitive>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_partner_groups ON groups TYPE array<record<groups>> DEFAULT [];

-- 2. PRIMITIVES & ENUMS (The Stateless Leaves)
DEFINE TABLE OVERWRITE test_primitive SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_string ON test_primitive TYPE string;
DEFINE FIELD a_int ON test_primitive TYPE int DEFAULT 0;
DEFINE FIELD a_decimal ON test_primitive TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD a_bool ON test_primitive TYPE bool DEFAULT false;
DEFINE FIELD a_datetime ON test_primitive TYPE datetime DEFAULT time::now();
DEFINE FIELD a_object ON test_primitive TYPE object DEFAULT {};
DEFINE FIELD a_enum ON test_primitive TYPE string ASSERT $value IN ['pending', 'active', 'archived'] DEFAULT 'pending';



-- 3. RELATIONAL PERMUTATIONS (Edges, Arrays, and Polymorphism)
DEFINE TABLE OVERWRITE test_relation SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_primitive ON test_relation TYPE record<test_primitive> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_polymorphic ON test_relation TYPE option<record<test_primitive | user>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_primitive_array ON test_relation TYPE array<record<test_primitive>> DEFAULT [] REFERENCE ON DELETE IGNORE
    COMMENT '@rebase-readers';
DEFINE FIELD a_poly_array ON test_relation TYPE option<array<record<test_primitive | groups>>> DEFAULT NONE;


-- 4. MULTI-RELATION (Multiple FKs from ONE table to ONE target)
DEFINE TABLE OVERWRITE test_multiref SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON test_multiref TYPE string;
DEFINE FIELD a_creator ON test_multiref TYPE record<user> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_reviewer ON test_multiref TYPE option<record<user>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_approver ON test_multiref TYPE option<record<user>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_owning_group ON test_multiref TYPE record<groups> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_auditing_group ON test_multiref TYPE option<record<groups>> REFERENCE ON DELETE REJECT DEFAULT NONE;


-- 5. TREE / SELF-REFERENTIAL (Recursive DAG)
DEFINE TABLE OVERWRITE test_tree SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON test_tree TYPE string;
DEFINE FIELD a_parent ON test_tree TYPE option<record<test_tree>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD a_related_nodes ON test_tree TYPE array<record<test_tree>> DEFAULT [] REFERENCE ON DELETE IGNORE
    COMMENT '@rebase-readers';

DEFINE FIELD e_guard ON test_tree TYPE bool VALUE {
    IF $this.a_parent = $this.id {
        THROW "TOPOLOGY_ERR: A node cannot be its own parent.";
    };
    RETURN true;
} ASSERT $value = true;

-- 6. NATIVE EXTERNAL RESOURCE TABLES
DEFINE TABLE OVERWRITE email_brevo_config SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD label ON email_brevo_config TYPE string;
DEFINE FIELD visibility ON email_brevo_config TYPE bool DEFAULT false;
DEFINE FIELD technical_owner ON email_brevo_config TYPE option<record<user | groups>> DEFAULT NONE REFERENCE ON DELETE REJECT;
DEFINE FIELD from_email ON email_brevo_config TYPE string ASSERT string::is_email($value);
DEFINE FIELD from_name ON email_brevo_config TYPE string;
DEFINE FIELD reply_to ON email_brevo_config TYPE option<string> DEFAULT NONE ASSERT $value = NONE OR string::is_email($value);
DEFINE FIELD api_secret_ref ON email_brevo_config TYPE string
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD compliance_note ON email_brevo_config TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD sending_enabled ON email_brevo_config TYPE bool DEFAULT false;
DEFINE FIELD account_key ON email_brevo_config TYPE string READONLY;
DEFINE FIELD last_verified_at ON email_brevo_config TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;

-- 7. TABLE-KEYED EFFECT EXAMPLES
DEFINE TABLE OVERWRITE file_storage_config SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD provider ON file_storage_config TYPE string DEFAULT 'local-storage';
DEFINE FIELD bucket ON file_storage_config TYPE string;
DEFINE FIELD credential_ref ON file_storage_config TYPE string
    PERMISSIONS FOR select NONE
    COMMENT '@rebase-audit-redact';
DEFINE FIELD default_expiry_seconds ON file_storage_config TYPE int DEFAULT 900 ASSERT $value > 0;

DEFINE TABLE OVERWRITE file_access_grant SCHEMAFULL COMMENT '@rebase-audit @rebase-effect sync';
DEFINE FIELD id ON file_access_grant TYPE uuid DEFAULT rand::uuid::v7();
DEFINE FIELD storage_config ON file_access_grant TYPE record<file_storage_config>
    REFERENCE ON DELETE REJECT
    COMMENT '@rebase-effect-input';
DEFINE FIELD object_key ON file_access_grant TYPE string COMMENT '@rebase-effect-input';
DEFINE FIELD expires_in ON file_access_grant TYPE int DEFAULT 900 ASSERT $value > 0
    COMMENT '@rebase-effect-input';
DEFINE FIELD effect_state ON file_access_grant TYPE string DEFAULT 'pending'
    ASSERT $value IN ['pending', 'succeeded', 'failed']
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD access_url ON file_access_grant TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD access_token ON file_access_grant TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select NONE FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD expires_at ON file_access_grant TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD provider_reference ON file_access_grant TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD provider_state ON file_access_grant TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD object_size ON file_access_grant TYPE option<int> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD object_etag ON file_access_grant TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD completed_at ON file_access_grant TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';

DEFINE TABLE OVERWRITE send_brevo_email SCHEMAFULL COMMENT '@rebase-audit @rebase-effect async';
DEFINE FIELD id ON send_brevo_email TYPE uuid DEFAULT rand::uuid::v7();
DEFINE FIELD config ON send_brevo_email TYPE record<email_brevo_config>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD to ON send_brevo_email TYPE array<string>
    ASSERT $value.len() > 0 AND array::all($value, |$email| string::is_email($email)) READONLY;
DEFINE FIELD subject ON send_brevo_email TYPE string ASSERT $value.len() > 0 READONLY;
DEFINE FIELD html ON send_brevo_email TYPE option<string> DEFAULT NONE READONLY;
DEFINE FIELD text ON send_brevo_email TYPE option<string> DEFAULT NONE READONLY;
DEFINE FIELD effect_state ON send_brevo_email TYPE string DEFAULT 'pending'
    ASSERT $value IN ['pending', 'processing', 'waiting', 'succeeded', 'failed']
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD provider_reference ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD provider_state ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD result ON send_brevo_email TYPE option<object> FLEXIBLE DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD error_code ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD error_message ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
