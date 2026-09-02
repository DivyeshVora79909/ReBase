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
DEFINE FIELD from_email ON email_brevo_config TYPE string ASSERT string::is_email($value);
DEFINE FIELD from_name ON email_brevo_config TYPE string;
DEFINE FIELD reply_to ON email_brevo_config TYPE option<string> DEFAULT NONE ASSERT $value = NONE OR string::is_email($value);
DEFINE FIELD api_key ON email_brevo_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD compliance_note ON email_brevo_config TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';

-- 7. TABLE-KEYED EFFECT EXAMPLES
DEFINE TABLE OVERWRITE file_storage_config SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD provider ON file_storage_config TYPE string DEFAULT 'local-storage';
DEFINE FIELD visibility ON file_storage_config TYPE bool DEFAULT false;
DEFINE FIELD access_key_id ON file_storage_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD secret_access_key ON file_storage_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD endpoint ON file_storage_config TYPE string ASSERT string::is_url($value)
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD region ON file_storage_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD default_expiry_seconds ON file_storage_config TYPE int DEFAULT 900 ASSERT $value > 0 AND $value <= 604800;

DEFINE TABLE OVERWRITE razorpay_config SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD label ON razorpay_config TYPE string ASSERT $value.len() > 0;
DEFINE FIELD visibility ON razorpay_config TYPE bool DEFAULT false;
DEFINE FIELD key_id ON razorpay_config TYPE string ASSERT $value.len() > 0 READONLY;
DEFINE FIELD key_secret ON razorpay_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD webhook_secret ON razorpay_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';

DEFINE TABLE OVERWRITE test_attachment SCHEMAFULL COMMENT '@rebase-audit @rebase-effect sync @rebase-events CREATE UPDATE DELETE @rebase-mutable-inputs @rebase-adapter createS3UploadGrant @rebase-adapter createS3AccessGrant @rebase-adapter deleteS3Object @rebase-timeout 10s';
DEFINE FIELD storage_config ON test_attachment TYPE record<file_storage_config>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD attached_to ON test_attachment TYPE record<test_primitive | test_tree>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD file_name ON test_attachment TYPE string ASSERT $value.len() > 0 AND $value.len() <= 255 READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD media_type ON test_attachment TYPE string ASSERT $value.len() > 0 AND $value.len() <= 255 READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD byte_length_limit ON test_attachment TYPE int ASSERT $value >= 0 READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD access_mode ON test_attachment TYPE string ASSERT $value IN ['upload', 'download'] DEFAULT 'upload' COMMENT '@rebase-effect-input';
DEFINE FIELD access_duration ON test_attachment TYPE int DEFAULT 900 ASSERT $value > 0 AND $value <= 604800 COMMENT '@rebase-effect-input';
DEFINE FIELD object_key ON test_attachment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD access_url ON test_attachment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output @rebase-audit-omit';
DEFINE FIELD access_headers ON test_attachment TYPE option<object> FLEXIBLE DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output @rebase-audit-omit';
DEFINE FIELD access_expires_at ON test_attachment TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';

DEFINE TABLE OVERWRITE send_brevo_email SCHEMAFULL COMMENT '@rebase-audit @rebase-effect async @rebase-adapter sendBrevoEmail @rebase-timeout 30s';
DEFINE FIELD config ON send_brevo_email TYPE record<email_brevo_config>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD to ON send_brevo_email TYPE array<string>
    ASSERT $value.len() > 0 AND array::all($value, |$email| string::is_email($email)) READONLY
    COMMENT '@rebase-effect-input';
DEFINE FIELD subject ON send_brevo_email TYPE string ASSERT $value.len() > 0 READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD html ON send_brevo_email TYPE option<string> DEFAULT NONE READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD text ON send_brevo_email TYPE option<string> DEFAULT NONE READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD provider_reference ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD provider_state ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output @rebase-change-log';
DEFINE FIELD result ON send_brevo_email TYPE option<object> FLEXIBLE DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE TABLE OVERWRITE razorpay_order SCHEMAFULL COMMENT '@rebase-audit @rebase-effect sync @rebase-adapter createRazorpayOrder @rebase-timeout 15s';
DEFINE FIELD config ON razorpay_order TYPE record<razorpay_config>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD amount_paise ON razorpay_order TYPE int ASSERT $value >= 100 AND $value <= 1000000000 READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD currency ON razorpay_order TYPE string DEFAULT 'INR' ASSERT $value = 'INR' READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD provider_order_id ON razorpay_order TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD receipt ON razorpay_order TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD status ON razorpay_order TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output @rebase-change-log';
DEFINE FIELD provider_created_at ON razorpay_order TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';

DEFINE TABLE OVERWRITE razorpay_payment SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD order ON razorpay_payment TYPE record<razorpay_order> REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD provider_payment_id ON razorpay_payment TYPE string ASSERT $value.len() > 0 READONLY;
DEFINE FIELD status ON razorpay_payment TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-change-log';
DEFINE FIELD amount_paise ON razorpay_payment TYPE int ASSERT $value >= 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE;
DEFINE FIELD currency ON razorpay_payment TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE;
DEFINE FIELD method ON razorpay_payment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;
DEFINE FIELD provider_created_at ON razorpay_payment TYPE datetime
    PERMISSIONS FOR select WHERE true FOR create, update NONE;
DEFINE FIELD error_code ON razorpay_payment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;
DEFINE FIELD error_description ON razorpay_payment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;

DEFINE INDEX OVERWRITE idx_razorpay_order_provider_order_id ON TABLE razorpay_order FIELDS provider_order_id UNIQUE;
DEFINE INDEX OVERWRITE idx_razorpay_order_receipt ON TABLE razorpay_order FIELDS receipt UNIQUE;
DEFINE INDEX OVERWRITE idx_razorpay_payment_provider_payment_id ON TABLE razorpay_payment FIELDS provider_payment_id UNIQUE;
DEFINE INDEX OVERWRITE idx_test_attachment_attached_to ON TABLE test_attachment FIELDS attached_to UNIQUE;
