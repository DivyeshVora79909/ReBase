-- 1. SYSTEM TABLES (Reactivity Registration via Lateral Data Links)
DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL;
DEFINE FIELD a_favorite_primitive ON rebase_user TYPE option<record<test_primitive>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_friends ON rebase_user TYPE array<record<rebase_user>> DEFAULT [];
DEFINE FIELD a_watched_items ON rebase_user TYPE option<array<record<test_primitive | test_tree>>> DEFAULT NONE;

DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL;
DEFINE FIELD a_associated_primitive ON rebase_group TYPE option<record<test_primitive>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_partner_groups ON rebase_group TYPE array<record<rebase_group>> DEFAULT [];

-- 2. PRIMITIVES & ENUMS (The Stateless Leaves)
DEFINE TABLE OVERWRITE test_primitive SCHEMAFULL;
DEFINE FIELD a_string ON test_primitive TYPE string COMMENT '@rebase-audit';
DEFINE FIELD a_int ON test_primitive TYPE int DEFAULT 0 COMMENT '@rebase-audit';
DEFINE FIELD a_decimal ON test_primitive TYPE decimal ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD a_bool ON test_primitive TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD a_datetime ON test_primitive TYPE datetime DEFAULT time::now() COMMENT '@rebase-audit';
DEFINE FIELD a_object ON test_primitive TYPE object DEFAULT {};
DEFINE FIELD a_enum ON test_primitive TYPE string ASSERT $value IN ['pending', 'active', 'archived'] DEFAULT 'pending' COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE audit_probe SCHEMAFULL;
DEFINE FIELD a_change_only ON audit_probe TYPE string COMMENT '@rebase-change-log';



-- 3. RELATIONAL PERMUTATIONS (Edges, Arrays, and Polymorphism)
DEFINE TABLE OVERWRITE test_relation SCHEMAFULL;
DEFINE FIELD a_primitive ON test_relation TYPE record<test_primitive> REFERENCE ON DELETE CASCADE COMMENT '@rebase-audit @rebase-readers';
DEFINE FIELD a_polymorphic ON test_relation TYPE option<record<test_primitive | rebase_user>> REFERENCE ON DELETE REJECT DEFAULT NONE COMMENT '@rebase-audit';
DEFINE FIELD a_primitive_array ON test_relation TYPE array<record<test_primitive>> DEFAULT [] REFERENCE ON DELETE IGNORE
    COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD a_poly_array ON test_relation TYPE option<array<record<test_primitive | rebase_group>>> DEFAULT NONE COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE unmarked_relation SCHEMAFULL;
DEFINE FIELD parent ON unmarked_relation TYPE option<record<test_primitive>> DEFAULT NONE REFERENCE ON DELETE REJECT;


-- 4. MULTI-RELATION (Multiple FKs from ONE table to ONE target)
DEFINE TABLE OVERWRITE test_multiref SCHEMAFULL;
DEFINE FIELD a_name ON test_multiref TYPE string COMMENT '@rebase-audit';
DEFINE FIELD a_creator ON test_multiref TYPE record<rebase_user> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD a_reviewer ON test_multiref TYPE option<record<rebase_user>> REFERENCE ON DELETE REJECT DEFAULT NONE COMMENT '@rebase-audit';
DEFINE FIELD a_approver ON test_multiref TYPE option<record<rebase_user>> REFERENCE ON DELETE REJECT DEFAULT NONE COMMENT '@rebase-audit';
DEFINE FIELD a_owning_group ON test_multiref TYPE record<rebase_group> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD a_auditing_group ON test_multiref TYPE option<record<rebase_group>> REFERENCE ON DELETE REJECT DEFAULT NONE COMMENT '@rebase-audit';


-- 5. TREE / SELF-REFERENTIAL (Recursive DAG)
DEFINE TABLE OVERWRITE test_tree SCHEMAFULL;
DEFINE FIELD a_name ON test_tree TYPE string COMMENT '@rebase-audit';
DEFINE FIELD a_parent ON test_tree TYPE option<record<test_tree>> REFERENCE ON DELETE CASCADE DEFAULT NONE COMMENT '@rebase-audit @rebase-readers';
DEFINE FIELD a_related_nodes ON test_tree TYPE array<record<test_tree>> DEFAULT [] REFERENCE ON DELETE IGNORE
    COMMENT '@rebase-readers @rebase-audit';

DEFINE FIELD e_guard ON test_tree TYPE bool VALUE {
    IF $this.a_parent = $this.id {
        THROW "TOPOLOGY_ERR: A node cannot be its own parent.";
    };
    RETURN true;
} ASSERT $value = true COMMENT '@rebase-audit';

-- 6. NATIVE EXTERNAL RESOURCE TABLES
DEFINE TABLE OVERWRITE file_storage_config SCHEMAFULL;
DEFINE FIELD provider ON file_storage_config TYPE string DEFAULT 'local-storage' COMMENT '@rebase-audit';
DEFINE FIELD visibility ON file_storage_config TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD access_key_id ON file_storage_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD secret_access_key ON file_storage_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD endpoint ON file_storage_config TYPE string ASSERT string::is_url($value)
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD region ON file_storage_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD default_expiry_seconds ON file_storage_config TYPE int DEFAULT 900 ASSERT $value > 0 AND $value <= 604800 COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE razorpay_config SCHEMAFULL;
DEFINE FIELD label ON razorpay_config TYPE string ASSERT $value.len() > 0 COMMENT '@rebase-audit';
DEFINE FIELD visibility ON razorpay_config TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD key_id ON razorpay_config TYPE string ASSERT $value.len() > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD key_secret ON razorpay_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true;
DEFINE FIELD webhook_secret ON razorpay_config TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select NONE FOR create, update WHERE true;

DEFINE TABLE OVERWRITE test_attachment SCHEMAFULL COMMENT '@rebase-effect sync @rebase-events CREATE UPDATE @rebase-mutable-inputs @rebase-adapter createS3UploadGrant @rebase-adapter createS3AccessGrant @rebase-timeout 10s';
DEFINE FIELD storage_config ON test_attachment TYPE record<file_storage_config>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD attached_to ON test_attachment TYPE record<test_primitive | test_tree>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD file_name ON test_attachment TYPE string ASSERT $value.len() > 0 AND $value.len() <= 255 READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD media_type ON test_attachment TYPE string ASSERT $value.len() > 0 AND $value.len() <= 255 READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD byte_length_limit ON test_attachment TYPE int ASSERT $value >= 0 READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD access_mode ON test_attachment TYPE string ASSERT $value IN ['upload', 'download'] DEFAULT 'upload' COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD access_duration ON test_attachment TYPE int DEFAULT 900 ASSERT $value > 0 AND $value <= 604800 COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD object_key ON test_attachment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD access_url ON test_attachment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD access_headers ON test_attachment TYPE option<object> FLEXIBLE DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD access_expires_at ON test_attachment TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';

DEFINE TABLE OVERWRITE test_attachment_cleanup SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-operation queued CREATE @rebase-adapter purgeS3Object';
DEFINE FIELD storage_config ON test_attachment_cleanup TYPE record<file_storage_config>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-operation-input';
DEFINE FIELD object_key ON test_attachment_cleanup TYPE string READONLY
    ASSERT $value.len() > 0 COMMENT '@rebase-operation-input';

DEFINE EVENT OVERWRITE rebase_create_attachment_cleanup ON TABLE test_attachment
    WHEN $event = 'DELETE' AND $before.object_key != NONE AND $before.object_key != '' THEN {
        CREATE test_attachment_cleanup CONTENT {
            owned_by: $before.owned_by,
            storage_config: $before.storage_config,
            object_key: $before.object_key,
            execute_at: IF $before.access_expires_at != NONE
                AND $before.access_expires_at + 5s > time::now()
                THEN $before.access_expires_at + 5s ELSE time::now() END
        };
    };

-- 7. TABLE-KEYED EFFECT EXAMPLES
DEFINE TABLE OVERWRITE send_brevo_email SCHEMAFULL COMMENT '@rebase-effect async @rebase-adapter sendBrevoEmail @rebase-adapter getBrevoEmailEvents @rebase-timeout 30s';
DEFINE FIELD config ON send_brevo_email TYPE option<record<rebase_email_delivery_config>> DEFAULT NONE
    ASSERT $value = NONE OR (!$auth OR (record::exists($value)
        AND $value.owned_by != rebase_group:root
        AND <string>$value.owned_by IN $auth.z_access_index))
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD to ON send_brevo_email TYPE array<string>
    ASSERT $value.len() > 0 AND array::all($value, |$email| string::is_email($email)) READONLY
    COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD subject ON send_brevo_email TYPE string ASSERT $value.len() > 0 READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD html ON send_brevo_email TYPE option<string> DEFAULT NONE READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD text ON send_brevo_email TYPE option<string> DEFAULT NONE READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD provider_reference ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD provider_state ON send_brevo_email TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD result ON send_brevo_email TYPE option<object> FLEXIBLE DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE TABLE OVERWRITE send_twilio_sms SCHEMAFULL COMMENT '@rebase-effect async @rebase-adapter sendTwilioSms @rebase-timeout 30s';
DEFINE FIELD config ON send_twilio_sms TYPE option<record<rebase_sms_delivery_config>> DEFAULT NONE
    ASSERT $value = NONE OR (!$auth OR (record::exists($value)
        AND $value.owned_by != rebase_group:root
        AND <string>$value.owned_by IN $auth.z_access_index))
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD to ON send_twilio_sms TYPE string
    ASSERT string::matches($value, /^\+[1-9][0-9]{7,14}$/) READONLY
    COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD body ON send_twilio_sms TYPE string ASSERT $value.len() > 0 READONLY
    COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD provider_reference ON send_twilio_sms TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE TABLE OVERWRITE razorpay_order SCHEMAFULL COMMENT '@rebase-effect sync @rebase-adapter createRazorpayOrder @rebase-timeout 15s';
DEFINE FIELD config ON razorpay_order TYPE record<razorpay_config>
    REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD amount_paise ON razorpay_order TYPE int ASSERT $value >= 100 AND $value <= 1000000000 READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD currency ON razorpay_order TYPE string DEFAULT 'INR' ASSERT $value = 'INR' READONLY COMMENT '@rebase-effect-input @rebase-audit';
DEFINE FIELD provider_order_id ON razorpay_order TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD receipt ON razorpay_order TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
DEFINE FIELD status ON razorpay_order TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-effect-output';
DEFINE FIELD provider_created_at ON razorpay_order TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';

DEFINE TABLE OVERWRITE razorpay_payment SCHEMAFULL;
DEFINE FIELD order ON razorpay_payment TYPE record<razorpay_order> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD provider_payment_id ON razorpay_payment TYPE string ASSERT $value.len() > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD status ON razorpay_payment TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-change-log';
DEFINE FIELD amount_paise ON razorpay_payment TYPE int ASSERT $value >= 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';
DEFINE FIELD amount_refunded_paise ON razorpay_payment TYPE int ASSERT $value >= 0 DEFAULT 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';
DEFINE FIELD currency ON razorpay_payment TYPE string ASSERT $value.len() > 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';
DEFINE FIELD method ON razorpay_payment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';
DEFINE FIELD provider_created_at ON razorpay_payment TYPE datetime
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';
DEFINE FIELD provider_event_at ON razorpay_payment TYPE datetime
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';
DEFINE FIELD error_code ON razorpay_payment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';
DEFINE FIELD error_description ON razorpay_payment TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-audit';

DEFINE INDEX OVERWRITE idx_razorpay_order_provider_order_id ON TABLE razorpay_order FIELDS provider_order_id UNIQUE;
DEFINE INDEX OVERWRITE idx_razorpay_order_receipt ON TABLE razorpay_order FIELDS receipt UNIQUE;
DEFINE INDEX OVERWRITE idx_razorpay_payment_provider_payment_id ON TABLE razorpay_payment FIELDS provider_payment_id UNIQUE;
DEFINE INDEX OVERWRITE idx_test_attachment_attached_to ON TABLE test_attachment FIELDS attached_to UNIQUE;
