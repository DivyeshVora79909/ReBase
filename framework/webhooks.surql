DEFINE TABLE OVERWRITE rebase_webhook_receipt SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-operation queued CREATE';
DEFINE FIELD OVERWRITE provider_account_id ON rebase_webhook_receipt TYPE string ASSERT $value.len() > 0 READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE event_id ON rebase_webhook_receipt TYPE string ASSERT $value.len() > 0 AND $value.len() <= 256 READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE provider ON rebase_webhook_receipt TYPE string ASSERT $value.len() > 0 READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE event ON rebase_webhook_receipt TYPE string ASSERT $value.len() > 0 READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE config_id ON rebase_webhook_receipt TYPE string ASSERT $value.len() > 0 READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE target_id ON rebase_webhook_receipt TYPE string ASSERT $value.len() > 0 READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE payload_hash ON rebase_webhook_receipt TYPE string ASSERT $value.len() = 64 READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE normalized_payload ON rebase_webhook_receipt TYPE object FLEXIBLE READONLY
    COMMENT '@rebase-operation-input';
DEFINE FIELD OVERWRITE received_at ON rebase_webhook_receipt TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD OVERWRITE applied_at ON rebase_webhook_receipt TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE
    COMMENT '@rebase-operation-output';
DEFINE INDEX OVERWRITE idx_rebase_webhook_receipt_account_event
    ON TABLE rebase_webhook_receipt FIELDS provider_account_id, event_id UNIQUE;
