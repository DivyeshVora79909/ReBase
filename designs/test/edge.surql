-- Project-owned integration state. R2 stores blobs; these records remain authoritative.
DEFINE TABLE edge_file SCHEMAFULL;
DEFINE FIELD name ON edge_file TYPE string;
DEFINE FIELD content_type ON edge_file TYPE string;
DEFINE FIELD size ON edge_file TYPE int ASSERT $value >= 0;
DEFINE FIELD etag ON edge_file TYPE string;
DEFINE FIELD object_key ON edge_file TYPE string PERMISSIONS NONE;
DEFINE FIELD status ON edge_file TYPE string ASSERT $value IN ['available', 'deleted'] DEFAULT 'available';

DEFINE TABLE edge_operation SCHEMAFULL;
DEFINE FIELD action ON edge_operation TYPE string ASSERT $value IN ['email.send', 'storage.upload', 'storage.download', 'storage.delete'];
DEFINE FIELD context ON edge_operation TYPE option<record> REFERENCE ON DELETE REJECT;
DEFINE FIELD request ON edge_operation TYPE object FLEXIBLE DEFAULT {} PERMISSIONS NONE;
DEFINE FIELD setting ON edge_operation TYPE record<setting> REFERENCE ON DELETE REJECT PERMISSIONS NONE;
DEFINE FIELD template ON edge_operation TYPE option<record<setting>> REFERENCE ON DELETE REJECT PERMISSIONS NONE;
DEFINE FIELD files ON edge_operation TYPE array<record<edge_file>> DEFAULT [] REFERENCE ON DELETE REJECT PERMISSIONS NONE;
DEFINE FIELD object_key ON edge_operation TYPE option<string> DEFAULT NONE PERMISSIONS NONE;
DEFINE FIELD idempotency_key ON edge_operation TYPE string PERMISSIONS NONE;
DEFINE FIELD status ON edge_operation TYPE string ASSERT $value IN ['pending', 'processing', 'completed', 'failed'] DEFAULT 'pending';
DEFINE FIELD attempts ON edge_operation TYPE int DEFAULT 0 PERMISSIONS NONE;
DEFINE FIELD claimed_at ON edge_operation TYPE option<datetime> DEFAULT NONE PERMISSIONS NONE;
DEFINE FIELD completed_at ON edge_operation TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD provider_result ON edge_operation TYPE object FLEXIBLE DEFAULT {} PERMISSIONS NONE;
DEFINE FIELD error ON edge_operation TYPE object FLEXIBLE DEFAULT {} PERMISSIONS NONE;

-- Runs as the record user. Table permissions are the authorization boundary for
-- the selected setting, template, files, and context.
DEFINE FUNCTION OVERWRITE fn::edge_prepare(
    $action: string,
    $context: option<string>,
    $input_json: string,
    $idempotency_key: string
) {
    IF $action NOT IN ['email.send', 'storage.upload', 'storage.download', 'storage.delete'] {
        THROW 'EDGE_ACTION_UNSUPPORTED';
    };
    IF !$auth OR string::len(string::trim($idempotency_key)) = 0 {
        THROW 'EDGE_UNAUTHENTICATED_OR_INVALID_IDEMPOTENCY_KEY';
    };

    LET $input = <object>encoding::json::decode($input_json);
    LET $context_record = IF $context != NONE THEN type::record($context) ELSE NONE END;
    LET $slug = IF $action = 'email.send' THEN 'email.resend.default' ELSE 'storage.r2.default' END;
    LET $record_settings = IF $context_record != NONE THEN (
        SELECT id FROM setting
        WHERE is_active = true AND slug = $slug AND target_record = $context_record
        LIMIT 1
    ) ELSE [] END;
    LET $record_setting = $record_settings[0] ?? NONE;
    LET $table_settings = IF $record_setting = NONE AND $context_record != NONE THEN (
        SELECT id FROM setting
        WHERE is_active = true AND slug = $slug
          AND target_record = NONE AND target_table = record::tb($context_record)
        LIMIT 1
    ) ELSE [] END;
    LET $table_setting = $table_settings[0] ?? NONE;
    LET $global_settings = IF $record_setting = NONE AND $table_setting = NONE THEN (
        SELECT id FROM setting
        WHERE is_active = true AND slug = $slug
          AND target_record = NONE AND target_table = NONE
        LIMIT 1
    ) ELSE [] END;
    LET $global_setting = $global_settings[0] ?? NONE;
    LET $resolved_setting = $record_setting ?? $table_setting ?? $global_setting;
    IF $resolved_setting = NONE { THROW 'EDGE_SETTING_NOT_FOUND'; };

    LET $templates = IF $action = 'email.send' AND $input.template != NONE THEN (
        SELECT id FROM setting
        WHERE id = type::record($input.template)
          AND is_active = true
          AND string::starts_with(slug, 'email.template.')
        LIMIT 1
    ) ELSE [] END;
    LET $template = $templates[0] ?? NONE;
    IF $action = 'email.send' AND $template = NONE { THROW 'EDGE_TEMPLATE_NOT_FOUND'; };

    LET $requested_files = IF $action = 'email.send' THEN
        ($input.attachments ?? []).map(|$id| type::record($id))
    ELSE IF $action IN ['storage.download', 'storage.delete'] THEN
        [type::record($input.file)]
    ELSE [] END;
    LET $files = SELECT VALUE id FROM edge_file WHERE id IN $requested_files AND status = 'available';
    IF array::len($files) != array::len($requested_files) { THROW 'EDGE_FILE_NOT_FOUND'; };

    LET $operation_id = type::record('edge_operation', [<string>$auth, $action, $idempotency_key]);
    LET $existing = (SELECT id, status FROM $operation_id)[0] ?? NONE;
    IF $existing != NONE {
        RETURN { id: <string>$existing.id, status: $existing.status };
    };

    RETURN {
        state: 'authorized',
        action: $action,
        owner: <string>$auth,
        context: IF $context_record != NONE THEN <string>$context_record ELSE NONE END,
        request: $input,
        setting: <string>$resolved_setting.id,
        template: IF $template != NONE THEN <string>$template.id ELSE NONE END,
        files: $files.map(|$file| <string>$file),
        idempotencyKey: $idempotency_key
    };
} PERMISSIONS FULL;

-- Runs as the Edge database user. It persists only the exact resolution returned
-- by the record-authenticated edge_prepare call.
DEFINE FUNCTION OVERWRITE fn::edge_create($authorization_json: string) {
    LET $authorized = <object>encoding::json::decode($authorization_json);
    IF $authorized.state != 'authorized' { THROW 'EDGE_AUTHORIZATION_INVALID'; };
    LET $operation_id = type::record('edge_operation', [
        $authorized.owner,
        $authorized.action,
        $authorized.idempotencyKey
    ]);
    LET $existing = (SELECT id, status FROM $operation_id)[0] ?? NONE;
    IF $existing != NONE {
        RETURN { id: <string>$existing.id, status: $existing.status };
    };
    LET $created = CREATE ONLY $operation_id CONTENT {
        action: $authorized.action,
        context: IF $authorized.context != NONE AND $authorized.context != NULL THEN type::record($authorized.context) ELSE NONE END,
        request: $authorized.request,
        setting: type::record($authorized.setting),
        template: IF $authorized.template != NONE AND $authorized.template != NULL THEN type::record($authorized.template) ELSE NONE END,
        files: ($authorized.files ?? []).map(|$file| type::record($file)),
        object_key: IF $authorized.action = 'storage.upload' THEN $authorized.owner + '/' + <string>rand::uuid() ELSE NONE END,
        idempotency_key: $authorized.idempotencyKey,
        status: 'pending',
        attempts: 0,
        claimed_at: NONE,
        completed_at: NONE,
        provider_result: { state: 'pending' },
        error: { code: '' },
        owned_by: type::record($authorized.owner)
    };
    RETURN { id: <string>$created.id, status: $created.status };
} PERMISSIONS NONE;

-- Runs only through the Edge database credential after edge_prepare succeeds.
DEFINE FUNCTION OVERWRITE fn::edge_claim($operation_id: string) {
    LET $id = type::record($operation_id);
    LET $operation = (SELECT * FROM $id)[0] ?? NONE;
    IF $operation = NONE { THROW 'EDGE_OPERATION_NOT_FOUND'; };
    IF $operation.status = 'completed' { RETURN { state: 'completed' }; };
    IF $operation.status = 'processing' AND $operation.claimed_at > time::now() - 5m {
        RETURN { state: 'busy' };
    };

    LET $claimed = UPDATE ONLY $id SET
        status = 'processing',
        attempts += 1,
        claimed_at = time::now()
    RETURN AFTER;
    LET $config = (SELECT payload, secrets FROM $claimed.setting)[0] ?? NONE;
    LET $template = IF $claimed.template != NONE THEN (SELECT payload FROM $claimed.template)[0] ELSE NONE END;
    LET $files = SELECT name, content_type, size, object_key FROM $claimed.files;

    RETURN {
        state: 'claimed',
        action: $claimed.action,
        provider: $config.payload.provider ?? IF $claimed.action = 'email.send' THEN 'resend' ELSE 'r2' END,
        apiKey: $config.secrets.api_key,
        idempotencyKey: $claimed.idempotency_key,
        from: $config.payload.from,
        to: $config.payload.to,
        cc: $config.payload.cc,
        bcc: $config.payload.bcc,
        replyTo: $config.payload.reply_to,
        headers: $config.payload.headers,
        template: $template.payload,
        variables: $claimed.request.variables ?? {},
        attachments: $files.map(|$file| {
            name: $file.name,
            contentType: $file.content_type,
            objectKey: $file.object_key
        }),
        objectKey: $claimed.object_key ?? $files[0].object_key,
        name: $claimed.request.name ?? $files[0].name,
        maxBytes: $config.payload.max_bytes,
        allowedTypes: $config.payload.allowed_types
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::edge_complete($operation_id: string, $result_json: string) {
    LET $id = type::record($operation_id);
    LET $result = <object>encoding::json::decode($result_json);
    LET $operation = (SELECT * FROM $id)[0] ?? NONE;
    IF $operation = NONE { THROW 'EDGE_OPERATION_NOT_FOUND'; };
    IF $operation.status = 'completed' {
        RETURN { id: <string>$operation.id, status: $operation.status, result: $operation.provider_result };
    };

    LET $file = IF $operation.action = 'storage.upload' THEN (
        CREATE ONLY edge_file CONTENT {
            name: $result.name,
            content_type: $result.contentType,
            size: $result.size,
            etag: $result.etag,
            object_key: $result.objectKey,
            status: 'available',
            owned_by: $operation.owned_by
        }
    ) ELSE NONE END;
    IF $operation.action = 'storage.delete' {
        UPDATE $operation.files SET status = 'deleted';
    };

    LET $completed = UPDATE ONLY $id SET
        status = 'completed',
        completed_at = time::now(),
        provider_result = $result
    RETURN AFTER;
    RETURN {
        id: <string>$completed.id,
        status: $completed.status,
        file: IF $file != NONE THEN <string>$file.id ELSE NONE END,
        result: $completed.provider_result
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::edge_fail(
    $operation_id: string,
    $error_json: string,
    $retryable: string
) {
    LET $id = type::record($operation_id);
    LET $error = <object>encoding::json::decode($error_json);
    LET $should_retry = $retryable = 'true';
    LET $operation = (SELECT id, status FROM $id)[0] ?? NONE;
    IF $operation = NONE { THROW 'EDGE_OPERATION_NOT_FOUND'; };
    IF $operation.status = 'completed' { RETURN { id: <string>$operation.id, status: 'completed' }; };
    LET $failed = UPDATE ONLY $id SET
        status = IF $should_retry THEN 'pending' ELSE 'failed' END,
        error = $error
    RETURN AFTER;
    RETURN { id: <string>$failed.id, status: $failed.status };
} PERMISSIONS NONE;
