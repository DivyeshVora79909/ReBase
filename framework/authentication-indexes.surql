-- One private tenant-wide unique keyspace, shared by every identity table.
-- Kind is a namespace; values are normalized by the source's VALUE clause.
DEFINE FIELD OVERWRITE z_auth_identifiers ON rebase_tenant TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key string,string';
DEFINE FIELD OVERWRITE z_auth_identifier ON rebase_user TYPE option<object> PERMISSIONS NONE
    COMMENT '@rebase-tree-node @rebase-tree-key string,string @rebase-tree-owner rebase_tenant.z_auth_identifiers @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_auth_identifier ON authentication_email TYPE option<object> PERMISSIONS NONE
    COMMENT '@rebase-tree-node @rebase-tree-key string,string @rebase-tree-owner rebase_tenant.z_auth_identifiers @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_auth_identifier ON authentication_phone TYPE option<object> PERMISSIONS NONE
    COMMENT '@rebase-tree-node @rebase-tree-key string,string @rebase-tree-owner rebase_tenant.z_auth_identifiers @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_auth_identifier ON authentication_passkey TYPE option<object> PERMISSIONS NONE
    COMMENT '@rebase-tree-node @rebase-tree-key string,string @rebase-tree-owner rebase_tenant.z_auth_identifiers @rebase-tree-no-reader';

DEFINE FUNCTION OVERWRITE fn::rebase::username_members($row: object) {
    RETURN [IF $row.username = NONE THEN NONE ELSE
        fn::tree::ordered_member($row.id, 'z_auth_identifier', $row.tenant,
            'z_auth_identifiers', ['username', $row.username], {}, {}) END];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::rebase::email_members($row: object) {
    RETURN [fn::tree::ordered_member($row.id, 'z_auth_identifier', $row.tenant,
        'z_auth_identifiers', ['email', $row.address], {}, {})];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::rebase::phone_members($row: object) {
    RETURN [fn::tree::ordered_member($row.id, 'z_auth_identifier', $row.tenant,
        'z_auth_identifiers', ['phone', $row.number], {}, {})];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::rebase::passkey_members($row: object) {
    RETURN [fn::tree::ordered_member($row.id, 'z_auth_identifier', $row.tenant,
        'z_auth_identifiers', ['passkey', $row.credential_id], {}, {})];
} PERMISSIONS NONE;

-- Only trusted authentication code may enumerate or resolve identifiers. Public
-- tree reads honor the private root and node fields, including counts and keys.
DEFINE FUNCTION OVERWRITE fn::rebase::identity($tenant: record<rebase_tenant>, $kind: string, $value: string) {
    IF !record::exists($tenant) { RETURN NONE; };
    LET $link = fn::tree::find({ rid: $tenant, slot: 'z_auth_identifiers' }, [$kind, $value]);
    RETURN IF $link = NONE THEN NONE ELSE (SELECT * FROM ONLY $link.rid) END;
} PERMISSIONS NONE;
