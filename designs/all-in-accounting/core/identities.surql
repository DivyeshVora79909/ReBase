-- Tenant-scoped business uniqueness uses the same cross-table ordered index.
-- Identity membership does not grant access to the indexed business record.
DEFINE FIELD OVERWRITE z_accounting_codes ON rebase_tenant TYPE object PERMISSIONS NONE
COMMENT '@rebase-tree-root @rebase-tree-key string,string';
DEFINE FIELD OVERWRITE z_exchange_pairs ON rebase_tenant TYPE object PERMISSIONS NONE
COMMENT '@rebase-tree-root @rebase-tree-key record,record';
DEFINE FIELD OVERWRITE z_adjustment_taxes ON rebase_tenant TYPE object PERMISSIONS NONE
COMMENT '@rebase-tree-root @rebase-tree-key string,record,record';

DEFINE FUNCTION OVERWRITE fn::accounting::identity_member($row: object) {
    LET $table = record::tb($row.id);
    IF $table IN ['currency','measure_unit'] {
        RETURN fn::tree::ordered_member($row.id,'z_identity',$row.tenant,'z_accounting_codes',[$table,$row.code],{},{});
    };
    IF $table = 'exchange_pair' {
        RETURN fn::tree::ordered_member($row.id,'z_identity',$row.tenant,'z_exchange_pairs',[$row.given_resource,$row.received_resource],{},{});
    };
    IF $table IN ['issue_adjustment_tax','issue_adjustment_net_tax','tax_adjustment_net_tax'] {
        RETURN fn::tree::ordered_member($row.id,'z_identity',$row.tenant,'z_adjustment_taxes',[$table,$row.adjustment,$row.source_tax],{},{});
    };
    RETURN NONE;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::identity_members($row: object) {
    RETURN [fn::accounting::identity_member($row)];
} PERMISSIONS NONE;

DEFINE FIELD OVERWRITE z_identity ON currency TYPE option<object> PERMISSIONS NONE
COMMENT '@rebase-tree-node @rebase-tree-key string,string @rebase-tree-no-reader @rebase-tree-owner rebase_tenant.z_accounting_codes';

DEFINE FIELD OVERWRITE z_identity ON measure_unit TYPE option<object> PERMISSIONS NONE
COMMENT '@rebase-tree-node @rebase-tree-key string,string @rebase-tree-no-reader @rebase-tree-owner rebase_tenant.z_accounting_codes';

DEFINE FIELD OVERWRITE z_identity ON exchange_pair TYPE option<object> PERMISSIONS NONE
COMMENT '@rebase-tree-node @rebase-tree-key record,record @rebase-tree-no-reader @rebase-tree-owner rebase_tenant.z_exchange_pairs';

DEFINE FIELD OVERWRITE z_identity ON issue_adjustment_tax TYPE option<object> PERMISSIONS NONE
COMMENT '@rebase-tree-node @rebase-tree-key string,record,record @rebase-tree-no-reader @rebase-tree-owner rebase_tenant.z_adjustment_taxes';

DEFINE FIELD OVERWRITE z_identity ON issue_adjustment_net_tax TYPE option<object> PERMISSIONS NONE
COMMENT '@rebase-tree-node @rebase-tree-key string,record,record @rebase-tree-no-reader @rebase-tree-owner rebase_tenant.z_adjustment_taxes';

DEFINE FIELD OVERWRITE z_identity ON tax_adjustment_net_tax TYPE option<object> PERMISSIONS NONE
COMMENT '@rebase-tree-node @rebase-tree-key string,record,record @rebase-tree-no-reader @rebase-tree-owner rebase_tenant.z_adjustment_taxes';

