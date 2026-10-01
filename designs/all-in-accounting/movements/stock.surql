-- Core real-resource movements. External parties do not get implied stock
-- accounts; each movement names a entity and a homogeneous resource position.

DEFINE FUNCTION OVERWRITE fn::movement::stock_position($id: record, $slot: string,
    $account: record<stock_account>, $at: datetime, $delta: decimal) {
    RETURN fn::tree::member($id, $slot, $account, 'z_history', $at,
        { quantity: $delta, available: $delta }, { resource: $account.resource, unit: $account.unit }, {}, false);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_in_members($row: object) {
    RETURN [fn::movement::stock_position($row.id, 'z_to', $row.to_account, $row.effective_at, $row.quantity)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_out_members($row: object) {
    RETURN [
        fn::movement::stock_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.quantity),
        fn::tree::member($row.id, 'z_return_grant', $row.id, 'z_returns', $row.effective_at,
            { quantity: $row.quantity }, { resource: $row.from_account.resource, unit: $row.from_account.unit }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_transfer_members($row: object) {
    RETURN [
        fn::movement::stock_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.quantity),
        fn::movement::stock_position($row.id, 'z_to', $row.to_account, $row.effective_at, $row.quantity)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_in_validate($row: object) {
    IF ($row.z_billing.summary.measures.billed.max_prefix ?? 0dec) > $row.quantity {
        THROW 'ACCOUNTING_STOCK_IN_OVERBILLED';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_out_validate($row: object) {
    IF ($row.z_billing.summary.measures.billed.max_prefix ?? 0dec) > $row.quantity {
        THROW 'ACCOUNTING_STOCK_OUT_OVERBILLED';
    };
    IF ($row.z_returns.summary.measures.quantity.instant_min ?? 0dec) < 0dec {
        THROW 'ACCOUNTING_STOCK_OUT_RETURN_CAPACITY';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_transfer_validate($row: object) {
    IF $row.from_account.economic_entity != $row.to_account.economic_entity {
        THROW 'ACCOUNTING_STOCK_TRANSFER_ENTITY_MISMATCH';
    };
    IF $row.from_account.resource != $row.to_account.resource OR $row.from_account.unit != $row.to_account.unit {
        THROW 'ACCOUNTING_STOCK_TRANSFER_RESOURCE_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE stock_in SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::stock_in_members @rebase-validate fn::accounting::stock_in_validate';
DEFINE FIELD OVERWRITE economic_entity ON stock_in TYPE record<rebase_user | organization> VALUE $this.to_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends to_account.economic_entity';
DEFINE FIELD OVERWRITE from_party ON stock_in TYPE record<rebase_user | organization | misc_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_account ON stock_in TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON stock_in TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON stock_in TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_to ON stock_in TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_billing ON stock_in TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE stock_out SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::stock_out_members @rebase-validate fn::accounting::stock_out_validate';
DEFINE FIELD OVERWRITE economic_entity ON stock_out TYPE record<rebase_user | organization> VALUE $this.from_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends from_account.economic_entity';
DEFINE FIELD OVERWRITE from_account ON stock_out TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_party ON stock_out TYPE record<rebase_user | organization | misc_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON stock_out TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON stock_out TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_from ON stock_out TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_billing ON stock_out TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_return_grant ON stock_out TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_out.z_returns';
DEFINE FIELD OVERWRITE z_returns ON stock_out TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FUNCTION OVERWRITE fn::accounting::stock_return_members($row: object) {
    RETURN [
        fn::movement::stock_position($row.id, 'z_destination', $row.destination_account, $row.effective_at, $row.quantity),
        fn::tree::member($row.id, 'z_source_capacity', $row.source, 'z_returns', $row.effective_at,
            { quantity: -$row.quantity }, { resource: $row.source.from_account.resource, unit: $row.source.from_account.unit }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_return_validate($row: object) {
    IF $row.return_party != $row.source.to_party {
        THROW 'ACCOUNTING_STOCK_RETURN_PARTY_MISMATCH';
    };
    IF $row.destination_account.economic_entity != $row.source.from_account.economic_entity {
        THROW 'ACCOUNTING_STOCK_RETURN_ENTITY_MISMATCH';
    };
    IF $row.destination_account.resource != $row.source.from_account.resource
        OR $row.destination_account.unit != $row.source.from_account.unit {
        THROW 'ACCOUNTING_STOCK_RETURN_RESOURCE_UNIT_MISMATCH';
    };
    IF $row.effective_at < $row.source_at {
        THROW 'ACCOUNTING_STOCK_RETURN_BEFORE_SOURCE';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE stock_return SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::stock_return_members @rebase-validate fn::accounting::stock_return_validate';
DEFINE FIELD OVERWRITE source ON stock_return TYPE record<stock_out> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE return_party ON stock_return TYPE record<rebase_user | organization | misc_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE destination_account ON stock_return TYPE record<stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON stock_return TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON stock_return TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source_at ON stock_return TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE z_destination ON stock_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_source_capacity ON stock_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_out.z_returns';

DEFINE TABLE OVERWRITE stock_transfer SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::stock_transfer_members @rebase-validate fn::accounting::stock_transfer_validate';
DEFINE FIELD OVERWRITE economic_entity ON stock_transfer TYPE record<rebase_user | organization> VALUE $this.from_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends from_account.economic_entity';
DEFINE FIELD OVERWRITE from_account ON stock_transfer TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_account ON stock_transfer TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON stock_transfer TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON stock_transfer TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_from ON stock_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_to ON stock_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
