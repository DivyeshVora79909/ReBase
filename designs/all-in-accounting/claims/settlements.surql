-- Cash allocations use one concrete source and one concrete outstanding claim.

DEFINE FUNCTION OVERWRITE fn::accounting::receivable_cash_allocation_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.target.claim_account, 'z_history', $row.effective_at,
            { receivable: -$row.amount, net: -$row.amount }, { currency: $row.target.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_target', $row.target, 'z_settlement', $row.effective_at,
            { settled: $row.amount }, { currency: $row.target.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_allocations', $row.effective_at,
            { allocated: $row.amount, available: -$row.amount }, { currency: $row.source.to_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_refund_grant', $row.id, 'z_refunds', $row.effective_at,
            { remaining: $row.amount }, { currency: $row.source.to_account.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::payable_cash_allocation_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.target.claim_account, 'z_history', $row.effective_at,
            { payable: -$row.amount, net: $row.amount }, { currency: $row.target.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_target', $row.target, 'z_settlement', $row.effective_at,
            { settled: $row.amount }, { currency: $row.target.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_allocations', $row.effective_at,
            { allocated: $row.amount }, { currency: $row.source.from_account.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::receivable_cash_allocation_validate($row: object) {
    IF $row.source.economic_entity != $row.target.claim_account.economic_entity {
        THROW 'ACCOUNTING_RECEIVABLE_ALLOCATION_ENTITY_MISMATCH';
    };
    IF $row.source.from_party != $row.target.claim_account.opponent {
        THROW 'ACCOUNTING_RECEIVABLE_ALLOCATION_PARTY_MISMATCH';
    };
    IF $row.source.to_account.currency != $row.target.claim_account.currency {
        THROW 'ACCOUNTING_RECEIVABLE_ALLOCATION_CURRENCY_MISMATCH';
    };
    IF $row.effective_at < $row.source_at OR $row.effective_at < $row.target_at {
        THROW 'ACCOUNTING_RECEIVABLE_ALLOCATION_BEFORE_SOURCE';
    };
    IF ($row.z_refunds.summary.measures.remaining.instant_min ?? 0dec) < 0dec {
        THROW 'ACCOUNTING_RECEIVABLE_ALLOCATION_REFUND_CAPACITY';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::payable_cash_allocation_validate($row: object) {
    IF $row.source.economic_entity != $row.target.claim_account.economic_entity {
        THROW 'ACCOUNTING_PAYABLE_ALLOCATION_ENTITY_MISMATCH';
    };
    IF $row.source.to_party != $row.target.claim_account.opponent {
        THROW 'ACCOUNTING_PAYABLE_ALLOCATION_PARTY_MISMATCH';
    };
    IF $row.source.from_account.currency != $row.target.claim_account.currency {
        THROW 'ACCOUNTING_PAYABLE_ALLOCATION_CURRENCY_MISMATCH';
    };
    IF $row.effective_at < $row.source_at OR $row.effective_at < $row.target_at {
        THROW 'ACCOUNTING_PAYABLE_ALLOCATION_BEFORE_SOURCE';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE receivable_cash_allocation SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::receivable_cash_allocation_members @rebase-validate fn::accounting::receivable_cash_allocation_validate';
DEFINE FIELD OVERWRITE source ON receivable_cash_allocation TYPE record<cash_in> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE target ON receivable_cash_allocation TYPE record<receivable> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON receivable_cash_allocation TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON receivable_cash_allocation TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source_at ON receivable_cash_allocation TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE target_at ON receivable_cash_allocation TYPE datetime VALUE $this.target.effective_at COMMENT '@rebase-derived @rebase-depends target.effective_at';
DEFINE FIELD OVERWRITE z_claim ON receivable_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_target ON receivable_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner receivable.z_settlement';
DEFINE FIELD OVERWRITE z_source ON receivable_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_in.z_allocations';
DEFINE FIELD OVERWRITE z_refund_grant ON receivable_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner receivable_cash_allocation.z_refunds';
DEFINE FIELD OVERWRITE z_refunds ON receivable_cash_allocation TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE payable_cash_allocation SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::payable_cash_allocation_members @rebase-validate fn::accounting::payable_cash_allocation_validate';
DEFINE FIELD OVERWRITE source ON payable_cash_allocation TYPE record<cash_out> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE target ON payable_cash_allocation TYPE record<payable> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON payable_cash_allocation TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON payable_cash_allocation TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source_at ON payable_cash_allocation TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE target_at ON payable_cash_allocation TYPE datetime VALUE $this.target.effective_at COMMENT '@rebase-derived @rebase-depends target.effective_at';
DEFINE FIELD OVERWRITE z_claim ON payable_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_target ON payable_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payable.z_settlement';
DEFINE FIELD OVERWRITE z_source ON payable_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_out.z_allocations';
