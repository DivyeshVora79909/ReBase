-- One allocated customer cash refund. The refund is the single real movement;
-- it restores the linked receivable and reverses its allocation effects.

DEFINE FUNCTION OVERWRITE fn::accounting::receivable_cash_refund_members($row: object) {
    RETURN [
        fn::movement::cash_position($row.id, 'z_treasury', $row.treasury_account, $row.effective_at, -$row.amount),
        fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
            { receivable: $row.amount, net: $row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_target', $row.target, 'z_settlement', $row.effective_at,
            { settled: -$row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_refund_capacity', $row.allocation, 'z_refunds', $row.effective_at,
            { remaining: -$row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_cash_source', $row.cash_in, 'z_allocations', $row.effective_at,
            { refunded: $row.amount, allocation_reversed: $row.amount }, { currency: $row.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::receivable_cash_refund_validate($row: object) {
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_RECEIVABLE_CASH_REFUND_POSITIVE'; };
    IF fn::accounting::currency_round($row.amount, $row.currency.precision) != $row.amount {
        THROW 'ACCOUNTING_RECEIVABLE_CASH_REFUND_CURRENCY_PRECISION';
    };
    IF $row.effective_at <= $row.allocation_at {
        THROW 'ACCOUNTING_RECEIVABLE_CASH_REFUND_NOT_AFTER_ALLOCATION';
    };
    IF $row.cash_in.economic_entity != $row.economic_entity
        OR $row.target.economic_entity != $row.economic_entity
        OR $row.claim_account.economic_entity != $row.economic_entity {
        THROW 'ACCOUNTING_RECEIVABLE_CASH_REFUND_ENTITY_MISMATCH';
    };
    IF $row.cash_in.from_party != $row.customer
        OR $row.claim_account.opponent != $row.customer {
        THROW 'ACCOUNTING_RECEIVABLE_CASH_REFUND_PARTY_MISMATCH';
    };
    IF $row.cash_in.to_account.currency != $row.currency
        OR $row.claim_account.currency != $row.currency {
        THROW 'ACCOUNTING_RECEIVABLE_CASH_REFUND_CURRENCY_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE receivable_cash_refund SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::receivable_cash_refund_members @rebase-validate fn::accounting::receivable_cash_refund_validate';
DEFINE FIELD OVERWRITE allocation ON receivable_cash_refund TYPE record<receivable_cash_allocation> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON receivable_cash_refund TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON receivable_cash_refund TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_in ON receivable_cash_refund TYPE record<cash_in> REFERENCE ON DELETE REJECT VALUE $this.allocation.source READONLY COMMENT '@rebase-derived @rebase-depends allocation.source';
DEFINE FIELD OVERWRITE treasury_account ON receivable_cash_refund TYPE record<treasury_account> REFERENCE ON DELETE REJECT VALUE $this.cash_in.to_account READONLY COMMENT '@rebase-derived @rebase-depends cash_in.to_account';
DEFINE FIELD OVERWRITE target ON receivable_cash_refund TYPE record<receivable> REFERENCE ON DELETE REJECT VALUE $this.allocation.target READONLY COMMENT '@rebase-derived @rebase-depends allocation.target';
DEFINE FIELD OVERWRITE claim_account ON receivable_cash_refund TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.target.claim_account READONLY COMMENT '@rebase-derived @rebase-depends target.claim_account';
DEFINE FIELD OVERWRITE customer ON receivable_cash_refund TYPE record<rebase_user | organization | tax_account | misc_account> REFERENCE ON DELETE REJECT VALUE $this.cash_in.from_party READONLY COMMENT '@rebase-derived @rebase-depends cash_in.from_party';
DEFINE FIELD OVERWRITE economic_entity ON receivable_cash_refund TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT VALUE $this.cash_in.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends cash_in.economic_entity';
DEFINE FIELD OVERWRITE currency ON receivable_cash_refund TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury_account.currency READONLY COMMENT '@rebase-derived @rebase-depends treasury_account.currency';
DEFINE FIELD OVERWRITE allocation_at ON receivable_cash_refund TYPE datetime VALUE $this.allocation.effective_at READONLY COMMENT '@rebase-derived @rebase-depends allocation.effective_at';
DEFINE FIELD OVERWRITE z_treasury ON receivable_cash_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_claim ON receivable_cash_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_target ON receivable_cash_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner receivable.z_settlement';
DEFINE FIELD OVERWRITE z_refund_capacity ON receivable_cash_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner receivable_cash_allocation.z_refunds';
DEFINE FIELD OVERWRITE z_cash_source ON receivable_cash_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_in.z_allocations';
