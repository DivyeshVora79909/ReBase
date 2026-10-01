-- Explicit settlement of a direct tax-account payable with one real cash-out.

DEFINE FUNCTION OVERWRITE fn::accounting::tax_claim_remittance_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
            { payable: -$row.amount, net: $row.amount }, { currency: $row.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_allocations', $row.effective_at,
            { allocated: $row.amount }, { currency: $row.source.from_account.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::tax_claim_remittance_validate($row: object) {
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_TAX_REMITTANCE_POSITIVE'; };
    IF fn::accounting::currency_round($row.amount, $row.claim_account.currency.precision) != $row.amount {
        THROW 'ACCOUNTING_TAX_REMITTANCE_CURRENCY_PRECISION';
    };
    IF record::tb($row.claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_TAX_REMITTANCE_TAX_ACCOUNT_REQUIRED';
    };
    IF $row.source.to_party != $row.claim_account.opponent {
        THROW 'ACCOUNTING_TAX_REMITTANCE_PARTY_MISMATCH';
    };
    IF $row.source.economic_entity != $row.claim_account.economic_entity {
        THROW 'ACCOUNTING_TAX_REMITTANCE_ENTITY_MISMATCH';
    };
    IF $row.source.from_account.currency != $row.claim_account.currency {
        THROW 'ACCOUNTING_TAX_REMITTANCE_CURRENCY_MISMATCH';
    };
    IF $row.effective_at < $row.source_at {
        THROW 'ACCOUNTING_TAX_REMITTANCE_BEFORE_CASH_OUT';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE tax_claim_remittance SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::tax_claim_remittance_members @rebase-validate fn::accounting::tax_claim_remittance_validate';
DEFINE FIELD OVERWRITE source ON tax_claim_remittance TYPE record<cash_out> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE claim_account ON tax_claim_remittance TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON tax_claim_remittance TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON tax_claim_remittance TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source_at ON tax_claim_remittance TYPE datetime VALUE $this.source.effective_at READONLY COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE z_claim ON tax_claim_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_source ON tax_claim_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_out.z_allocations';
