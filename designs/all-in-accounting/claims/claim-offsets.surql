-- An explicit paired offset against receivable and payable positions on the
-- same tax claim account. One tree membership carries both reductions.

DEFINE FUNCTION OVERWRITE fn::accounting::claim_offset_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
        { receivable: -$row.amount, payable: -$row.amount, net: 0dec },
        { currency: $row.claim_account.currency }, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::claim_offset_validate($row: object) {
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_CLAIM_OFFSET_POSITIVE'; };
    IF fn::accounting::currency_round($row.amount, $row.claim_account.currency.precision) != $row.amount {
        THROW 'ACCOUNTING_CLAIM_OFFSET_CURRENCY_PRECISION';
    };
    IF record::tb($row.claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_CLAIM_OFFSET_TAX_ACCOUNT_REQUIRED';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE claim_offset_instruction SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::claim_offset_members @rebase-validate fn::accounting::claim_offset_validate';
DEFINE FIELD OVERWRITE claim_account ON claim_offset_instruction TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON claim_offset_instruction TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON claim_offset_instruction TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_claim ON claim_offset_instruction TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
