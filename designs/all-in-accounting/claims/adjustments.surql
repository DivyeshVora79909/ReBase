-- Signed corrections preserve their receivable/payable family.

DEFINE FUNCTION OVERWRITE fn::accounting::receivable_adjustment_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
        { receivable: $row.delta, net: $row.delta }, { currency: $row.claim_account.currency }, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::payable_adjustment_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
        { payable: $row.delta, net: -$row.delta }, { currency: $row.claim_account.currency }, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::claim_adjustment_validate($row: object) {
    IF $row.delta = 0dec { THROW 'ACCOUNTING_CLAIM_ADJUSTMENT_NONZERO'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE receivable_adjustment SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::receivable_adjustment_members @rebase-validate fn::accounting::claim_adjustment_validate';
DEFINE FIELD OVERWRITE economic_entity ON receivable_adjustment TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE claim_account ON receivable_adjustment TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE delta ON receivable_adjustment TYPE decimal ASSERT $value != 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON receivable_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_claim ON receivable_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';

DEFINE TABLE OVERWRITE payable_adjustment SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::payable_adjustment_members @rebase-validate fn::accounting::claim_adjustment_validate';
DEFINE FIELD OVERWRITE economic_entity ON payable_adjustment TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE claim_account ON payable_adjustment TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE delta ON payable_adjustment TYPE decimal ASSERT $value != 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON payable_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_claim ON payable_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
