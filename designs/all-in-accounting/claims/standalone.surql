-- Explicit claims are dated facts independent of cash/resource movement.
-- Positive inputs select a claim family; signed corrections use later recipes.

DEFINE FUNCTION OVERWRITE fn::accounting::receivable_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
        { receivable: $row.amount, net: $row.amount }, { currency: $row.claim_account.currency }, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::payable_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
        { payable: $row.amount, net: -$row.amount }, { currency: $row.claim_account.currency }, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::claim_entry_validate($row: object) {
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_CLAIM_AMOUNT_POSITIVE'; };
    IF ($row.z_settlement.summary.measures.settled.max_prefix ?? 0dec) > $row.amount {
        THROW 'ACCOUNTING_CLAIM_OVERSETTLED';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE receivable SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::receivable_members @rebase-validate fn::accounting::claim_entry_validate';
DEFINE FIELD OVERWRITE economic_entity ON receivable TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE claim_account ON receivable TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON receivable TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON receivable TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_claim ON receivable TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_settlement ON receivable TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE payable SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::payable_members @rebase-validate fn::accounting::claim_entry_validate';
DEFINE FIELD OVERWRITE economic_entity ON payable TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE claim_account ON payable TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON payable TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON payable TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_claim ON payable TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_settlement ON payable TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
