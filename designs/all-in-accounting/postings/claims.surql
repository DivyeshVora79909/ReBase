-- Independent non-invoice obligations and their cash settlement.
DEFINE FUNCTION OVERWRITE fn::accounting::claim_validate($row: object) {
    fn::accounting::precision_validate($row.amount, $row.currency);
    IF ($row.z_capacity.summary.measures.remaining.instant_min ?? 0dec) < 0dec { THROW 'CLAIM_SETTLEMENT_CAPACITY'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::claim_members($row: object) {
    RETURN [fn::accounting::balance_member($row, 'z_account', $row.account, $row.effective_at,
        fn::accounting::claim($row.claim_kind = 'receivable', $row.amount), false),
        fn::tree::member($row.id, 'z_self', $row.id, 'z_capacity', $row.effective_at,
            { remaining: $row.amount }, {}, {}, false)];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE account_claim SCHEMAFULL COMMENT '@rebase-members fn::accounting::claim_members @rebase-validate fn::accounting::claim_validate';
DEFINE FIELD OVERWRITE account ON account_claim TYPE record<organization | direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE claim_kind ON account_claim TYPE string ASSERT $value IN ['receivable', 'payable'] COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON account_claim TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON account_claim TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON account_claim TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON account_claim TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_capacity ON account_claim TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_account ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';
DEFINE FIELD OVERWRITE z_self ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner account_claim.z_capacity';

DEFINE FUNCTION OVERWRITE fn::accounting::claim_settlement_validate($row: object) {
    fn::accounting::fee_validate($row);
    fn::accounting::precision_validate($row.amount, $row.treasury_currency);
    fn::accounting::rate_validate($row.treasury_currency, $row.currency, $row.exchange_rate);
    IF $row.account_amount <= 0dec { THROW 'CLAIM_SETTLEMENT_ZERO_AMOUNT'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::claim_settlement_members($row: object) {
    LET $received = $row.claim_kind = 'receivable';
    LET $tax_real = IF record::tb($row.account) = 'organization' THEN 0dec ELSE IF $received THEN -$row.account_amount ELSE $row.account_amount END;
    RETURN array::concat(array::concat([fn::accounting::balance_member($row, 'z_account', $row.account, $row.effective_at,
        fn::accounting::effects($tax_real, IF $received THEN -$row.account_amount ELSE 0dec END,
            IF $received THEN 0dec ELSE -$row.account_amount END), false),
        fn::accounting::balance_member($row, 'z_treasury', $row.treasury, $row.effective_at,
            fn::accounting::effects(IF $received THEN $row.amount ELSE -$row.amount END, 0dec, 0dec), false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_capacity', $row.effective_at,
            { remaining: -$row.account_amount }, {}, {}, false)], fn::accounting::fee_members($row)), fn::accounting::payment_pair($row));
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE claim_settlement SCHEMAFULL COMMENT '@rebase-members fn::accounting::claim_settlement_members @rebase-validate fn::accounting::claim_settlement_validate';
DEFINE FIELD OVERWRITE source ON claim_settlement TYPE record<account_claim> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE treasury ON claim_settlement TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON claim_settlement TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON claim_settlement TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON claim_settlement TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON claim_settlement TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE account ON claim_settlement TYPE record<organization | direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source.account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON claim_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury_currency ON claim_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE claim_kind ON claim_settlement TYPE string VALUE $this.source.claim_kind COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON claim_settlement TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_amount ON claim_settlement TYPE decimal VALUE fn::accounting::round($this.amount * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_account ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';
DEFINE FIELD OVERWRITE z_treasury ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_source ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner account_claim.z_capacity';
