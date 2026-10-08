-- Tax cash and credit offsets are explicit source facts with complete-time capacity.
DEFINE FUNCTION OVERWRITE fn::accounting::tax_account_validate($row: object) {
    fn::accounting::account_validate($row);
    IF ($row.z_history.summary.measures.receivable.instant_min ?? 0dec) < 0dec
        OR ($row.z_history.summary.measures.payable.instant_min ?? 0dec) < 0dec { THROW 'TAX_CLAIM_CAPACITY'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::tax_cash_validate($row: object) {
    fn::accounting::fee_validate($row);
    fn::accounting::precision_validate($row.amount, $row.treasury_currency);
    fn::accounting::rate_validate($row.treasury_currency, $row.currency, $row.exchange_rate);
    IF $row.account_amount <= 0dec { THROW 'TAX_CASH_ZERO_AMOUNT'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::tax_cash_members($row: object) {
    LET $refund = record::tb($row.id) = 'tax_refund';
    LET $deposit = record::tb($row.id) = 'tax_deposit';
    RETURN array::concat(array::concat([
        fn::accounting::balance_member($row, 'z_treasury', $row.treasury, $row.effective_at,
            fn::accounting::effects(IF $refund THEN $row.amount ELSE -$row.amount END, 0dec, 0dec), false),
        fn::accounting::balance_member($row, 'z_tax_account', $row.tax_account, $row.effective_at,
            fn::accounting::effects(IF $refund THEN -$row.account_amount ELSE $row.account_amount END,
                IF $deposit THEN $row.account_amount ELSE IF $refund THEN -$row.account_amount ELSE 0dec END,
                IF !$refund AND !$deposit THEN -$row.account_amount ELSE 0dec END), false)
    ], fn::accounting::fee_members($row)), fn::accounting::payment_pair($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE tax_settlement SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_cash_members @rebase-validate fn::accounting::tax_cash_validate';
DEFINE FIELD OVERWRITE tax_account ON tax_settlement TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE treasury ON tax_settlement TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON tax_settlement TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON tax_settlement TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON tax_settlement TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON tax_settlement TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON tax_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury_currency ON tax_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON tax_settlement TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_amount ON tax_settlement TYPE decimal VALUE fn::accounting::round($this.amount * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_treasury ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_tax_account ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE TABLE OVERWRITE tax_deposit SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_cash_members @rebase-validate fn::accounting::tax_cash_validate';
DEFINE FIELD OVERWRITE tax_account ON tax_deposit TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE treasury ON tax_deposit TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON tax_deposit TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON tax_deposit TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON tax_deposit TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON tax_deposit TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON tax_deposit TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury_currency ON tax_deposit TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON tax_deposit TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_amount ON tax_deposit TYPE decimal VALUE fn::accounting::round($this.amount * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_treasury ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_tax_account ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE TABLE OVERWRITE tax_refund SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_cash_members @rebase-validate fn::accounting::tax_cash_validate';
DEFINE FIELD OVERWRITE tax_account ON tax_refund TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE treasury ON tax_refund TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON tax_refund TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON tax_refund TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON tax_refund TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON tax_refund TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON tax_refund TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury_currency ON tax_refund TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON tax_refund TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_amount ON tax_refund TYPE decimal VALUE fn::accounting::round($this.amount * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_treasury ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_tax_account ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FUNCTION OVERWRITE fn::accounting::tax_offset_validate($row: object) {
    fn::accounting::precision_validate($row.amount, $row.credit_currency);
    fn::accounting::rate_validate($row.credit_currency, $row.liability_currency, $row.exchange_rate);
    IF $row.liability_amount <= 0dec { THROW 'TAX_OFFSET_ZERO_AMOUNT'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::tax_offset_members($row: object) {
    RETURN [
        fn::accounting::balance_member($row, 'z_credit', $row.credit_account, $row.effective_at,
            fn::accounting::effects(0dec, -$row.amount, 0dec), false),
        fn::accounting::balance_member($row, 'z_liability', $row.liability_account, $row.effective_at,
            fn::accounting::effects(0dec, 0dec, -$row.liability_amount), false)
    ];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE tax_offset SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_offset_members @rebase-validate fn::accounting::tax_offset_validate';
DEFINE FIELD OVERWRITE credit_account ON tax_offset TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE liability_account ON tax_offset TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON tax_offset TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON tax_offset TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON tax_offset TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON tax_offset TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE credit_currency ON tax_offset TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.credit_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE liability_currency ON tax_offset TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.liability_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON tax_offset TYPE int VALUE $this.liability_currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE liability_amount ON tax_offset TYPE decimal VALUE fn::accounting::round($this.amount * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_credit ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';
DEFINE FIELD OVERWRITE z_liability ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';
