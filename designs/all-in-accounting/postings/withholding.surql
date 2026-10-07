-- Withholding transfers the same claim family to the selected direct-tax account.

DEFINE FUNCTION OVERWRITE fn::accounting::withholding_validate($row: object) {
    IF $row.effective_at < $row.source_at { THROW 'WITHHOLDING_BEFORE_PAYMENT'; };
    fn::accounting::precision_validate($row.amount, $row.currency);
    fn::accounting::rate_validate($row.currency, $row.account_currency, $row.exchange_rate);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::withholding_members($row: object) {
    RETURN array::concat(fn::accounting::commercial_members($row, 0dec, $row.amount), [
        fn::accounting::balance_member($row, 'z_tax_account', $row.tax_account, $row.effective_at, fn::accounting::claim($row.is_sale, $row.account_amount), false)]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE payment_withholding SCHEMAFULL COMMENT '@rebase-members fn::accounting::withholding_members @rebase-validate fn::accounting::withholding_validate';
DEFINE FIELD OVERWRITE source ON payment_withholding TYPE record<invoice_settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_account ON payment_withholding TYPE record<direct_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON payment_withholding TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON payment_withholding TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON payment_withholding TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice ON payment_withholding TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE organization ON payment_withholding TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.source.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON payment_withholding TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON payment_withholding TYPE datetime VALUE $this.source.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON payment_withholding TYPE bool VALUE $this.source.is_sale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_at ON payment_withholding TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_currency ON payment_withholding TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_precision ON payment_withholding TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_amount ON payment_withholding TYPE decimal VALUE fn::accounting::round($this.amount * $this.exchange_rate, $this.account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_organization ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_tax_account ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history';
