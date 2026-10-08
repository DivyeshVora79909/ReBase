-- Cash has its actual effective time. The invoice guard permits covered advances.

DEFINE FUNCTION OVERWRITE fn::accounting::settlement_validate($row: object) {
    fn::accounting::fee_validate($row);
    fn::accounting::rate_validate($row.treasury_currency, $row.currency, $row.exchange_rate);
    fn::accounting::precision_validate($row.amount, $row.treasury_currency);
    IF ($row.z_capacity.summary.measures.cash.instant_min ?? 0dec) < 0dec
        OR ($row.z_capacity.summary.measures.invoice_amount.instant_min ?? 0dec) < 0dec { THROW 'PAYMENT_REVERSAL_CAPACITY'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::settlement_members($row: object) {
    RETURN array::concat(array::concat(array::concat(fn::accounting::commercial_members($row, 0dec, $row.invoice_amount), [
        fn::accounting::balance_member($row, 'z_treasury', $row.treasury, $row.effective_at,
            fn::accounting::effects(IF $row.is_sale THEN $row.amount ELSE -$row.amount END, 0dec, 0dec), false),
        fn::tree::member($row.id, 'z_self', $row.id, 'z_capacity', $row.effective_at,
            { cash: $row.amount, invoice_amount: $row.invoice_amount }, {}, {}, false)]), fn::accounting::fee_members($row)), fn::accounting::payment_pair($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE invoice_settlement SCHEMAFULL COMMENT '@rebase-members fn::accounting::settlement_members @rebase-validate fn::accounting::settlement_validate';
DEFINE FIELD OVERWRITE invoice ON invoice_settlement TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE treasury ON invoice_settlement TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON invoice_settlement TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON invoice_settlement TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON invoice_settlement TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE organization ON invoice_settlement TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON invoice_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON invoice_settlement TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON invoice_settlement TYPE bool VALUE record::tb($this.invoice) = 'sales_invoice' COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury_currency ON invoice_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON invoice_settlement TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_amount ON invoice_settlement TYPE decimal VALUE fn::accounting::round($this.amount * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_capacity ON invoice_settlement TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_organization ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_treasury ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_self ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice_settlement.z_capacity';

DEFINE FUNCTION OVERWRITE fn::accounting::payment_change_validate($row: object) {
    fn::accounting::fee_validate($row);
    IF $row.effective_at < $row.source_at { THROW 'PAYMENT_CHANGE_BEFORE_SOURCE'; };
    fn::accounting::phase($row.effective_at, $row.invoice_date, record::tb($row.id) = 'payment_adjustment');
    fn::accounting::precision_validate($row.cash_delta, $row.treasury_currency);
    fn::accounting::precision_validate($row.invoice_delta, $row.currency);
    IF math::abs($row.cash_delta) > $row.source_amount OR math::abs($row.invoice_delta) > $row.source_invoice_amount { THROW 'PAYMENT_CHANGE_MAGNITUDE'; };
    IF ($row.cash_delta < 0dec AND $row.invoice_delta > 0dec) OR ($row.cash_delta > 0dec AND $row.invoice_delta < 0dec) { THROW 'PAYMENT_CHANGE_DIRECTION'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::payment_change_members($row: object) {
    RETURN array::concat(array::concat(array::concat(fn::accounting::commercial_members($row, 0dec, $row.invoice_delta), [
        fn::accounting::balance_member($row, 'z_treasury', $row.treasury, $row.effective_at,
            fn::accounting::effects(IF $row.is_sale THEN $row.cash_delta ELSE -$row.cash_delta END, 0dec, 0dec), false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_capacity', $row.effective_at,
            { cash: $row.cash_delta, invoice_amount: $row.invoice_delta }, {}, {}, false)]), fn::accounting::fee_members($row)), fn::accounting::payment_pair($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE payment_refund SCHEMAFULL COMMENT '@rebase-members fn::accounting::payment_change_members @rebase-validate fn::accounting::payment_change_validate';
DEFINE FIELD OVERWRITE source ON payment_refund TYPE record<invoice_settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON payment_refund TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON payment_refund TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON payment_refund TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE entered_invoice_amount ON payment_refund TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice ON payment_refund TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE organization ON payment_refund TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.source.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON payment_refund TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON payment_refund TYPE datetime VALUE $this.source.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON payment_refund TYPE bool VALUE $this.source.is_sale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_at ON payment_refund TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_amount ON payment_refund TYPE decimal VALUE $this.source.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_invoice_amount ON payment_refund TYPE decimal VALUE $this.source.invoice_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury ON payment_refund TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT VALUE $this.source.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury_currency ON payment_refund TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.treasury_currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE exchange_rate ON payment_refund TYPE decimal VALUE $this.source.exchange_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON payment_refund TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE cash_delta ON payment_refund TYPE decimal VALUE -$this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_delta ON payment_refund TYPE decimal VALUE -($this.entered_invoice_amount ?? fn::accounting::round($this.amount * $this.exchange_rate, $this.precision)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_organization ON payment_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON payment_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_treasury ON payment_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_source ON payment_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice_settlement.z_capacity';

DEFINE TABLE OVERWRITE payment_adjustment SCHEMAFULL COMMENT '@rebase-members fn::accounting::payment_change_members @rebase-validate fn::accounting::payment_change_validate';
DEFINE FIELD OVERWRITE source ON payment_adjustment TYPE record<invoice_settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON payment_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON payment_adjustment TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount_delta ON payment_adjustment TYPE decimal ASSERT $value != 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE entered_invoice_delta ON payment_adjustment TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice ON payment_adjustment TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE organization ON payment_adjustment TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.source.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON payment_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON payment_adjustment TYPE datetime VALUE $this.source.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON payment_adjustment TYPE bool VALUE $this.source.is_sale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_at ON payment_adjustment TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_amount ON payment_adjustment TYPE decimal VALUE $this.source.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_invoice_amount ON payment_adjustment TYPE decimal VALUE $this.source.invoice_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury ON payment_adjustment TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT VALUE $this.source.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE treasury_currency ON payment_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.treasury_currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE exchange_rate ON payment_adjustment TYPE decimal VALUE $this.source.exchange_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON payment_adjustment TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE cash_delta ON payment_adjustment TYPE decimal VALUE $this.amount_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_delta ON payment_adjustment TYPE decimal VALUE $this.entered_invoice_delta ?? fn::accounting::round($this.cash_delta * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_organization ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_treasury ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_source ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice_settlement.z_capacity';
