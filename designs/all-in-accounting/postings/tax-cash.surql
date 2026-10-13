DEFINE FUNCTION OVERWRITE fn::accounting::tax_cash_validate($row: object) {
    fn::accounting::same_subsidiary($row.treasury,$row.tax_account);
    fn::accounting::precision_validate($row.amount,$row.treasury_currency);
    IF $row.account_amount<=0dec { THROW 'TAX_CASH_ZERO_AMOUNT'; };
    fn::accounting::fee_validate($row);
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::tax_cash_members($row: object) {
    LET $refund=record::tb($row.id)='tax_refund';
    LET $deposit=record::tb($row.id)='tax_deposit';
    LET $signed=IF $refund THEN -$row.account_amount ELSE $row.account_amount END;
    RETURN array::concat(fn::accounting::post($row,'z_cash',$row.treasury,$row.effective_at,fn::accounting::effects(IF $refund THEN $row.amount ELSE -$row.amount END,0dec,0dec)),
        fn::accounting::post($row,'z_tax',$row.tax_account,$row.effective_at,
            object::extend(fn::accounting::claim($signed),{real:$signed,
                credit_available:IF $deposit THEN $row.account_amount ELSE IF $refund THEN -$row.account_amount ELSE 0dec END,
                liability_available:IF !$deposit AND !$refund THEN -$row.account_amount ELSE 0dec END})),[
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)],fn::accounting::fee_members($row));
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::offset_validate($row: object) {
    fn::accounting::same_subsidiary($row.credit_account,$row.liability_account);
    fn::accounting::precision_validate($row.amount,$row.credit_currency);
    IF $row.liability_amount<=0dec { THROW 'TAX_OFFSET_ZERO_AMOUNT'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::offset_members($row: object) {
    RETURN array::concat(fn::accounting::post($row,'z_credit',$row.credit_account,$row.effective_at,
        object::extend(fn::accounting::claim(-$row.amount),{credit_available:-$row.amount})),
        fn::accounting::post($row,'z_liability',$row.liability_account,$row.effective_at,
        object::extend(fn::accounting::claim($row.liability_amount),{liability_available:-$row.liability_amount})),[
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)]);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::withholding_validate($row: object) {
    fn::accounting::same_subsidiary($row.currency_account,$row.tax_account);
    IF $row.effective_at<$row.source_at { THROW 'WITHHOLDING_BEFORE_PAYMENT'; };
    fn::accounting::precision_validate($row.amount,$row.currency);
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::withholding_members($row: object) {
    RETURN array::concat(fn::accounting::commercial($row,0dec,$row.amount),
        fn::accounting::post($row,'z_tax',$row.tax_account,$row.effective_at,fn::accounting::tax_effects(!$row.is_sale,$row.account_amount)),[
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE tax_settlement SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_cash_members @rebase-validate fn::accounting::tax_cash_validate';

DEFINE FIELD OVERWRITE tax_account ON tax_settlement TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE treasury ON tax_settlement TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON tax_settlement TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON tax_settlement TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON tax_settlement TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON tax_settlement TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency ON tax_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE treasury_currency ON tax_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON tax_settlement TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON tax_settlement TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.treasury_currency,$this.currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_amount ON tax_settlement TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_cash ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';

DEFINE FIELD OVERWRITE z_cash_subsidiary ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_cash_sub_rate ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_fx ON tax_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE tax_deposit SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_cash_members @rebase-validate fn::accounting::tax_cash_validate';

DEFINE FIELD OVERWRITE tax_account ON tax_deposit TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE treasury ON tax_deposit TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON tax_deposit TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON tax_deposit TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON tax_deposit TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON tax_deposit TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency ON tax_deposit TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE treasury_currency ON tax_deposit TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON tax_deposit TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON tax_deposit TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.treasury_currency,$this.currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_amount ON tax_deposit TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_cash ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';

DEFINE FIELD OVERWRITE z_cash_subsidiary ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_cash_sub_rate ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_fx ON tax_deposit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE tax_refund SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_cash_members @rebase-validate fn::accounting::tax_cash_validate';

DEFINE FIELD OVERWRITE tax_account ON tax_refund TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE treasury ON tax_refund TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON tax_refund TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON tax_refund TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON tax_refund TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON tax_refund TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency ON tax_refund TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE treasury_currency ON tax_refund TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON tax_refund TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON tax_refund TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.treasury_currency,$this.currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_amount ON tax_refund TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_cash ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';

DEFINE FIELD OVERWRITE z_cash_subsidiary ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_cash_sub_rate ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_fx ON tax_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE tax_offset SCHEMAFULL COMMENT '@rebase-members fn::accounting::offset_members @rebase-validate fn::accounting::offset_validate';

DEFINE FIELD OVERWRITE credit_account ON tax_offset TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE liability_account ON tax_offset TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON tax_offset TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON tax_offset TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON tax_offset TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON tax_offset TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE credit_currency ON tax_offset TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.credit_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE liability_currency ON tax_offset TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.liability_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON tax_offset TYPE int VALUE $this.liability_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON tax_offset TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.credit_currency,$this.liability_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE liability_amount ON tax_offset TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_credit ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_credit_subsidiary ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_credit_sub_rate ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_liability ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_liability_subsidiary ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_liability_sub_rate ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_fx ON tax_offset TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE payment_withholding SCHEMAFULL COMMENT '@rebase-members fn::accounting::withholding_members @rebase-validate fn::accounting::withholding_validate';

DEFINE FIELD OVERWRITE source ON payment_withholding TYPE record<invoice_settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE tax_account ON payment_withholding TYPE record<direct_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON payment_withholding TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON payment_withholding TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON payment_withholding TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON payment_withholding TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON payment_withholding TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON payment_withholding TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON payment_withholding TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON payment_withholding TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON payment_withholding TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON payment_withholding TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON payment_withholding TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON payment_withholding TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE source_at ON payment_withholding TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON payment_withholding TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON payment_withholding TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON payment_withholding TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_amount ON payment_withholding TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_fx ON payment_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';
