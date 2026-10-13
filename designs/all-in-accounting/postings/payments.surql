DEFINE FUNCTION OVERWRITE fn::accounting::settlement_validate($row: object) {
    fn::accounting::same_subsidiary($row.treasury,$row.currency_account);
    fn::accounting::precision_validate($row.amount,$row.treasury_currency);
    IF ($row.z_capacity.summary.measures.cash.instant_min??0dec)<0dec OR ($row.z_capacity.summary.measures.invoice_amount.instant_min??0dec)<0dec { THROW 'PAYMENT_REVERSAL_CAPACITY'; };
    fn::accounting::fee_validate($row);
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::settlement_members($row: object) {
    RETURN array::concat(fn::accounting::commercial($row,0dec,$row.invoice_amount),
        fn::accounting::post($row,'z_cash',$row.treasury,$row.effective_at,fn::accounting::effects(IF $row.is_sale THEN $row.amount ELSE -$row.amount END,0dec,0dec)),[
        fn::tree::member($row.id,'z_self',$row.id,'z_capacity',$row.effective_at,{cash:$row.amount,invoice_amount:$row.invoice_amount},{},{},false),
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)],fn::accounting::fee_members($row));
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::payment_adjustment_validate($row: object) {
    IF $row.effective_at<=$row.source_at { THROW 'ADJUSTMENT_AFTER_SOURCE'; };
    fn::accounting::precision_validate($row.amount_delta,$row.treasury_currency);
    fn::accounting::precision_validate($row.invoice_delta,$row.currency);
    IF math::abs($row.amount_delta)>$row.source_amount OR math::abs($row.invoice_delta)>$row.source_invoice_amount { THROW 'PAYMENT_CHANGE_MAGNITUDE'; };
    IF ($row.amount_delta<0dec AND $row.invoice_delta>0dec) OR ($row.amount_delta>0dec AND $row.invoice_delta<0dec) { THROW 'PAYMENT_CHANGE_DIRECTION'; };
    fn::accounting::fee_validate($row);
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::payment_adjustment_members($row: object) {
    RETURN array::concat(fn::accounting::commercial($row,0dec,$row.invoice_delta),
        fn::accounting::post($row,'z_cash',$row.treasury,$row.effective_at,fn::accounting::effects(IF $row.is_sale THEN $row.amount_delta ELSE -$row.amount_delta END,0dec,0dec)),[
        fn::tree::member($row.id,'z_source',$row.source,'z_capacity',$row.effective_at,{cash:$row.amount_delta,invoice_amount:$row.invoice_delta},{},{},false),
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)],fn::accounting::fee_members($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE invoice_settlement SCHEMAFULL COMMENT '@rebase-members fn::accounting::settlement_members @rebase-validate fn::accounting::settlement_validate';

DEFINE FIELD OVERWRITE invoice ON invoice_settlement TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE treasury ON invoice_settlement TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON invoice_settlement TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON invoice_settlement TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON invoice_settlement TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON invoice_settlement TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency_account ON invoice_settlement TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON invoice_settlement TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON invoice_settlement TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON invoice_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON invoice_settlement TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON invoice_settlement TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON invoice_settlement TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE treasury_currency ON invoice_settlement TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON invoice_settlement TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.treasury_currency,$this.currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_amount ON invoice_settlement TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_capacity ON invoice_settlement TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_cash ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';

DEFINE FIELD OVERWRITE z_cash_subsidiary ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_cash_sub_rate ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_self ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice_settlement.z_capacity';

DEFINE FIELD OVERWRITE z_fx ON invoice_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE payment_adjustment SCHEMAFULL COMMENT '@rebase-members fn::accounting::payment_adjustment_members @rebase-validate fn::accounting::payment_adjustment_validate';

DEFINE FIELD OVERWRITE source ON payment_adjustment TYPE record<invoice_settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON payment_adjustment TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON payment_adjustment TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount_delta ON payment_adjustment TYPE decimal ASSERT $value!=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE entered_invoice_delta ON payment_adjustment TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON payment_adjustment TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON payment_adjustment TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON payment_adjustment TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON payment_adjustment TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON payment_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON payment_adjustment TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON payment_adjustment TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON payment_adjustment TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE adjustment_note ON payment_adjustment TYPE record<sales_adjustment_note | purchase_adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_note ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE treasury ON payment_adjustment TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT VALUE $this.source.treasury COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE treasury_currency ON payment_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.treasury_currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_pair ON payment_adjustment TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source.exchange_pair COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_amount ON payment_adjustment TYPE decimal VALUE $this.source.amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_invoice_amount ON payment_adjustment TYPE decimal VALUE $this.source.invoice_amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON payment_adjustment TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON payment_adjustment TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.treasury_currency,$this.currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_delta ON payment_adjustment TYPE decimal VALUE $this.entered_invoice_delta??fn::accounting::round($this.amount_delta*$this.exchange_rate,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_cash ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';

DEFINE FIELD OVERWRITE z_cash_subsidiary ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_cash_sub_rate ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_source ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice_settlement.z_capacity';

DEFINE FIELD OVERWRITE z_fx ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';
