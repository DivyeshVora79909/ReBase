DEFINE FUNCTION OVERWRITE fn::accounting::tax_rule($basis: decimal, $rate: decimal, $lower: decimal, $upper: option<decimal>, $precision: int) {
    LET $raw=$basis*$rate/100dec;
    RETURN fn::accounting::round(math::max([$lower,IF $upper=NONE THEN $raw ELSE math::min([$raw,$upper]) END]),$precision);
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::tax_effects($sale: bool, $amount: decimal) {
    RETURN object::extend(fn::accounting::claim(IF $sale THEN -$amount ELSE $amount END),
        {credit_available:IF $sale THEN 0dec ELSE $amount END,liability_available:IF $sale THEN $amount ELSE 0dec END});
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::tax_validate($row: object) {
    fn::accounting::same_subsidiary($row.currency_account,$row.tax_account);
    IF $row.effective_at<$row.source_at OR $row.effective_at>$row.invoice_date { THROW 'TAX_TIME'; };
    IF $row.is_net AND $row.basis<=0dec { THROW 'NET_TAX_REQUIRES_PRIOR_BASIS'; };
    IF $row.upper_bound!=NONE AND $row.upper_bound<$row.lower_bound { THROW 'TAX_BOUND_ORDER'; };
    fn::accounting::precision_validate($row.lower_bound,$row.currency);
    IF $row.upper_bound!=NONE { fn::accounting::precision_validate($row.upper_bound,$row.currency); };
    IF ($row.z_capacity.summary.measures.amount.instant_min??0dec)<0dec OR ($row.z_capacity.summary.measures.account_amount.instant_min??0dec)<0dec { THROW 'TAX_REVERSAL_CAPACITY'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::tax_members($row: object) {
    RETURN array::concat(fn::accounting::commercial($row,$row.amount,0dec),
        fn::accounting::post($row,'z_tax',$row.tax_account,$row.effective_at,fn::accounting::tax_effects($row.is_sale,$row.account_amount)),[
        IF $row.is_net THEN NONE ELSE fn::tree::member($row.id,'z_basis',$row.source,'z_state',$row.effective_at+1ns,{},{},{},true) END,
        fn::tree::member($row.id,'z_issue_net',$row.source,'z_net',$row.effective_at,{amount:$row.amount},{},{},$row.is_net),
        fn::tree::member($row.id,'z_self',$row.id,'z_capacity',$row.effective_at,{amount:$row.amount,account_amount:$row.account_amount},{},{},false),
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE issue_tax SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_members @rebase-validate fn::accounting::tax_validate';

DEFINE FIELD OVERWRITE source ON issue_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE tax_account ON issue_tax TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON issue_tax TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON issue_tax TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON issue_tax TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE rate ON issue_tax TYPE decimal ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE lower_bound ON issue_tax TYPE decimal DEFAULT 0dec ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE upper_bound ON issue_tax TYPE option<decimal> ASSERT $value=NONE OR $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON issue_tax TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON issue_tax TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON issue_tax TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON issue_tax TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON issue_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON issue_tax TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON issue_tax TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON issue_tax TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE source_at ON issue_tax TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_net ON issue_tax TYPE bool VALUE false COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON issue_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON issue_tax TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON issue_tax TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis ON issue_tax TYPE decimal VALUE fn::accounting::prefix($this.source,'z_state','base',$this.effective_at+1ns) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount ON issue_tax TYPE decimal VALUE fn::accounting::tax_rule($this.basis,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_amount ON issue_tax TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_capacity ON issue_tax TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_adjustments ON issue_tax TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FIELD OVERWRITE z_tax ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_basis ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_state @rebase-tree-owner purchase_issue.z_state';

DEFINE FIELD OVERWRITE z_issue_net ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FIELD OVERWRITE z_self ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_tax.z_capacity';

DEFINE FIELD OVERWRITE z_fx ON issue_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE issue_net_tax SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_members @rebase-validate fn::accounting::tax_validate';

DEFINE FIELD OVERWRITE source ON issue_net_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE tax_account ON issue_net_tax TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON issue_net_tax TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON issue_net_tax TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON issue_net_tax TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE rate ON issue_net_tax TYPE decimal ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE lower_bound ON issue_net_tax TYPE decimal DEFAULT 0dec ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE upper_bound ON issue_net_tax TYPE option<decimal> ASSERT $value=NONE OR $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON issue_net_tax TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON issue_net_tax TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON issue_net_tax TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON issue_net_tax TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON issue_net_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON issue_net_tax TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON issue_net_tax TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON issue_net_tax TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE source_at ON issue_net_tax TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_net ON issue_net_tax TYPE bool VALUE true COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON issue_net_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.tax_account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON issue_net_tax TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON issue_net_tax TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis ON issue_net_tax TYPE decimal VALUE fn::accounting::prefix($this.source,'z_net','amount',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount ON issue_net_tax TYPE decimal VALUE fn::accounting::tax_rule($this.basis,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_amount ON issue_net_tax TYPE decimal VALUE fn::accounting::round($this.amount*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_capacity ON issue_net_tax TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_adjustments ON issue_net_tax TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FIELD OVERWRITE z_tax ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_issue_net ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FIELD OVERWRITE z_self ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_net_tax.z_capacity';

DEFINE FIELD OVERWRITE z_fx ON issue_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';
