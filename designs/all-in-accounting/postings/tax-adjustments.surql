DEFINE FUNCTION OVERWRITE fn::accounting::tax_adjustment_validate($row: object) {
    IF $row.effective_at<=$row.source_at { THROW 'ADJUSTMENT_AFTER_SOURCE'; };
    IF math::abs($row.amount_delta)>$row.source_amount OR math::abs($row.account_delta)>$row.source_account_amount { THROW 'TAX_CHANGE_MAGNITUDE'; };
    fn::accounting::precision_validate($row.amount_delta,$row.currency);
    fn::accounting::precision_validate($row.account_delta,$row.account_currency);
    IF ($row.amount_delta<0dec AND $row.account_delta>0dec) OR ($row.amount_delta>0dec AND $row.account_delta<0dec) { THROW 'TAX_CHANGE_DIRECTION'; };
    IF $row.adjustment!=NONE {
        IF $row.adjustment_issue!=$row.issue { THROW 'ADJUSTMENT_TAX_SOURCE'; };
        IF $row.adjustment_at<=$row.source_at OR $row.effective_at<$row.adjustment_at { THROW 'ADJUSTMENT_TAX_ORDER'; };
        IF $row.basis_before+$row.basis_delta<0dec { THROW 'ADJUSTMENT_TAX_BASIS_CAPACITY'; };
    };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::tax_adjustment_members($row: object) {
    RETURN array::concat(fn::accounting::commercial($row,$row.amount_delta,0dec),
        fn::accounting::post($row,'z_tax',$row.tax_account,$row.effective_at,fn::accounting::tax_effects($row.is_sale,$row.account_delta)),[
        fn::tree::member($row.id,'z_source',$row.source_tax,'z_capacity',$row.effective_at,{amount:$row.amount_delta,account_amount:$row.account_delta},{},{},false),
        fn::tree::member($row.id,'z_issue_net',$row.issue,'z_net',$row.effective_at,{amount:$row.amount_delta},{},{},false),
        IF $row.adjustment=NONE THEN NONE ELSE fn::tree::member($row.id,'z_order',$row.source_tax,'z_adjustments',$row.effective_at,{basis:$row.basis_delta},{},{},true) END,
        IF $row.adjustment=NONE THEN NONE ELSE fn::tree::member($row.id,'z_adjustment',$row.adjustment,'z_taxes',$row.effective_at,{amount:$row.amount_delta},{},{},$row.is_net) END,
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE tax_adjustment SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_adjustment_members @rebase-validate fn::accounting::tax_adjustment_validate';

DEFINE FIELD OVERWRITE source_tax ON tax_adjustment TYPE record<issue_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON tax_adjustment TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON tax_adjustment TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON tax_adjustment TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source_tax.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON tax_adjustment TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON tax_adjustment TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON tax_adjustment TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON tax_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON tax_adjustment TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON tax_adjustment TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON tax_adjustment TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE adjustment_note ON tax_adjustment TYPE record<sales_adjustment_note | purchase_adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_note ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE issue ON tax_adjustment TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.source_tax.source COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE tax_account ON tax_adjustment TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source_tax.tax_account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON tax_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.account_currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_pair ON tax_adjustment TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source_tax.exchange_pair COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON tax_adjustment TYPE datetime VALUE $this.source_tax.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_amount ON tax_adjustment TYPE decimal VALUE $this.source_tax.amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_account_amount ON tax_adjustment TYPE decimal VALUE $this.source_tax.account_amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON tax_adjustment TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON tax_adjustment TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount_delta ON tax_adjustment TYPE decimal ASSERT $value!=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE entered_account_delta ON tax_adjustment TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE account_delta ON tax_adjustment TYPE decimal VALUE $this.entered_account_delta??fn::accounting::round($this.amount_delta*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_taxes ON tax_adjustment TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_tax ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_source ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_tax.z_capacity';

DEFINE FIELD OVERWRITE z_issue_net ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FIELD OVERWRITE z_fx ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE net_tax_adjustment SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_adjustment_members @rebase-validate fn::accounting::tax_adjustment_validate';

DEFINE FIELD OVERWRITE source_tax ON net_tax_adjustment TYPE record<issue_net_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON net_tax_adjustment TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON net_tax_adjustment TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON net_tax_adjustment TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source_tax.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON net_tax_adjustment TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON net_tax_adjustment TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON net_tax_adjustment TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON net_tax_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON net_tax_adjustment TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON net_tax_adjustment TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON net_tax_adjustment TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE adjustment_note ON net_tax_adjustment TYPE record<sales_adjustment_note | purchase_adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_note ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE issue ON net_tax_adjustment TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.source_tax.source COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE tax_account ON net_tax_adjustment TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source_tax.tax_account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON net_tax_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.account_currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_pair ON net_tax_adjustment TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source_tax.exchange_pair COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON net_tax_adjustment TYPE datetime VALUE $this.source_tax.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_amount ON net_tax_adjustment TYPE decimal VALUE $this.source_tax.amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_account_amount ON net_tax_adjustment TYPE decimal VALUE $this.source_tax.account_amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON net_tax_adjustment TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON net_tax_adjustment TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount_delta ON net_tax_adjustment TYPE decimal ASSERT $value!=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE entered_account_delta ON net_tax_adjustment TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE account_delta ON net_tax_adjustment TYPE decimal VALUE $this.entered_account_delta??fn::accounting::round($this.amount_delta*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_source ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_net_tax.z_capacity';

DEFINE FIELD OVERWRITE z_issue_net ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FIELD OVERWRITE z_fx ON net_tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE issue_adjustment_tax SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_adjustment_members @rebase-validate fn::accounting::tax_adjustment_validate';

DEFINE FIELD OVERWRITE source_tax ON issue_adjustment_tax TYPE record<issue_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON issue_adjustment_tax TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON issue_adjustment_tax TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE adjustment ON issue_adjustment_tax TYPE record<issue_adjustment> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON issue_adjustment_tax TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source_tax.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON issue_adjustment_tax TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON issue_adjustment_tax TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON issue_adjustment_tax TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON issue_adjustment_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON issue_adjustment_tax TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON issue_adjustment_tax TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON issue_adjustment_tax TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE adjustment_note ON issue_adjustment_tax TYPE record<sales_adjustment_note | purchase_adjustment_note> REFERENCE ON DELETE REJECT VALUE $this.adjustment.adjustment_note COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_note ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE issue ON issue_adjustment_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.source_tax.source COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE tax_account ON issue_adjustment_tax TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source_tax.tax_account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON issue_adjustment_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.account_currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_pair ON issue_adjustment_tax TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source_tax.exchange_pair COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON issue_adjustment_tax TYPE datetime VALUE $this.source_tax.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_amount ON issue_adjustment_tax TYPE decimal VALUE $this.source_tax.amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_account_amount ON issue_adjustment_tax TYPE decimal VALUE $this.source_tax.account_amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON issue_adjustment_tax TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON issue_adjustment_tax TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE rate ON issue_adjustment_tax TYPE decimal VALUE $this.source_tax.rate COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE lower_bound ON issue_adjustment_tax TYPE decimal VALUE $this.source_tax.lower_bound COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE upper_bound ON issue_adjustment_tax TYPE option<decimal> VALUE $this.source_tax.upper_bound COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_basis ON issue_adjustment_tax TYPE decimal VALUE $this.source_tax.basis COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_issue ON issue_adjustment_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.adjustment.source COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_at ON issue_adjustment_tax TYPE datetime VALUE $this.adjustment.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_delta ON issue_adjustment_tax TYPE decimal VALUE $this.adjustment.amount_delta COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_net ON issue_adjustment_tax TYPE bool VALUE false COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis_delta ON issue_adjustment_tax TYPE decimal VALUE $this.adjustment_delta COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis_before ON issue_adjustment_tax TYPE decimal VALUE $this.source_basis+fn::accounting::prefix($this.source_tax,'z_adjustments','basis',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount_delta ON issue_adjustment_tax TYPE decimal VALUE fn::accounting::tax_rule($this.basis_before+$this.basis_delta,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision)-fn::accounting::tax_rule($this.basis_before,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_order ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_tax.z_adjustments';

DEFINE FIELD OVERWRITE z_adjustment ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_adjustment.z_taxes';

DEFINE INDEX OVERWRITE issue_adjustment_tax_pair ON issue_adjustment_tax FIELDS tenant,adjustment,source_tax UNIQUE;

DEFINE FIELD OVERWRITE entered_account_delta ON issue_adjustment_tax TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE account_delta ON issue_adjustment_tax TYPE decimal VALUE $this.entered_account_delta??fn::accounting::round($this.amount_delta*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_source ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_tax.z_capacity';

DEFINE FIELD OVERWRITE z_issue_net ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FIELD OVERWRITE z_fx ON issue_adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE issue_adjustment_net_tax SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_adjustment_members @rebase-validate fn::accounting::tax_adjustment_validate';

DEFINE FIELD OVERWRITE source_tax ON issue_adjustment_net_tax TYPE record<issue_net_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON issue_adjustment_net_tax TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON issue_adjustment_net_tax TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE adjustment ON issue_adjustment_net_tax TYPE record<issue_adjustment> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON issue_adjustment_net_tax TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source_tax.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON issue_adjustment_net_tax TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON issue_adjustment_net_tax TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON issue_adjustment_net_tax TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON issue_adjustment_net_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON issue_adjustment_net_tax TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON issue_adjustment_net_tax TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON issue_adjustment_net_tax TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE adjustment_note ON issue_adjustment_net_tax TYPE record<sales_adjustment_note | purchase_adjustment_note> REFERENCE ON DELETE REJECT VALUE $this.adjustment.adjustment_note COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_note ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE issue ON issue_adjustment_net_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.source_tax.source COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE tax_account ON issue_adjustment_net_tax TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source_tax.tax_account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON issue_adjustment_net_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.account_currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_pair ON issue_adjustment_net_tax TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source_tax.exchange_pair COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON issue_adjustment_net_tax TYPE datetime VALUE $this.source_tax.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_amount ON issue_adjustment_net_tax TYPE decimal VALUE $this.source_tax.amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_account_amount ON issue_adjustment_net_tax TYPE decimal VALUE $this.source_tax.account_amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON issue_adjustment_net_tax TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON issue_adjustment_net_tax TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE rate ON issue_adjustment_net_tax TYPE decimal VALUE $this.source_tax.rate COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE lower_bound ON issue_adjustment_net_tax TYPE decimal VALUE $this.source_tax.lower_bound COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE upper_bound ON issue_adjustment_net_tax TYPE option<decimal> VALUE $this.source_tax.upper_bound COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_basis ON issue_adjustment_net_tax TYPE decimal VALUE $this.source_tax.basis COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_issue ON issue_adjustment_net_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.adjustment.source COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_at ON issue_adjustment_net_tax TYPE datetime VALUE $this.adjustment.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_delta ON issue_adjustment_net_tax TYPE decimal VALUE $this.adjustment.amount_delta COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_net ON issue_adjustment_net_tax TYPE bool VALUE true COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis_delta ON issue_adjustment_net_tax TYPE decimal VALUE $this.adjustment_delta+fn::accounting::prefix($this.adjustment,'z_taxes','amount',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis_before ON issue_adjustment_net_tax TYPE decimal VALUE $this.source_basis+fn::accounting::prefix($this.source_tax,'z_adjustments','basis',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount_delta ON issue_adjustment_net_tax TYPE decimal VALUE fn::accounting::tax_rule($this.basis_before+$this.basis_delta,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision)-fn::accounting::tax_rule($this.basis_before,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_order ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_net_tax.z_adjustments';

DEFINE FIELD OVERWRITE z_adjustment ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_adjustment.z_taxes';

DEFINE INDEX OVERWRITE issue_adjustment_net_tax_pair ON issue_adjustment_net_tax FIELDS tenant,adjustment,source_tax UNIQUE;

DEFINE FIELD OVERWRITE entered_account_delta ON issue_adjustment_net_tax TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE account_delta ON issue_adjustment_net_tax TYPE decimal VALUE $this.entered_account_delta??fn::accounting::round($this.amount_delta*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_source ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_net_tax.z_capacity';

DEFINE FIELD OVERWRITE z_issue_net ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FIELD OVERWRITE z_fx ON issue_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE TABLE OVERWRITE tax_adjustment_net_tax SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_adjustment_members @rebase-validate fn::accounting::tax_adjustment_validate';

DEFINE FIELD OVERWRITE source_tax ON tax_adjustment_net_tax TYPE record<issue_net_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON tax_adjustment_net_tax TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON tax_adjustment_net_tax TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE adjustment ON tax_adjustment_net_tax TYPE record<tax_adjustment> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON tax_adjustment_net_tax TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source_tax.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON tax_adjustment_net_tax TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON tax_adjustment_net_tax TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON tax_adjustment_net_tax TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON tax_adjustment_net_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON tax_adjustment_net_tax TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON tax_adjustment_net_tax TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON tax_adjustment_net_tax TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE adjustment_note ON tax_adjustment_net_tax TYPE record<sales_adjustment_note | purchase_adjustment_note> REFERENCE ON DELETE REJECT VALUE $this.adjustment.adjustment_note COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_note ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE issue ON tax_adjustment_net_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.source_tax.source COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE tax_account ON tax_adjustment_net_tax TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source_tax.tax_account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_currency ON tax_adjustment_net_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.account_currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_pair ON tax_adjustment_net_tax TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source_tax.exchange_pair COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON tax_adjustment_net_tax TYPE datetime VALUE $this.source_tax.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_amount ON tax_adjustment_net_tax TYPE decimal VALUE $this.source_tax.amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_account_amount ON tax_adjustment_net_tax TYPE decimal VALUE $this.source_tax.account_amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_precision ON tax_adjustment_net_tax TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON tax_adjustment_net_tax TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.currency,$this.account_currency,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE rate ON tax_adjustment_net_tax TYPE decimal VALUE $this.source_tax.rate COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE lower_bound ON tax_adjustment_net_tax TYPE decimal VALUE $this.source_tax.lower_bound COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE upper_bound ON tax_adjustment_net_tax TYPE option<decimal> VALUE $this.source_tax.upper_bound COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_basis ON tax_adjustment_net_tax TYPE decimal VALUE $this.source_tax.basis COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_issue ON tax_adjustment_net_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.adjustment.issue COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_at ON tax_adjustment_net_tax TYPE datetime VALUE $this.adjustment.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE adjustment_delta ON tax_adjustment_net_tax TYPE decimal VALUE $this.adjustment.amount_delta COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_net ON tax_adjustment_net_tax TYPE bool VALUE true COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis_delta ON tax_adjustment_net_tax TYPE decimal VALUE $this.adjustment_delta+fn::accounting::prefix($this.adjustment,'z_taxes','amount',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE basis_before ON tax_adjustment_net_tax TYPE decimal VALUE $this.source_basis+fn::accounting::prefix($this.source_tax,'z_adjustments','basis',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount_delta ON tax_adjustment_net_tax TYPE decimal VALUE fn::accounting::tax_rule($this.basis_before+$this.basis_delta,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision)-fn::accounting::tax_rule($this.basis_before,$this.rate,$this.lower_bound,$this.upper_bound,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_order ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_net_tax.z_adjustments';

DEFINE FIELD OVERWRITE z_adjustment ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tax_adjustment.z_taxes';

DEFINE INDEX OVERWRITE tax_adjustment_net_tax_pair ON tax_adjustment_net_tax FIELDS tenant,adjustment,source_tax UNIQUE;

DEFINE FIELD OVERWRITE entered_account_delta ON tax_adjustment_net_tax TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE account_delta ON tax_adjustment_net_tax TYPE decimal VALUE $this.entered_account_delta??fn::accounting::round($this.amount_delta*$this.exchange_rate,$this.account_precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_tax ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_tax_subsidiary ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_tax_sub_rate ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_source ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_net_tax.z_capacity';

DEFINE FIELD OVERWRITE z_issue_net ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FIELD OVERWRITE z_fx ON tax_adjustment_net_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';
