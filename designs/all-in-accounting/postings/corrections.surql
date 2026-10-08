-- Corrections are explicit signed marginal facts, never hidden child postings.

DEFINE FUNCTION OVERWRITE fn::accounting::issue_change_validate($row: object) {
    IF $row.effective_at < $row.source_at { THROW 'ISSUE_CHANGE_BEFORE_SOURCE'; };
    fn::accounting::phase($row.effective_at, $row.invoice_date, record::tb($row.id) = 'issue_adjustment');
    fn::accounting::precision_validate($row.amount_delta, $row.currency);
    IF math::abs($row.quantity_delta) > $row.source_quantity OR math::abs($row.amount_delta) > $row.source_amount { THROW 'ISSUE_CHANGE_MAGNITUDE'; };
    IF record::tb($row.id) = 'issue_adjustment' {
        LET $count = array::len([$row.quantity_delta, $row.price_delta, $row.exchange_rate_delta].filter(|$v| $v != 0dec));
        IF $count != 1 { THROW 'ADJUSTMENT_ONE_DIMENSION'; };
        IF math::abs($row.price_delta) > $row.source_price OR math::abs($row.exchange_rate_delta) > $row.source_exchange_rate { THROW 'ISSUE_CHANGE_MAGNITUDE'; };
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::issue_change_members($row: object) {
    RETURN array::concat(array::concat(fn::accounting::commercial_members($row, $row.amount_delta, 0dec), [
        IF $row.quantity_delta = 0dec THEN NONE ELSE fn::accounting::balance_member($row, 'z_stock', $row.stock_account, $row.effective_at,
            fn::accounting::effects(IF $row.is_sale THEN -$row.quantity_delta ELSE $row.quantity_delta END, 0dec, 0dec), false) END,
        fn::tree::member($row.id, 'z_source', $row.source, 'z_basis', $row.effective_at, { base: $row.amount_delta, quantity: $row.quantity_delta }, {}, {}, false),
        fn::tree::member($row.id, 'z_issue_net', $row.source, 'z_net', $row.effective_at, { amount: $row.amount_delta }, {}, {}, false)]), fn::accounting::trade_members($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE issue_adjustment SCHEMAFULL COMMENT '@rebase-members fn::accounting::issue_change_members @rebase-validate fn::accounting::issue_change_validate';
DEFINE FIELD OVERWRITE source ON issue_adjustment TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON issue_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON issue_adjustment TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity_delta ON issue_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE price_delta ON issue_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate_delta ON issue_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice ON issue_adjustment TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE organization ON issue_adjustment TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.source.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON issue_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON issue_adjustment TYPE datetime VALUE $this.source.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON issue_adjustment TYPE bool VALUE $this.source.is_sale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_at ON issue_adjustment TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_quantity ON issue_adjustment TYPE decimal VALUE $this.source.quantity COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_price ON issue_adjustment TYPE decimal VALUE $this.source.price COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_exchange_rate ON issue_adjustment TYPE decimal VALUE $this.source.exchange_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_amount ON issue_adjustment TYPE decimal VALUE $this.source.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE stock_account ON issue_adjustment TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT VALUE $this.source.stock_account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON issue_adjustment TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE amount_delta ON issue_adjustment TYPE decimal VALUE fn::accounting::round($this.quantity_delta * $this.source_price * $this.source_exchange_rate + $this.source_quantity * $this.price_delta * $this.source_exchange_rate + $this.source_quantity * $this.source_price * $this.exchange_rate_delta, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_taxes ON issue_adjustment TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_organization ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_stock ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_source ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_basis @rebase-tree-owner purchase_issue.z_basis';
DEFINE FIELD OVERWRITE z_issue_net ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE TABLE OVERWRITE issue_return SCHEMAFULL COMMENT '@rebase-members fn::accounting::issue_change_members @rebase-validate fn::accounting::issue_change_validate';
DEFINE FIELD OVERWRITE source ON issue_return TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON issue_return TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON issue_return TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON issue_return TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE entered_amount ON issue_return TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity_delta ON issue_return TYPE decimal VALUE -$this.quantity COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice ON issue_return TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE organization ON issue_return TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.source.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON issue_return TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON issue_return TYPE datetime VALUE $this.source.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON issue_return TYPE bool VALUE $this.source.is_sale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_at ON issue_return TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_quantity ON issue_return TYPE decimal VALUE $this.source.quantity COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_price ON issue_return TYPE decimal VALUE $this.source.price COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_exchange_rate ON issue_return TYPE decimal VALUE $this.source.exchange_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_amount ON issue_return TYPE decimal VALUE $this.source.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE stock_account ON issue_return TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT VALUE $this.source.stock_account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON issue_return TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE amount_delta ON issue_return TYPE decimal VALUE -($this.entered_amount ?? fn::accounting::round($this.quantity * $this.source_price * $this.source_exchange_rate, $this.precision)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_taxes ON issue_return TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_organization ON issue_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON issue_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_stock ON issue_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_source ON issue_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_basis @rebase-tree-owner purchase_issue.z_basis';
DEFINE FIELD OVERWRITE z_issue_net ON issue_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE FUNCTION OVERWRITE fn::accounting::tax_change_validate($row: object) {
    IF $row.effective_at < $row.source_at { THROW 'TAX_CHANGE_BEFORE_SOURCE'; };
    fn::accounting::precision_validate($row.amount_delta, $row.currency);
    fn::accounting::precision_validate($row.account_delta, $row.account_currency);
    IF math::abs($row.amount_delta) > $row.source_amount OR math::abs($row.account_delta) > $row.source_account_amount { THROW 'TAX_CHANGE_MAGNITUDE'; };
    IF ($row.amount_delta < 0dec AND $row.account_delta > 0dec) OR ($row.amount_delta > 0dec AND $row.account_delta < 0dec) { THROW 'TAX_CHANGE_DIRECTION'; };
    IF record::tb($row.id) = 'tax_adjustment' { fn::accounting::phase($row.effective_at, $row.invoice_date, true); } ELSE {
        IF $row.issue != $row.adjustment_issue { THROW 'ADJUSTMENT_TAX_SOURCE'; };
        IF $row.adjustment_at <= $row.source_at OR $row.effective_at < $row.adjustment_at { THROW 'ADJUSTMENT_TAX_ORDER'; };
        fn::accounting::phase($row.effective_at, $row.invoice_date, record::tb($row.adjustment) = 'issue_adjustment');
        IF $row.basis_before + $row.basis_delta < 0dec { THROW 'ADJUSTMENT_TAX_BASIS_CAPACITY'; };
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::tax_change_members($row: object) {
    RETURN array::concat(fn::accounting::commercial_members($row, $row.amount_delta, 0dec), [
        fn::accounting::balance_member($row, 'z_tax_account', $row.tax_account, $row.effective_at, fn::accounting::claim(!$row.is_sale, $row.account_delta), false),
        fn::tree::member($row.id, 'z_source', $row.source_tax, 'z_capacity', $row.effective_at, { amount: $row.amount_delta, account_amount: $row.account_delta }, {}, {}, false),
        fn::tree::member($row.id, 'z_issue_net', $row.issue, 'z_net', $row.effective_at, { amount: $row.amount_delta }, {}, {}, false),
        IF $row.adjustment = NONE THEN NONE ELSE fn::tree::member($row.id, 'z_order', $row.source_tax, 'z_adjustments', $row.effective_at, { base: $row.basis_delta }, {}, {}, true) END,
        IF $row.adjustment = NONE THEN NONE ELSE fn::tree::member($row.id, 'z_adjustment', $row.adjustment, 'z_taxes', $row.effective_at, { amount: $row.amount_delta }, {}, {}, $row.is_net) END]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE tax_adjustment SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_change_members @rebase-validate fn::accounting::tax_change_validate';
DEFINE FIELD OVERWRITE source_tax ON tax_adjustment TYPE record<issue_tax | issue_net_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON tax_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON tax_adjustment TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE entered_account_delta ON tax_adjustment TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount_delta ON tax_adjustment TYPE decimal ASSERT $value != 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice ON tax_adjustment TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source_tax.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE organization ON tax_adjustment TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.source_tax.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON tax_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON tax_adjustment TYPE datetime VALUE $this.source_tax.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON tax_adjustment TYPE bool VALUE $this.source_tax.is_sale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_at ON tax_adjustment TYPE datetime VALUE $this.source_tax.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_amount ON tax_adjustment TYPE decimal VALUE $this.source_tax.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_account_amount ON tax_adjustment TYPE decimal VALUE $this.source_tax.account_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE issue ON tax_adjustment TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.source_tax.source COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE tax_account ON tax_adjustment TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source_tax.tax_account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_currency ON tax_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.account_currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE exchange_rate ON tax_adjustment TYPE decimal VALUE $this.source_tax.exchange_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_precision ON tax_adjustment TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_delta ON tax_adjustment TYPE decimal VALUE $this.entered_account_delta ?? fn::accounting::round($this.amount_delta * $this.exchange_rate, $this.account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_organization ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_tax_account ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';
DEFINE FIELD OVERWRITE z_source ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_tax.z_capacity @rebase-tree-owner issue_net_tax.z_capacity';
DEFINE FIELD OVERWRITE z_issue_net ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';

DEFINE TABLE OVERWRITE adjustment_tax SCHEMAFULL COMMENT '@rebase-members fn::accounting::tax_change_members @rebase-validate fn::accounting::tax_change_validate';
DEFINE FIELD OVERWRITE source_tax ON adjustment_tax TYPE record<issue_tax | issue_net_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON adjustment_tax TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON adjustment_tax TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE entered_account_delta ON adjustment_tax TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE adjustment ON adjustment_tax TYPE record<issue_adjustment | issue_return> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice ON adjustment_tax TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source_tax.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE organization ON adjustment_tax TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.source_tax.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON adjustment_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON adjustment_tax TYPE datetime VALUE $this.source_tax.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON adjustment_tax TYPE bool VALUE $this.source_tax.is_sale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_at ON adjustment_tax TYPE datetime VALUE $this.source_tax.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_amount ON adjustment_tax TYPE decimal VALUE $this.source_tax.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_account_amount ON adjustment_tax TYPE decimal VALUE $this.source_tax.account_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE issue ON adjustment_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.source_tax.source COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE tax_account ON adjustment_tax TYPE record<direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source_tax.tax_account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_currency ON adjustment_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.source_tax.account_currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE exchange_rate ON adjustment_tax TYPE decimal VALUE $this.source_tax.exchange_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE account_precision ON adjustment_tax TYPE int VALUE $this.account_currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE rate ON adjustment_tax TYPE decimal VALUE $this.source_tax.rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE lower_bound ON adjustment_tax TYPE decimal VALUE $this.source_tax.lower_bound COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE upper_bound ON adjustment_tax TYPE option<decimal> VALUE $this.source_tax.upper_bound COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE source_basis ON adjustment_tax TYPE decimal VALUE $this.source_tax.basis COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_net ON adjustment_tax TYPE bool VALUE $this.source_tax.is_net COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON adjustment_tax TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE adjustment_issue ON adjustment_tax TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT VALUE $this.adjustment.source COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE adjustment_at ON adjustment_tax TYPE datetime VALUE $this.adjustment.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE adjustment_delta ON adjustment_tax TYPE decimal VALUE $this.adjustment.amount_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE basis_delta ON adjustment_tax TYPE decimal VALUE $this.adjustment_delta + IF $this.is_net THEN fn::accounting::prefix($this.adjustment, 'z_taxes', 'amount', $this.effective_at) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE basis_before ON adjustment_tax TYPE decimal VALUE $this.source_basis + fn::accounting::prefix($this.source_tax, 'z_adjustments', 'base', $this.effective_at) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE amount_delta ON adjustment_tax TYPE decimal VALUE fn::accounting::tax_rule($this.basis_before + $this.basis_delta, $this.rate, $this.lower_bound, $this.upper_bound, $this.precision) - fn::accounting::tax_rule($this.basis_before, $this.rate, $this.lower_bound, $this.upper_bound, $this.precision) COMMENT '@rebase-derived';
DEFINE INDEX OVERWRITE adjustment_tax_pair ON adjustment_tax FIELDS tenant, adjustment, source_tax UNIQUE;
DEFINE FIELD OVERWRITE z_order ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_tax.z_adjustments @rebase-tree-owner issue_net_tax.z_adjustments';
DEFINE FIELD OVERWRITE z_adjustment ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_adjustment.z_taxes @rebase-tree-owner issue_return.z_taxes';
DEFINE FIELD OVERWRITE account_delta ON adjustment_tax TYPE decimal VALUE $this.entered_account_delta ?? fn::accounting::round($this.amount_delta * $this.exchange_rate, $this.account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_organization ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_tax_account ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';
DEFINE FIELD OVERWRITE z_source ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner issue_tax.z_capacity @rebase-tree-owner issue_net_tax.z_capacity';
DEFINE FIELD OVERWRITE z_issue_net ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';
