-- Quantity/value pairs are additive; average price is a read-time division.
DEFINE FUNCTION OVERWRITE fn::accounting::trade($row: object, $quantity: decimal, $amount: decimal, $organization: bool) {
    LET $a=SELECT * FROM ONLY $row.currency_account;
    LET $currency=IF $organization THEN $a.organization_currency ELSE $a.reporting_currency END;
    LET $query=IF $organization THEN $row.q_counterparty_organization ELSE $row.q_counterparty_reporting END;
    LET $value=fn::accounting::round($amount*(fn::dependency::value($query)??1dec),$currency.precision);
    RETURN {sales_quantity:IF $row.is_sale THEN $quantity ELSE 0dec END,purchase_quantity:IF $row.is_sale THEN 0dec ELSE $quantity END,
        sales_reporting_value:IF $row.is_sale THEN $value ELSE 0dec END,purchase_reporting_value:IF $row.is_sale THEN 0dec ELSE $value END};
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::issue_validate($row: object) {
    IF $row.effective_at>$row.invoice_date { THROW 'ORIGINAL_ON_OR_BEFORE_INVOICE'; };
    fn::accounting::same_subsidiary($row.stock_account,$row.currency_account);
    IF $row.counterparty_stock.organization!=$row.organization OR $row.counterparty_stock.resource!=$row.stock_account.resource { THROW 'ISSUE_RESOURCE_ACCOUNT'; };
    IF ($row.z_state.summary.measures.quantity.instant_min??0dec)<0dec OR ($row.z_state.summary.measures.price.instant_min??0dec)<0dec OR ($row.z_state.summary.measures.base.instant_min??0dec)<0dec { THROW 'ISSUE_CAPACITY'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::issue_members($row: object) {
    LET $q=IF $row.is_sale THEN -$row.quantity ELSE $row.quantity END;
    RETURN array::concat(fn::accounting::commercial($row,$row.amount,0dec),
        fn::accounting::post($row,'z_stock',$row.stock_account,$row.effective_at,object::extend(fn::accounting::effects($q,0dec,0dec),fn::accounting::trade($row,$row.quantity,$row.amount,false)), $row.q_stock_reporting, $row.q_stock_organization),
        fn::accounting::post($row,'z_goods',$row.counterparty_stock,$row.effective_at,object::extend(fn::accounting::effects(-$q,0dec,0dec),fn::accounting::trade($row,$row.quantity,$row.amount,true)), $row.q_goods_reporting, $row.q_goods_organization),[
        fn::tree::member($row.id,'z_self',$row.id,'z_state',$row.effective_at,{quantity:$row.quantity,price:$row.price,base:$row.amount},{},{}),
        fn::tree::member($row.id,'z_net_self',$row.id,'z_net',$row.effective_at,{amount:$row.amount},{},{})]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE sales_issue SCHEMAFULL COMMENT '@rebase-members fn::accounting::issue_members @rebase-validate fn::accounting::issue_validate';

DEFINE FIELD OVERWRITE invoice ON sales_issue TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE stock_account ON sales_issue TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE counterparty_stock ON sales_issue TYPE record<organization_resource_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE quantity ON sales_issue TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE price ON sales_issue TYPE decimal ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON sales_issue TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON sales_issue TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency_account ON sales_issue TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON sales_issue TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON sales_issue TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON sales_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON sales_issue TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON sales_issue TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON sales_issue TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE q_counterparty_reporting ON sales_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.currency_account.valuation_pair,$this.currency_account.resource,$this.currency_account.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE q_counterparty_organization ON sales_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::organization_query($this.currency_account,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_organization ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_invoice ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE amount ON sales_issue TYPE decimal VALUE fn::accounting::round($this.quantity*$this.price,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_state ON sales_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_net ON sales_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_adjustments ON sales_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FIELD OVERWRITE z_stock ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';

DEFINE FIELD OVERWRITE q_stock_reporting ON sales_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.stock_account.valuation_pair,$this.stock_account.resource,$this.stock_account.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_stock_subsidiary ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_goods ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_resource_account.z_history';

DEFINE FIELD OVERWRITE q_goods_reporting ON sales_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.counterparty_stock.valuation_pair,$this.counterparty_stock.resource,$this.counterparty_stock.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE q_goods_organization ON sales_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::organization_query($this.counterparty_stock,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_goods_subsidiary ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_goods_organization ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_self ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_state';

DEFINE FIELD OVERWRITE z_net_self ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net';

DEFINE TABLE OVERWRITE purchase_issue SCHEMAFULL COMMENT '@rebase-members fn::accounting::issue_members @rebase-validate fn::accounting::issue_validate';

DEFINE FIELD OVERWRITE invoice ON purchase_issue TYPE record<purchase_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE stock_account ON purchase_issue TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE counterparty_stock ON purchase_issue TYPE record<organization_resource_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE quantity ON purchase_issue TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE price ON purchase_issue TYPE decimal ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON purchase_issue TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON purchase_issue TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency_account ON purchase_issue TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON purchase_issue TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON purchase_issue TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON purchase_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON purchase_issue TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON purchase_issue TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON purchase_issue TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE q_counterparty_reporting ON purchase_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.currency_account.valuation_pair,$this.currency_account.resource,$this.currency_account.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE q_counterparty_organization ON purchase_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::organization_query($this.currency_account,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_organization ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_invoice ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE amount ON purchase_issue TYPE decimal VALUE fn::accounting::round($this.quantity*$this.price,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_state ON purchase_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_net ON purchase_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_adjustments ON purchase_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FIELD OVERWRITE z_stock ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';

DEFINE FIELD OVERWRITE q_stock_reporting ON purchase_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.stock_account.valuation_pair,$this.stock_account.resource,$this.stock_account.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_stock_subsidiary ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_goods ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_resource_account.z_history';

DEFINE FIELD OVERWRITE q_goods_reporting ON purchase_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.counterparty_stock.valuation_pair,$this.counterparty_stock.resource,$this.counterparty_stock.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE q_goods_organization ON purchase_issue TYPE option<object> FLEXIBLE
VALUE fn::accounting::organization_query($this.counterparty_stock,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_goods_subsidiary ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_goods_organization ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_self ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_issue.z_state';

DEFINE FIELD OVERWRITE z_net_self ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_issue.z_net';
