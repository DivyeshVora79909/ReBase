DEFINE FUNCTION OVERWRITE fn::accounting::issue_adjustment_validate($row: object) {
    IF $row.effective_at<=$row.source_at { THROW 'ADJUSTMENT_AFTER_SOURCE'; };
    IF $row.quantity_delta=0dec AND $row.price_delta=0dec { THROW 'ADJUSTMENT_EMPTY'; };
    IF math::abs($row.quantity_delta)>$row.source_quantity OR math::abs($row.price_delta)>$row.source_price OR math::abs($row.amount_delta)>$row.source_amount { THROW 'ISSUE_CHANGE_MAGNITUDE'; };
    IF $row.quantity_before+$row.quantity_delta<0dec OR $row.price_before+$row.price_delta<0dec { THROW 'ISSUE_CAPACITY'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::issue_adjustment_members($row: object) {
    LET $q=IF $row.is_sale THEN -$row.quantity_delta ELSE $row.quantity_delta END;
    RETURN array::concat(fn::accounting::commercial($row,$row.amount_delta,0dec),
        fn::accounting::post($row,'z_stock',$row.stock_account,$row.effective_at,object::extend(fn::accounting::effects($q,0dec,0dec),fn::accounting::trade($row,$row.quantity_delta,$row.amount_delta,false))),
        fn::accounting::post($row,'z_goods',$row.counterparty_stock,$row.effective_at,object::extend(fn::accounting::effects(-$q,0dec,0dec),fn::accounting::trade($row,$row.quantity_delta,$row.amount_delta,true))),[
        fn::tree::member($row.id,'z_state',$row.source,'z_state',$row.effective_at,{quantity:$row.quantity_delta,price:$row.price_delta,base:$row.amount_delta},{},{},true),
        fn::tree::member($row.id,'z_order',$row.source,'z_adjustments',$row.effective_at,{},{},{},false),
        fn::tree::member($row.id,'z_net',$row.source,'z_net',$row.effective_at,{amount:$row.amount_delta},{},{},false)]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE issue_adjustment SCHEMAFULL COMMENT '@rebase-members fn::accounting::issue_adjustment_members @rebase-validate fn::accounting::issue_adjustment_validate';

DEFINE FIELD OVERWRITE source ON issue_adjustment TYPE record<sales_issue | purchase_issue> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON issue_adjustment TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON issue_adjustment TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice ON issue_adjustment TYPE record<sales_invoice | purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.source.invoice COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency_account ON issue_adjustment TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON issue_adjustment TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON issue_adjustment TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.invoice.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON issue_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE invoice_date ON issue_adjustment TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON issue_adjustment TYPE bool VALUE $this.invoice.is_sale COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE precision ON issue_adjustment TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_counterparty ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE z_counterparty_subsidiary ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_counterparty_sub_rate ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_counterparty_organization ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_counterparty_org_rate ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_invoice ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';

DEFINE FIELD OVERWRITE adjustment_note ON issue_adjustment TYPE record<sales_adjustment_note | purchase_adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_note ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE quantity_delta ON issue_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE price_delta ON issue_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE source_quantity ON issue_adjustment TYPE decimal VALUE $this.source.quantity COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_price ON issue_adjustment TYPE decimal VALUE $this.source.price COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_amount ON issue_adjustment TYPE decimal VALUE $this.source.amount COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON issue_adjustment TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE stock_account ON issue_adjustment TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT VALUE $this.source.stock_account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE counterparty_stock ON issue_adjustment TYPE record<organization_resource_account> REFERENCE ON DELETE REJECT VALUE $this.source.counterparty_stock COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE quantity_before ON issue_adjustment TYPE decimal VALUE fn::accounting::prefix($this.source,'z_state','quantity',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE price_before ON issue_adjustment TYPE decimal VALUE fn::accounting::prefix($this.source,'z_state','price',$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE amount_delta ON issue_adjustment TYPE decimal VALUE fn::accounting::round(($this.quantity_before+$this.quantity_delta)*($this.price_before+$this.price_delta),$this.precision)-fn::accounting::round($this.quantity_before*$this.price_before,$this.precision) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_taxes ON issue_adjustment TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_stock ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';

DEFINE FIELD OVERWRITE z_stock_subsidiary ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_stock_sub_rate ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_goods ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_resource_account.z_history';

DEFINE FIELD OVERWRITE z_goods_subsidiary ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_goods_sub_rate ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_goods_organization ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_goods_org_rate ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_state ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_state @rebase-tree-owner purchase_issue.z_state';

DEFINE FIELD OVERWRITE z_order ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_adjustments @rebase-tree-owner purchase_issue.z_adjustments';

DEFINE FIELD OVERWRITE z_net ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net @rebase-tree-owner purchase_issue.z_net';
