-- Optional source enrollment, explicit units, and ratios of associative components.
DEFINE FUNCTION OVERWRITE fn::accounting::ratio($numerator: decimal, $denominator: decimal) {
    RETURN IF $denominator > 0dec THEN $numerator / $denominator ELSE NONE END;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::pair_validate($row: object) {
    IF $row.from_resource = $row.to_resource { THROW 'PAIR_IDENTICAL_DIMENSIONS'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::pair_members($row: object) {
    RETURN [fn::tree::ordered_member($row.id, 'z_identity', $row.from_resource, 'z_exchange_pairs', [$row.to_resource], {}, {})];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE exchange_pair SCHEMAFULL COMMENT '@rebase-members fn::accounting::pair_members @rebase-validate fn::accounting::pair_validate';
DEFINE FIELD OVERWRITE from_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON exchange_pair TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON exchange_pair TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_identity ON exchange_pair TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner currency.z_exchange_pairs @rebase-tree-owner item.z_exchange_pairs @rebase-tree-owner service.z_exchange_pairs @rebase-tree-no-reader';

DEFINE FUNCTION OVERWRITE fn::accounting::pair_observation($row: object, $slot: string, $pair: option<record>, $from: record, $to: record, $from_amount: decimal, $to_amount: decimal, $original: bool) {
    IF $pair = NONE { RETURN NONE; };
    IF $pair.from_resource != $from OR $pair.to_resource != $to { THROW 'PAIR_DIMENSIONS'; };
    LET $observed = $original AND $from_amount > 0dec;
    LET $trade = record::tb($row.id) IN ['sales_issue', 'purchase_issue', 'issue_return', 'issue_adjustment'];
    LET $kind = IF $trade THEN IF $row.is_sale THEN 'sales' ELSE 'purchase' END ELSE IF record::tb($row.id) = 'resource_exchange' THEN 'exchange' ELSE 'settlement' END;
    LET $measures = { from_amount: $from_amount, to_amount: $to_amount,
        observed_from: IF $observed THEN $from_amount ELSE 0dec END,
        observed_to: IF $observed THEN $to_amount ELSE 0dec END,
        observations: IF $observed THEN 1 ELSE 0 END, corrections: IF $original THEN 0 ELSE 1 END };
    LET $typed = object::extend($measures, object::from_entries([[$kind + '_from', $from_amount], [$kind + '_to', $to_amount]]));
    RETURN fn::tree::member($row.id, $slot, $pair, 'z_history', $row.effective_at,
        IF $observed THEN object::extend($typed, object::from_entries([['rate', $to_amount / $from_amount], [$kind + '_rate', $to_amount / $from_amount]])) ELSE $typed END,
        { from_resource: $from, to_resource: $to }, {}, false);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::trade_members($row: object) {
    LET $original = record::tb($row.id) IN ['sales_issue', 'purchase_issue'];
    LET $pairs = [fn::accounting::pair_observation($row, 'z_price_pair', $row.price_pair, $row.trade_resource, $row.currency, $row.trade_quantity, $row.trade_amount, $original),
        fn::accounting::pair_observation($row, 'z_fx_pair', $row.fx_pair, $row.trade_currency, $row.currency, $row.trade_local_value, $row.trade_amount, $original)];
    IF !$row.include_analytics { RETURN $pairs; };
    LET $q = { sales_quantity: IF $row.is_sale THEN $row.trade_quantity ELSE 0dec END,
        purchase_quantity: IF $row.is_sale THEN 0dec ELSE $row.trade_quantity END,
        gross_sales_quantity: IF $original AND $row.is_sale THEN $row.trade_quantity ELSE 0dec END,
        gross_purchase_quantity: IF $original AND !$row.is_sale THEN $row.trade_quantity ELSE 0dec END };
    LET $money = fn::accounting::trade_money($row.is_sale, $row.trade_amount, $original);
    LET $stock = object::extend($q, fn::accounting::trade_money($row.is_sale, $row.trade_local_value, $original));
    RETURN array::concat($pairs, [
        fn::tree::member($row.id, 'z_trade_stock', $row.stock_account, 'z_trade', $row.effective_at, $stock, {}, {}, false),
        fn::tree::member($row.id, 'z_trade_resource', $row.trade_resource, 'z_trade', $row.effective_at, $q, {}, {}, false),
        fn::tree::member($row.id, 'z_trade_currency', $row.currency, 'z_trade', $row.effective_at, $money, {}, {}, false),
        fn::tree::ordered_member($row.id, 'z_trade_unit_currency', $row.currency, 'z_trade_by_unit', [$row.trade_unit, $row.effective_at], $money, {}),
        fn::tree::member($row.id, 'z_trade_unit', $row.trade_unit, 'z_trade', $row.effective_at, {}, { currency: $row.currency, resource: $row.trade_resource }, {}, false),
        fn::tree::member($row.id, 'z_trade_organization', $row.organization, 'z_trade', $row.effective_at, $money, {}, {}, false)]);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::trade_money($sale: bool, $amount: decimal, $original: bool) {
    RETURN { sales_value: IF $sale THEN $amount ELSE 0dec END, purchase_value: IF $sale THEN 0dec ELSE $amount END,
        gross_sales_value: IF $original AND $sale THEN $amount ELSE 0dec END,
        gross_purchase_value: IF $original AND !$sale THEN $amount ELSE 0dec END,
        sales_lines: IF $original AND $sale THEN 1 ELSE 0 END, purchase_lines: IF $original AND !$sale THEN 1 ELSE 0 END };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::payment_analytics($row: object) {
    IF $row.include_analytics != true { RETURN []; };
    LET $m = { gross_in: IF $row.cash_amount > 0dec THEN $row.cash_amount ELSE 0dec END,
        gross_out: IF $row.cash_amount < 0dec THEN -$row.cash_amount ELSE 0dec END,
        charges: $row.fee_amount, charge_tax: $row.fee_tax_amount,
        net_cash: $row.cash_amount - $row.fee_amount - $row.fee_tax_amount };
    RETURN [fn::tree::member($row.id, 'z_payment_account', $row.fee_treasury, 'z_payments', $row.fee_at, $m, {}, {}, false),
        fn::tree::member($row.id, 'z_payment_currency', $row.fee_currency, 'z_payments', $row.fee_at, $m, {}, {}, false)];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::payment_pair($row: object) {
    RETURN [fn::accounting::pair_observation($row, 'z_fx_pair', $row.fx_pair, $row.treasury_currency, $row.currency,
        $row.pair_cash, $row.pair_amount, !(record::tb($row.id) IN ['payment_refund', 'payment_adjustment']))];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::exchange_observation($row: object) {
    RETURN [fn::accounting::pair_observation($row, 'z_exchange_pair', $row.exchange_pair, $row.from_resource, $row.to_resource, $row.from_amount, $row.to_amount, true)];
} PERMISSIONS NONE;
DEFINE FIELD OVERWRITE z_exchange_pairs ON currency TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key record';
DEFINE FIELD OVERWRITE z_exchange_pairs ON item TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key record';
DEFINE FIELD OVERWRITE z_exchange_pairs ON service TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key record';
DEFINE FIELD OVERWRITE z_trade ON currency TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_trade ON item TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_trade ON service TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_trade ON operating_unit TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_trade ON organization TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_trade ON stock_account TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_trade ON misc_stock_account TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_trade_by_unit ON currency TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key record,datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_payments ON currency TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_payments ON treasury TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_payments ON misc_currency_account TYPE object  COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE include_analytics ON sales_issue TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE price_pair ON sales_issue TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_price_pair ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON sales_issue TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_fx_pair ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE trade_resource ON sales_issue TYPE record<item | service> REFERENCE ON DELETE REJECT VALUE $this.stock_account.resource COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_currency ON sales_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.stock_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_unit ON sales_issue TYPE record<operating_unit> REFERENCE ON DELETE REJECT VALUE $this.stock_account.operating_unit COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_quantity ON sales_issue TYPE decimal VALUE $this.quantity COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_amount ON sales_issue TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_local_value ON sales_issue TYPE decimal VALUE $this.quantity * $this.price COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_trade_stock ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_trade @rebase-tree-owner misc_stock_account.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_resource ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner item.z_trade @rebase-tree-owner service.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_currency ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit_currency ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key record,datetime @rebase-tree-owner currency.z_trade_by_unit @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_organization ON sales_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_trade @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON purchase_issue TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE price_pair ON purchase_issue TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_price_pair ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON purchase_issue TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_fx_pair ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE trade_resource ON purchase_issue TYPE record<item | service> REFERENCE ON DELETE REJECT VALUE $this.stock_account.resource COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_currency ON purchase_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.stock_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_unit ON purchase_issue TYPE record<operating_unit> REFERENCE ON DELETE REJECT VALUE $this.stock_account.operating_unit COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_quantity ON purchase_issue TYPE decimal VALUE $this.quantity COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_amount ON purchase_issue TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_local_value ON purchase_issue TYPE decimal VALUE $this.quantity * $this.price COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_trade_stock ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_trade @rebase-tree-owner misc_stock_account.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_resource ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner item.z_trade @rebase-tree-owner service.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_currency ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit_currency ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key record,datetime @rebase-tree-owner currency.z_trade_by_unit @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_organization ON purchase_issue TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_trade @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON issue_adjustment TYPE bool VALUE $this.source.include_analytics COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE price_pair ON issue_adjustment TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source.price_pair COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_price_pair ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON issue_adjustment TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source.fx_pair COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE trade_resource ON issue_adjustment TYPE record<item | service> REFERENCE ON DELETE REJECT VALUE $this.stock_account.resource COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_currency ON issue_adjustment TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.stock_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_unit ON issue_adjustment TYPE record<operating_unit> REFERENCE ON DELETE REJECT VALUE $this.stock_account.operating_unit COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_quantity ON issue_adjustment TYPE decimal VALUE $this.quantity_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_amount ON issue_adjustment TYPE decimal VALUE $this.amount_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_local_value ON issue_adjustment TYPE decimal VALUE $this.quantity_delta * $this.source_price + $this.source_quantity * $this.price_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_trade_stock ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_trade @rebase-tree-owner misc_stock_account.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_resource ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner item.z_trade @rebase-tree-owner service.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_currency ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit_currency ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key record,datetime @rebase-tree-owner currency.z_trade_by_unit @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_organization ON issue_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_trade @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON issue_return TYPE bool VALUE $this.source.include_analytics COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE price_pair ON issue_return TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source.price_pair COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_price_pair ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON issue_return TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source.fx_pair COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE trade_resource ON issue_return TYPE record<item | service> REFERENCE ON DELETE REJECT VALUE $this.stock_account.resource COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_currency ON issue_return TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.stock_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_unit ON issue_return TYPE record<operating_unit> REFERENCE ON DELETE REJECT VALUE $this.stock_account.operating_unit COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_quantity ON issue_return TYPE decimal VALUE $this.quantity_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_amount ON issue_return TYPE decimal VALUE $this.amount_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE trade_local_value ON issue_return TYPE decimal VALUE $this.quantity_delta * $this.source_price COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_trade_stock ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_trade @rebase-tree-owner misc_stock_account.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_resource ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner item.z_trade @rebase-tree-owner service.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_currency ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit_currency ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key record,datetime @rebase-tree-owner currency.z_trade_by_unit @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_unit ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_trade @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_trade_organization ON issue_return TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_trade @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON invoice_settlement TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON invoice_settlement TYPE decimal VALUE IF $this.is_sale THEN $this.amount ELSE -$this.amount END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON invoice_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON invoice_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON invoice_settlement TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair_cash ON invoice_settlement TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_amount ON invoice_settlement TYPE decimal VALUE $this.invoice_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON invoice_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON payment_refund TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON payment_refund TYPE decimal VALUE IF $this.is_sale THEN $this.cash_delta ELSE -$this.cash_delta END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON payment_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON payment_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON payment_refund TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source.fx_pair COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_cash ON payment_refund TYPE decimal VALUE $this.cash_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_amount ON payment_refund TYPE decimal VALUE $this.invoice_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON payment_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON payment_adjustment TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON payment_adjustment TYPE decimal VALUE IF $this.is_sale THEN $this.cash_delta ELSE -$this.cash_delta END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON payment_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON payment_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON payment_adjustment TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT VALUE $this.source.fx_pair COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_cash ON payment_adjustment TYPE decimal VALUE $this.cash_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_amount ON payment_adjustment TYPE decimal VALUE $this.invoice_delta COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON payment_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON claim_settlement TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON claim_settlement TYPE decimal VALUE IF $this.claim_kind = 'receivable' THEN $this.amount ELSE -$this.amount END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON claim_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON claim_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON claim_settlement TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair_cash ON claim_settlement TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_amount ON claim_settlement TYPE decimal VALUE $this.account_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON claim_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON tax_settlement TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON tax_settlement TYPE decimal VALUE -$this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON tax_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON tax_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON tax_settlement TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair_cash ON tax_settlement TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_amount ON tax_settlement TYPE decimal VALUE $this.account_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON tax_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON tax_deposit TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON tax_deposit TYPE decimal VALUE -$this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON tax_deposit TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON tax_deposit TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON tax_deposit TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair_cash ON tax_deposit TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_amount ON tax_deposit TYPE decimal VALUE $this.account_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON tax_deposit TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON tax_refund TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON tax_refund TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON tax_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON tax_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE fx_pair ON tax_refund TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair_cash ON tax_refund TYPE decimal VALUE $this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE pair_amount ON tax_refund TYPE decimal VALUE $this.account_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fx_pair ON tax_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE include_analytics ON production_cost TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cash_amount ON production_cost TYPE decimal VALUE -$this.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_payment_account ON production_cost TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_payments @rebase-tree-owner misc_currency_account.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_payment_currency ON production_cost TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_payments @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE exchange_pair ON resource_exchange TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_exchange_pair ON resource_exchange TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history @rebase-tree-no-reader';
