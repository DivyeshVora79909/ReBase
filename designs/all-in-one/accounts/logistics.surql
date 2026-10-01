DEFINE FUNCTION OVERWRITE fn::delivery::base($id: record<delivery>, $from: record<stock_account>, $to: record<stock_account>,
    $quantity: decimal, $amount: decimal, $currency: record<currency>, $at: datetime, $invoice: option<record<invoice>>, $v: option<object>) {
    IF $from.a_subject != $to.a_subject { THROW 'CALC_DELIVERY_SUBJECT'; };
    IF $invoice != NONE AND ($from.z10_organization != $v.issuer.a_entity OR $to.z10_organization != $v.recipient.a_entity) { THROW 'CALC_INVOICE_DELIVERY_PARTIES'; };
    IF $invoice != NONE AND $currency != $v.currency { THROW 'CALC_INVOICE_CURRENCY'; };
    RETURN { from: $from, to: $to, subject: $from.a_subject,
        from_unit: IF record::tb($from.a_endpoint) = 'operating_unit' THEN $from.a_endpoint ELSE NONE END,
        to_unit: IF record::tb($to.a_endpoint) = 'operating_unit' THEN $to.a_endpoint ELSE NONE END,
        quantity: $quantity, amount: $amount, currency: $currency, origin: $id, origin_at: $at,
        invoice: $invoice, invoice_at: $v.issued_at, issuer: $v.issuer, recipient: $v.recipient,
        tax_account: NONE, tax_party: NONE, tax_kind: '', capacity: NONE, capacity_at: NONE, capacity_amount: 0dec };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::delivery::amend($base: object, $quantity: decimal, $amount: decimal) {
    RETURN object::extend($base, { quantity: $quantity, amount: $amount,
        capacity_amount: IF $base.capacity = NONE THEN 0dec ELSE $amount END });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::delivery::charge($base: object, $amount: decimal, $id: record, $at: datetime, $tax: record<money_account>) {
    LET $target = fn::tax::target($tax, $base.currency);
    LET $party = IF $target.kind = 'payable' THEN $base.from.z10_organization ELSE $base.to.z10_organization END;
    IF $target.party.a_entity != $party { THROW 'CALC_TAX_CLAIM_PARTY'; };
    RETURN object::extend(fn::delivery::amend($base, 0dec, $amount), {
        tax_account: $tax, tax_party: $target.party, tax_kind: $target.kind,
        capacity: $id, capacity_at: $at, capacity_amount: $amount });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::delivery::members($row: object) {
    LET $c = $row.z20_ctx;
    LET $stock = $c.quantity != 0dec;
    LET $type = record::tb($row.id);
    LET $line = $type IN ['delivery', 'delivery_charge', 'delivery_parent_charge'];
    -- A claim exists no earlier than issue, even when its source fact is earlier.
    LET $recognized = IF $c.invoice_at != NONE AND $c.invoice_at > $row.a_effective_at THEN $c.invoice_at ELSE $row.a_effective_at END;
    RETURN [
        fn::tree::member($row.id, 'z_from', IF $stock THEN $c.from ELSE NONE END, 'z_book', $row.a_effective_at,
            { quantity: -$c.quantity }, { subject: $c.subject }, {}, false),
        fn::tree::member($row.id, 'z_to', IF $stock THEN $c.to ELSE NONE END, 'z_book', $row.a_effective_at,
            { quantity: $c.quantity }, { subject: $c.subject }, {}, false),
        fn::tree::member($row.id, 'z_from_unit', IF $stock THEN $c.from_unit ELSE NONE END, 'z_activity', $row.a_effective_at,
            IF $c.quantity > 0dec THEN { outbound: 1dec } ELSE { inbound: 1dec } END, {}, {}, false),
        fn::tree::member($row.id, 'z_to_unit', IF $stock THEN $c.to_unit ELSE NONE END, 'z_activity', $row.a_effective_at,
            IF $c.quantity > 0dec THEN { inbound: 1dec } ELSE { outbound: 1dec } END, {}, {}, false),
        fn::tree::member($row.id, 'z_original', $c.origin, 'z_history', $row.a_effective_at,
            { quantity: $c.quantity, amount: $c.amount }, { subject: $c.subject, currency: $c.currency }, {}, $type = 'delivery_charge'),
        fn::tree::member($row.id, 'z_invoice', $c.invoice, 'z_book', $row.a_effective_at,
            { amount: $c.amount, billed: $c.amount }, { currency: $c.currency, issuer: $c.issuer, recipient: $c.recipient },
            IF $line THEN { line: $row.a_effective_at } ELSE { amendment: $row.a_effective_at } END, false),
        fn::tree::member($row.id, 'z_issuer', $c.issuer, 'z_book', $recognized,
            { receivable: $c.amount, billed_out: $c.amount }, { currency: $c.currency }, {}, false),
        fn::tree::member($row.id, 'z_recipient', $c.recipient, 'z_book', $recognized,
            { payable: $c.amount, billed_in: $c.amount }, { currency: $c.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax', $c.tax_account, 'z_book', $recognized,
            object::from_entries([[$c.tax_kind, $c.amount]]), { currency: $c.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax_party', $c.tax_party, 'z_book', $recognized,
            object::from_entries([[$c.tax_kind, $c.amount]]), { currency: $c.currency }, {}, false),
        fn::tree::member($row.id, 'z_capacity', $c.capacity, 'z_history', $row.a_effective_at,
            { amount: $c.capacity_amount }, { currency: $c.currency }, {}, false),
        fn::calc::note($row, $c.amount, $c.currency, $c.invoice)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::delivery::validate($row: object) {
    LET $c = $row.z20_ctx;
    IF $row.a_effective_at < $c.origin_at OR ($c.capacity_at != NONE AND $row.a_effective_at < $c.capacity_at) { THROW 'CALC_CHILD_BEFORE_ORIGINAL'; };
    IF $row.z_history != NONE { fn::calc::history($row); };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE delivery SCHEMAFULL COMMENT '@rebase-members fn::delivery::members @rebase-validate fn::delivery::validate';
DEFINE FIELD OVERWRITE a_effective_at ON delivery TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON delivery TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_from ON delivery TYPE record<stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON delivery TYPE record<stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_quantity ON delivery TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_value ON delivery TYPE decimal ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_currency ON delivery TYPE record<currency> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_invoice ON delivery TYPE option<record<invoice>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON delivery TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON delivery TYPE { from: record<stock_account>, to: record<stock_account>, subject: record<item | service>, from_unit: option<record<operating_unit>>, to_unit: option<record<operating_unit>>, quantity: decimal, amount: decimal, currency: record<currency>, origin: record<delivery>, origin_at: datetime, invoice: option<record<invoice>>, invoice_at: option<datetime>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, tax_account: option<record<money_account>>, tax_party: option<record<money_account>>, tax_kind: string, capacity: option<record<delivery_charge | delivery_parent_charge>>, capacity_at: option<datetime>, capacity_amount: decimal } VALUE fn::delivery::base($this.id, $this.a_from, $this.a_to, $this.a_quantity, $this.a_value, $this.a_currency, $this.a_effective_at, $this.a_invoice, $this.a_invoice.z20_ctx) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_book';
DEFINE FIELD OVERWRITE z_to ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_book';
DEFINE FIELD OVERWRITE z_from_unit ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';
DEFINE FIELD OVERWRITE z_to_unit ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';
DEFINE FIELD OVERWRITE z_original ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery.z_history';
DEFINE FIELD OVERWRITE z_invoice ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';

DEFINE TABLE OVERWRITE delivery_adjustment SCHEMAFULL COMMENT '@rebase-members fn::delivery::members @rebase-validate fn::delivery::validate';
DEFINE FIELD OVERWRITE a_effective_at ON delivery_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON delivery_adjustment TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON delivery_adjustment TYPE record<delivery> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_note ON delivery_adjustment TYPE record<adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_quantity_delta ON delivery_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_value_delta ON delivery_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON delivery_adjustment TYPE { from: record<stock_account>, to: record<stock_account>, subject: record<item | service>, from_unit: option<record<operating_unit>>, to_unit: option<record<operating_unit>>, quantity: decimal, amount: decimal, currency: record<currency>, origin: record<delivery>, origin_at: datetime, invoice: option<record<invoice>>, invoice_at: option<datetime>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, tax_account: option<record<money_account>>, tax_party: option<record<money_account>>, tax_kind: string, capacity: option<record<delivery_charge | delivery_parent_charge>>, capacity_at: option<datetime>, capacity_amount: decimal } VALUE fn::delivery::amend($this.a_original.z20_ctx, $this.a_quantity_delta, $this.a_value_delta) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_book';
DEFINE FIELD OVERWRITE z_to ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_book';
DEFINE FIELD OVERWRITE z_from_unit ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';
DEFINE FIELD OVERWRITE z_to_unit ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';
DEFINE FIELD OVERWRITE z_original ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery.z_history';
DEFINE FIELD OVERWRITE z_invoice ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_note ON delivery_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner adjustment_note.z_book';

DEFINE TABLE OVERWRITE delivery_return SCHEMAFULL COMMENT '@rebase-members fn::delivery::members @rebase-validate fn::delivery::validate';
DEFINE FIELD OVERWRITE a_effective_at ON delivery_return TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON delivery_return TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON delivery_return TYPE record<delivery> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_note ON delivery_return TYPE record<adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_quantity ON delivery_return TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON delivery_return TYPE { from: record<stock_account>, to: record<stock_account>, subject: record<item | service>, from_unit: option<record<operating_unit>>, to_unit: option<record<operating_unit>>, quantity: decimal, amount: decimal, currency: record<currency>, origin: record<delivery>, origin_at: datetime, invoice: option<record<invoice>>, invoice_at: option<datetime>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, tax_account: option<record<money_account>>, tax_party: option<record<money_account>>, tax_kind: string, capacity: option<record<delivery_charge | delivery_parent_charge>>, capacity_at: option<datetime>, capacity_amount: decimal } VALUE fn::delivery::amend($this.a_original.z20_ctx, -$this.a_quantity, 0dec) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_book';
DEFINE FIELD OVERWRITE z_to ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_book';
DEFINE FIELD OVERWRITE z_from_unit ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';
DEFINE FIELD OVERWRITE z_to_unit ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';
DEFINE FIELD OVERWRITE z_original ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery.z_history';
DEFINE FIELD OVERWRITE z_invoice ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_note ON delivery_return TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner adjustment_note.z_book';

DEFINE TABLE OVERWRITE delivery_charge SCHEMAFULL COMMENT '@rebase-members fn::delivery::members @rebase-validate fn::delivery::validate';
DEFINE FIELD OVERWRITE a_effective_at ON delivery_charge TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON delivery_charge TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON delivery_charge TYPE record<delivery> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rule ON delivery_charge TYPE record<calculation_rule> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_tax_account ON delivery_charge TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_basis ON delivery_charge TYPE decimal VALUE fn::tree::before({rid:$this.a_original,slot:'z_history'}, [$this.a_effective_at,<string>$this.id,'z_original']).measures.amount.sum ?? 0dec COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_amount ON delivery_charge TYPE decimal VALUE fn::calc::rule($this.z10_basis, $this.a_rule.a_rate, $this.a_rule.a_fixed, $this.a_rule.a_cap, $this.a_original.z20_ctx.currency.a_precision) COMMENT '@rebase-derived @rebase-depends a_original.z20_ctx';
DEFINE FIELD OVERWRITE z_history ON delivery_charge TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON delivery_charge TYPE { from: record<stock_account>, to: record<stock_account>, subject: record<item | service>, from_unit: option<record<operating_unit>>, to_unit: option<record<operating_unit>>, quantity: decimal, amount: decimal, currency: record<currency>, origin: record<delivery>, origin_at: datetime, invoice: option<record<invoice>>, invoice_at: option<datetime>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, tax_account: option<record<money_account>>, tax_party: option<record<money_account>>, tax_kind: string, capacity: option<record<delivery_charge | delivery_parent_charge>>, capacity_at: option<datetime>, capacity_amount: decimal } VALUE fn::delivery::charge($this.a_original.z20_ctx, $this.z11_amount, $this.id, $this.a_effective_at, $this.a_tax_account) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_original ON delivery_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery.z_history';
DEFINE FIELD OVERWRITE z_invoice ON delivery_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON delivery_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON delivery_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_tax ON delivery_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_tax_party ON delivery_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_capacity ON delivery_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery_charge.z_history';

DEFINE TABLE OVERWRITE delivery_parent_charge SCHEMAFULL COMMENT '@rebase-members fn::delivery::members @rebase-validate fn::delivery::validate';
DEFINE FIELD OVERWRITE a_effective_at ON delivery_parent_charge TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON delivery_parent_charge TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON delivery_parent_charge TYPE record<delivery> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rule ON delivery_parent_charge TYPE record<calculation_rule> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_tax_account ON delivery_parent_charge TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_basis ON delivery_parent_charge TYPE decimal VALUE $this.a_original.z20_ctx.amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_amount ON delivery_parent_charge TYPE decimal VALUE fn::calc::rule($this.z10_basis, $this.a_rule.a_rate, $this.a_rule.a_fixed, $this.a_rule.a_cap, $this.a_original.z20_ctx.currency.a_precision) COMMENT '@rebase-derived @rebase-depends a_original.z20_ctx';
DEFINE FIELD OVERWRITE z_history ON delivery_parent_charge TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON delivery_parent_charge TYPE { from: record<stock_account>, to: record<stock_account>, subject: record<item | service>, from_unit: option<record<operating_unit>>, to_unit: option<record<operating_unit>>, quantity: decimal, amount: decimal, currency: record<currency>, origin: record<delivery>, origin_at: datetime, invoice: option<record<invoice>>, invoice_at: option<datetime>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, tax_account: option<record<money_account>>, tax_party: option<record<money_account>>, tax_kind: string, capacity: option<record<delivery_charge | delivery_parent_charge>>, capacity_at: option<datetime>, capacity_amount: decimal } VALUE fn::delivery::charge($this.a_original.z20_ctx, $this.z11_amount, $this.id, $this.a_effective_at, $this.a_tax_account) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_original ON delivery_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery.z_history';
DEFINE FIELD OVERWRITE z_invoice ON delivery_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON delivery_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON delivery_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_tax ON delivery_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_tax_party ON delivery_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_capacity ON delivery_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery_parent_charge.z_history';

DEFINE TABLE OVERWRITE delivery_charge_adjustment SCHEMAFULL COMMENT '@rebase-members fn::delivery::members @rebase-validate fn::delivery::validate';
DEFINE FIELD OVERWRITE a_effective_at ON delivery_charge_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON delivery_charge_adjustment TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_charge ON delivery_charge_adjustment TYPE record<delivery_charge | delivery_parent_charge> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_note ON delivery_charge_adjustment TYPE record<adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_delta ON delivery_charge_adjustment TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON delivery_charge_adjustment TYPE { from: record<stock_account>, to: record<stock_account>, subject: record<item | service>, from_unit: option<record<operating_unit>>, to_unit: option<record<operating_unit>>, quantity: decimal, amount: decimal, currency: record<currency>, origin: record<delivery>, origin_at: datetime, invoice: option<record<invoice>>, invoice_at: option<datetime>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, tax_account: option<record<money_account>>, tax_party: option<record<money_account>>, tax_kind: string, capacity: option<record<delivery_charge | delivery_parent_charge>>, capacity_at: option<datetime>, capacity_amount: decimal } VALUE fn::delivery::amend($this.a_charge.z20_ctx, 0dec, $this.a_delta) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_original ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery.z_history';
DEFINE FIELD OVERWRITE z_invoice ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_tax ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_tax_party ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_capacity ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner delivery_charge.z_history @rebase-tree-owner delivery_parent_charge.z_history';
DEFINE FIELD OVERWRITE z_note ON delivery_charge_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner adjustment_note.z_book';
