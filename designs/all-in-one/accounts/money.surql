-- Signed endpoint projections are independent of the rule/FX calculation between them.
DEFINE FUNCTION OVERWRITE fn::money::base($id: record, $from: record<money_account>, $to: record<money_account>,
    $debit: decimal, $credit: decimal, $at: datetime, $exchange: option<record<currency_exchange>>) {
    IF record::tb($from.a_entity) IN ['tax_receivable','tax_payable'] OR record::tb($to.a_entity) IN ['tax_receivable','tax_payable'] { THROW 'CALC_CLAIM_IS_NOT_CASH'; };
    RETURN { from: $from, to: $to, from_currency: $from.a_currency, to_currency: $to.a_currency,
        from_party: IF record::tb($from.a_entity) = 'organization' THEN $from ELSE $from.z10_party END,
        to_party: IF record::tb($to.a_entity) = 'organization' THEN $to ELSE $to.z10_party END,
        origin: $id, origin_at: $at, from_amount: $debit, to_amount: $credit,
        exchange: $exchange, exchange_at: $exchange.a_effective_at,
        invoice: NONE, invoice_at: NONE, invoice_currency: NONE, issuer: NONE, recipient: NONE, invoice_leg: 0, invoice_amount: 0dec,
        claim: NONE, claim_party: NONE, claim_kind: '', claim_amount: 0dec,
        parent: NONE, parent_at: NONE, parent_kind: '', parent_from_currency: NONE, parent_to_currency: NONE };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::money::settle($c: object, $invoice: record<invoice>, $v: object) {
    IF $c.from_party.a_entity != $v.recipient.a_entity OR $c.to_party.a_entity != $v.issuer.a_entity { THROW 'CALC_SETTLEMENT_PARTIES'; };
    LET $leg = IF $c.to_currency = $v.currency THEN 2 ELSE IF $c.from_currency = $v.currency THEN 1 ELSE 0 END;
    IF $leg = 0 { THROW 'CALC_SETTLEMENT_CURRENCY'; };
    RETURN object::extend($c, { invoice: $invoice, invoice_at: $v.issued_at, invoice_currency: $v.currency,
        issuer: $v.issuer, recipient: $v.recipient, invoice_leg: $leg,
        invoice_amount: IF $leg = 1 THEN $c.from_amount ELSE $c.to_amount END });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::money::claim($c: object, $account: record<money_account>, $kind: string) {
    IF record::tb($account.a_entity) != 'tax_' + $kind { THROW 'CALC_TAX_CLAIM_KIND'; };
    IF $c.from_currency != $account.a_currency OR $c.to_currency != $account.a_currency { THROW 'CALC_TAX_CLAIM_CURRENCY'; };
    LET $party = IF $kind = 'payable' THEN $c.from_party ELSE $c.to_party END;
    IF $party != $account.z10_party { THROW 'CALC_TAX_CLAIM_PARTY'; };
    RETURN object::extend($c, { claim: $account, claim_party: $account.z10_party, claim_kind: $kind, claim_amount: -$c.from_amount });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::money::amend($c: object, $debit: decimal, $credit: decimal, $exchange: option<record<currency_exchange>>) {
    RETURN object::extend($c, { from_amount: $debit, to_amount: $credit, exchange: $exchange, exchange_at: $exchange.a_effective_at,
        invoice_amount: IF $c.invoice_leg = 1 THEN $debit ELSE IF $c.invoice_leg = 2 THEN $credit ELSE 0dec END,
        claim_amount: IF $c.claim = NONE THEN 0dec ELSE -$debit END });
} PERMISSIONS FULL;

-- Charges move assets to a real endpoint; allocations retain assets in a direct-tax
-- account. The latter consume the parent's received capacity. A linked reversal
-- restores it; an unrelated recovery transfer does not rewrite the allocation.
DEFINE FUNCTION OVERWRITE fn::money::derived($id: record, $base: object, $target: record<money_account>, $amount: decimal,
    $at: datetime, $kind: string) {
    LET $from = IF $kind = 'allocation' THEN $base.to ELSE $base.from END;
    IF $from.a_currency != $target.a_currency { THROW 'CALC_DERIVED_CURRENCY'; };
    IF $kind = 'allocation' AND (record::tb($target.a_entity) != 'tax_asset' OR $target.z10_party != $from.z10_party AND $target.z10_party != $from) { THROW 'CALC_ALLOCATION_ACCOUNT'; };
    RETURN object::extend(fn::money::base($id, $from, $target, $amount, $amount, $at, NONE), {
        parent: $base.origin, parent_at: $base.origin_at, parent_kind: $kind,
        parent_from_currency: $base.from_currency, parent_to_currency: $base.to_currency });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::money::members($row: object) {
    LET $c = $row.z20_ctx;
    LET $type = record::tb($row.id);
    RETURN [
        fn::tree::member($row.id, 'z_from', $c.from, 'z_book', $row.a_effective_at,
            { asset: -$c.from_amount, outflow: $c.from_amount }, { currency: $c.from_currency }, {}, false),
        fn::tree::member($row.id, 'z_to', $c.to, 'z_book', $row.a_effective_at,
            { asset: $c.to_amount, inflow: $c.to_amount }, { currency: $c.to_currency }, {}, false),
        fn::tree::member($row.id, 'z_from_party', IF $c.from_party = $c.from THEN NONE ELSE $c.from_party END, 'z_book', $row.a_effective_at,
            { asset: -$c.from_amount, outflow: $c.from_amount }, { currency: $c.from_currency }, {}, false),
        fn::tree::member($row.id, 'z_to_party', IF $c.to_party = $c.to THEN NONE ELSE $c.to_party END, 'z_book', $row.a_effective_at,
            { asset: $c.to_amount, inflow: $c.to_amount }, { currency: $c.to_currency }, {}, false),
        fn::tree::member($row.id, 'z_original', $c.origin, 'z_history', $row.a_effective_at,
            { from_amount: $c.from_amount, to_amount: $c.to_amount, basis: $c.from_amount }, { from_currency: $c.from_currency, to_currency: $c.to_currency }, {}, false),
        fn::tree::member($row.id, 'z_parent', $c.parent, 'z_history', $row.a_effective_at,
            IF $c.parent_kind = 'allocation' THEN { to_amount: -$c.from_amount } ELSE { basis: $c.from_amount } END,
            { from_currency: $c.parent_from_currency, to_currency: $c.parent_to_currency }, {}, $type IN ['money_charge','asset_allocation']),
        fn::tree::member($row.id, 'z_invoice', $c.invoice, 'z_book', $row.a_effective_at,
            { amount: -$c.invoice_amount, settled: $c.invoice_amount }, { currency: $c.invoice_currency, issuer: $c.issuer, recipient: $c.recipient }, { settlement: $row.a_effective_at }, false),
        fn::tree::member($row.id, 'z_issuer', $c.issuer, 'z_book', $row.a_effective_at,
            { receivable: -$c.invoice_amount, settled_in: $c.invoice_amount }, { currency: $c.invoice_currency }, {}, false),
        fn::tree::member($row.id, 'z_recipient', $c.recipient, 'z_book', $row.a_effective_at,
            { payable: -$c.invoice_amount, settled_out: $c.invoice_amount }, { currency: $c.invoice_currency }, {}, false),
        fn::tree::member($row.id, 'z_claim', $c.claim, 'z_book', $row.a_effective_at,
            object::from_entries([[$c.claim_kind, $c.claim_amount]]), { currency: $c.from_currency }, {}, false),
        fn::tree::member($row.id, 'z_claim_party', $c.claim_party, 'z_book', $row.a_effective_at,
            object::from_entries([[$c.claim_kind, $c.claim_amount]]), { currency: $c.from_currency }, {}, false),
        fn::tree::member($row.id, 'z_exchange', $c.exchange, 'z_usage', $row.a_effective_at,
            { source: $c.from_amount, target: $c.to_amount }, { from_currency: $c.from_currency, to_currency: $c.to_currency }, {}, false),
        fn::calc::note($row, $c.from_amount, $c.from_currency, $c.invoice)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::money::validate($row: object) {
    LET $c = $row.z20_ctx;
    IF $row.a_effective_at < $c.origin_at OR ($c.parent_at != NONE AND $row.a_effective_at < $c.parent_at) { THROW 'CALC_CHILD_BEFORE_ORIGINAL'; };
    IF $c.invoice_at != NONE AND $row.a_effective_at < $c.invoice_at { THROW 'CALC_SETTLEMENT_BEFORE_INVOICE'; };
    IF $c.exchange_at != NONE AND $row.a_effective_at < $c.exchange_at { THROW 'CALC_EXCHANGE_AFTER_USAGE'; };
    IF record::tb($row.id) IN ['payment','settlement'] AND $c.to_amount <= 0dec { THROW 'CALC_POSITIVE_TRANSFER'; };
    IF record::tb($row.id) = 'money_refund' AND $c.to_amount > 0dec { THROW 'CALC_REFUND_DIRECTION'; };
    IF $row.z_history != NONE { fn::calc::history($row); };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE payment SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON payment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON payment TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_from ON payment TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON payment TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON payment TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_exchange ON payment TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_credit ON payment TYPE decimal VALUE fn::calc::convert($this.a_amount, $this.a_from.a_currency, $this.a_to.a_currency, $this.a_exchange) COMMENT '@rebase-derived @rebase-depends a_exchange.a_rate';
DEFINE FIELD OVERWRITE z_history ON payment TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON payment TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::base($this.id, $this.a_from, $this.a_to, $this.a_amount, $this.z10_credit, $this.a_effective_at, $this.a_exchange) COMMENT '@rebase-derived @rebase-depends a_exchange.a_effective_at';
DEFINE FIELD OVERWRITE z_from ON payment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON payment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON payment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON payment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON payment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history';
DEFINE FIELD OVERWRITE z_exchange ON payment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency_exchange.z_usage';

DEFINE TABLE OVERWRITE settlement SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON settlement TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON settlement TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_from ON settlement TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON settlement TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON settlement TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_exchange ON settlement TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_credit ON settlement TYPE decimal VALUE fn::calc::convert($this.a_amount, $this.a_from.a_currency, $this.a_to.a_currency, $this.a_exchange) COMMENT '@rebase-derived @rebase-depends a_exchange.a_rate';
DEFINE FIELD OVERWRITE a_invoice ON settlement TYPE record<invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON settlement TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON settlement TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::settle(fn::money::base($this.id, $this.a_from, $this.a_to, $this.a_amount, $this.z10_credit, $this.a_effective_at, $this.a_exchange), $this.a_invoice, $this.a_invoice.z20_ctx) COMMENT '@rebase-derived @rebase-depends a_exchange.a_effective_at';
DEFINE FIELD OVERWRITE z_from ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner settlement.z_history';
DEFINE FIELD OVERWRITE z_invoice ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_exchange ON settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency_exchange.z_usage';

DEFINE TABLE OVERWRITE tax_remittance SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON tax_remittance TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON tax_remittance TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_from ON tax_remittance TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON tax_remittance TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON tax_remittance TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_exchange ON tax_remittance TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_credit ON tax_remittance TYPE decimal VALUE fn::calc::convert($this.a_amount, $this.a_from.a_currency, $this.a_to.a_currency, $this.a_exchange) COMMENT '@rebase-derived @rebase-depends a_exchange.a_rate';
DEFINE FIELD OVERWRITE a_tax_account ON tax_remittance TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON tax_remittance TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON tax_remittance TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::claim(fn::money::base($this.id, $this.a_from, $this.a_to, $this.a_amount, $this.z10_credit, $this.a_effective_at, $this.a_exchange), $this.a_tax_account, 'payable') COMMENT '@rebase-derived @rebase-depends a_exchange.a_effective_at';
DEFINE FIELD OVERWRITE z_from ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tax_remittance.z_history';
DEFINE FIELD OVERWRITE z_claim ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_claim_party ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_exchange ON tax_remittance TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency_exchange.z_usage';

DEFINE TABLE OVERWRITE tax_recovery SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON tax_recovery TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON tax_recovery TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_from ON tax_recovery TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON tax_recovery TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON tax_recovery TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_exchange ON tax_recovery TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_credit ON tax_recovery TYPE decimal VALUE fn::calc::convert($this.a_amount, $this.a_from.a_currency, $this.a_to.a_currency, $this.a_exchange) COMMENT '@rebase-derived @rebase-depends a_exchange.a_rate';
DEFINE FIELD OVERWRITE a_tax_account ON tax_recovery TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON tax_recovery TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON tax_recovery TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::claim(fn::money::base($this.id, $this.a_from, $this.a_to, $this.a_amount, $this.z10_credit, $this.a_effective_at, $this.a_exchange), $this.a_tax_account, 'receivable') COMMENT '@rebase-derived @rebase-depends a_exchange.a_effective_at';
DEFINE FIELD OVERWRITE z_from ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tax_recovery.z_history';
DEFINE FIELD OVERWRITE z_claim ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_claim_party ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_exchange ON tax_recovery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency_exchange.z_usage';

DEFINE TABLE OVERWRITE money_adjustment SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON money_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON money_adjustment TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON money_adjustment TYPE record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_note ON money_adjustment TYPE record<adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_exchange ON money_adjustment TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_from_delta ON money_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to_delta ON money_adjustment TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z05_exchange ON money_adjustment TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT VALUE $this.a_exchange ?? $this.a_original.z20_ctx.exchange COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z10_credit ON money_adjustment TYPE decimal VALUE fn::calc::convert($this.a_from_delta, $this.a_original.z20_ctx.from_currency, $this.a_original.z20_ctx.to_currency, $this.z05_exchange) + $this.a_to_delta COMMENT '@rebase-derived @rebase-depends z05_exchange.a_rate';
DEFINE FIELD OVERWRITE z20_ctx ON money_adjustment TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::amend($this.a_original.z20_ctx, $this.a_from_delta, $this.z10_credit, $this.z05_exchange) COMMENT '@rebase-derived @rebase-depends z05_exchange.a_effective_at';
DEFINE FIELD OVERWRITE z_from ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history @rebase-tree-owner tax_remittance.z_history @rebase-tree-owner tax_recovery.z_history @rebase-tree-owner money_charge.z_history @rebase-tree-owner money_parent_charge.z_history @rebase-tree-owner asset_allocation.z_history @rebase-tree-owner asset_parent_allocation.z_history';
DEFINE FIELD OVERWRITE z_parent ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history';
DEFINE FIELD OVERWRITE z_invoice ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_claim ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_claim_party ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_exchange ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency_exchange.z_usage';
DEFINE FIELD OVERWRITE z_note ON money_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner adjustment_note.z_book';

DEFINE TABLE OVERWRITE money_refund SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON money_refund TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON money_refund TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON money_refund TYPE record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_note ON money_refund TYPE record<adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_exchange ON money_refund TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON money_refund TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to_delta ON money_refund TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z05_exchange ON money_refund TYPE option<record<currency_exchange>> REFERENCE ON DELETE REJECT VALUE $this.a_exchange ?? $this.a_original.z20_ctx.exchange COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z10_credit ON money_refund TYPE decimal VALUE fn::calc::convert(-$this.a_amount, $this.a_original.z20_ctx.from_currency, $this.a_original.z20_ctx.to_currency, $this.z05_exchange) + $this.a_to_delta COMMENT '@rebase-derived @rebase-depends z05_exchange.a_rate';
DEFINE FIELD OVERWRITE z20_ctx ON money_refund TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::amend($this.a_original.z20_ctx, -$this.a_amount, $this.z10_credit, $this.z05_exchange) COMMENT '@rebase-derived @rebase-depends z05_exchange.a_effective_at';
DEFINE FIELD OVERWRITE z_from ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history @rebase-tree-owner tax_remittance.z_history @rebase-tree-owner tax_recovery.z_history @rebase-tree-owner money_charge.z_history @rebase-tree-owner money_parent_charge.z_history @rebase-tree-owner asset_allocation.z_history @rebase-tree-owner asset_parent_allocation.z_history';
DEFINE FIELD OVERWRITE z_parent ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history';
DEFINE FIELD OVERWRITE z_invoice ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner invoice.z_book';
DEFINE FIELD OVERWRITE z_issuer ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_recipient ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_claim ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_claim_party ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_exchange ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency_exchange.z_usage';
DEFINE FIELD OVERWRITE z_note ON money_refund TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner adjustment_note.z_book';

DEFINE TABLE OVERWRITE money_charge SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON money_charge TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON money_charge TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON money_charge TYPE record<payment | settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON money_charge TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rule ON money_charge TYPE record<calculation_rule> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_basis ON money_charge TYPE decimal VALUE fn::tree::before({rid:$this.a_original,slot:'z_history'}, [$this.a_effective_at,<string>$this.id,'z_parent']).measures.basis.sum ?? 0dec COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_amount ON money_charge TYPE decimal VALUE fn::calc::rule($this.z10_basis, $this.a_rule.a_rate, $this.a_rule.a_fixed, $this.a_rule.a_cap, $this.a_original.z20_ctx.from_currency.a_precision) COMMENT '@rebase-derived @rebase-depends a_original.z20_ctx';
DEFINE FIELD OVERWRITE z_history ON money_charge TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON money_charge TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::derived($this.id, $this.a_original.z20_ctx, $this.a_to, $this.z11_amount, $this.a_effective_at, 'charge') COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON money_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON money_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON money_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON money_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON money_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_charge.z_history';
DEFINE FIELD OVERWRITE z_parent ON money_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history';

DEFINE TABLE OVERWRITE money_parent_charge SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON money_parent_charge TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON money_parent_charge TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON money_parent_charge TYPE record<payment | settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON money_parent_charge TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rule ON money_parent_charge TYPE record<calculation_rule> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_basis ON money_parent_charge TYPE decimal VALUE $this.a_original.z20_ctx.from_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_amount ON money_parent_charge TYPE decimal VALUE fn::calc::rule($this.z10_basis, $this.a_rule.a_rate, $this.a_rule.a_fixed, $this.a_rule.a_cap, $this.a_original.z20_ctx.from_currency.a_precision) COMMENT '@rebase-derived @rebase-depends a_original.z20_ctx';
DEFINE FIELD OVERWRITE z_history ON money_parent_charge TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON money_parent_charge TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::derived($this.id, $this.a_original.z20_ctx, $this.a_to, $this.z11_amount, $this.a_effective_at, 'charge') COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON money_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON money_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON money_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON money_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON money_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_parent_charge.z_history';
DEFINE FIELD OVERWRITE z_parent ON money_parent_charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history';

DEFINE TABLE OVERWRITE asset_allocation SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON asset_allocation TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON asset_allocation TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON asset_allocation TYPE record<payment | settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON asset_allocation TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rule ON asset_allocation TYPE record<calculation_rule> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_basis ON asset_allocation TYPE decimal VALUE fn::tree::before({rid:$this.a_original,slot:'z_history'}, [$this.a_effective_at,<string>$this.id,'z_parent']).measures.to_amount.sum ?? 0dec COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_amount ON asset_allocation TYPE decimal VALUE fn::calc::rule($this.z10_basis, $this.a_rule.a_rate, $this.a_rule.a_fixed, $this.a_rule.a_cap, $this.a_original.z20_ctx.to_currency.a_precision) COMMENT '@rebase-derived @rebase-depends a_original.z20_ctx';
DEFINE FIELD OVERWRITE z_history ON asset_allocation TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON asset_allocation TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::derived($this.id, $this.a_original.z20_ctx, $this.a_to, $this.z11_amount, $this.a_effective_at, 'allocation') COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON asset_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON asset_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON asset_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON asset_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON asset_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner asset_allocation.z_history';
DEFINE FIELD OVERWRITE z_parent ON asset_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history';

DEFINE TABLE OVERWRITE asset_parent_allocation SCHEMAFULL COMMENT '@rebase-members fn::money::members @rebase-validate fn::money::validate';
DEFINE FIELD OVERWRITE a_effective_at ON asset_parent_allocation TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON asset_parent_allocation TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_original ON asset_parent_allocation TYPE record<payment | settlement> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON asset_parent_allocation TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rule ON asset_parent_allocation TYPE record<calculation_rule> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_basis ON asset_parent_allocation TYPE decimal VALUE $this.a_original.z20_ctx.to_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_amount ON asset_parent_allocation TYPE decimal VALUE fn::calc::rule($this.z10_basis, $this.a_rule.a_rate, $this.a_rule.a_fixed, $this.a_rule.a_cap, $this.a_original.z20_ctx.to_currency.a_precision) COMMENT '@rebase-derived @rebase-depends a_original.z20_ctx';
DEFINE FIELD OVERWRITE z_history ON asset_parent_allocation TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z20_ctx ON asset_parent_allocation TYPE { from: record<money_account>, to: record<money_account>, from_currency: record<currency>, to_currency: record<currency>, from_party: option<record<money_account>>, to_party: option<record<money_account>>, origin: record<payment | settlement | tax_remittance | tax_recovery | money_charge | money_parent_charge | asset_allocation | asset_parent_allocation>, origin_at: datetime, from_amount: decimal, to_amount: decimal, exchange: option<record<currency_exchange>>, exchange_at: option<datetime>, invoice: option<record<invoice>>, invoice_at: option<datetime>, invoice_currency: option<record<currency>>, issuer: option<record<money_account>>, recipient: option<record<money_account>>, invoice_leg: int, invoice_amount: decimal, claim: option<record<money_account>>, claim_party: option<record<money_account>>, claim_kind: string, claim_amount: decimal, parent: option<record<payment | settlement>>, parent_at: option<datetime>, parent_kind: string, parent_from_currency: option<record<currency>>, parent_to_currency: option<record<currency>> } VALUE fn::money::derived($this.id, $this.a_original.z20_ctx, $this.a_to, $this.z11_amount, $this.a_effective_at, 'allocation') COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON asset_parent_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to ON asset_parent_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_from_party ON asset_parent_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_to_party ON asset_parent_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON asset_parent_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner asset_parent_allocation.z_history';
DEFINE FIELD OVERWRITE z_parent ON asset_parent_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner payment.z_history @rebase-tree-owner settlement.z_history';
