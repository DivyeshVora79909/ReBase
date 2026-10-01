-- Both parties are explicit organization/currency accounts. 'Our' organization is
-- an ordinary party. The document creates claims; settlement moves actual assets.
DEFINE TABLE OVERWRITE invoice SCHEMAFULL COMMENT '@rebase-validate fn::invoice::validate';
DEFINE FIELD OVERWRITE a_issuer ON invoice TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_recipient ON invoice TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON invoice TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_number ON invoice TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON invoice TYPE { issuer: record<money_account>, recipient: record<money_account>, currency: record<currency>, issued_at: datetime } VALUE { issuer: $this.a_issuer, recipient: $this.a_recipient, currency: $this.a_issuer.a_currency, issued_at: $this.a_effective_at } COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_book ON invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE invoice_number ON invoice FIELDS a_issuer, a_number UNIQUE;

DEFINE FUNCTION OVERWRITE fn::invoice::validate($row: object) {
    IF record::tb($row.a_issuer.a_entity) != 'organization' OR record::tb($row.a_recipient.a_entity) != 'organization' OR $row.a_issuer = $row.a_recipient { THROW 'CALC_INVOICE_PARTIES'; };
    IF $row.a_issuer.a_currency != $row.a_recipient.a_currency { THROW 'CALC_INVOICE_CURRENCY'; };
    LET $s = $row.z_book.summary;
    IF ($s.measures.amount.min_prefix ?? 0dec) < 0dec { THROW 'CALC_INVOICE_OVERSETTLED'; };
    IF $s.tags.currency != NONE AND (!$s.tags.currency.uniform OR $s.tags.currency.value != $row.z20_ctx.currency) { THROW 'CALC_INVOICE_CURRENCY'; };
    IF $s.tags.issuer != NONE AND (!$s.tags.issuer.uniform OR $s.tags.issuer.value != $row.a_issuer) { THROW 'CALC_INVOICE_ISSUER'; };
    IF $s.tags.recipient != NONE AND (!$s.tags.recipient.uniform OR $s.tags.recipient.value != $row.a_recipient) { THROW 'CALC_INVOICE_RECIPIENT'; };
    IF $s.spans.line != NONE AND $s.spans.line.max > $row.a_effective_at { THROW 'CALC_LINE_AFTER_INVOICE'; };
    IF $s.spans.settlement != NONE AND $s.spans.settlement.min < $row.a_effective_at { THROW 'CALC_SETTLEMENT_BEFORE_INVOICE'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::tax::target($account: record<money_account>, $currency: record<currency>) {
    LET $type = record::tb($account.a_entity);
    IF !($type IN ['tax_receivable', 'tax_payable']) { THROW 'CALC_TAX_CLAIM_KIND'; };
    IF $account.a_currency != $currency { THROW 'CALC_TAX_CLAIM_CURRENCY'; };
    RETURN { account: $account, party: $account.z10_party, kind: IF $type = 'tax_receivable' THEN 'receivable' ELSE 'payable' END };
} PERMISSIONS FULL;

-- Standalone assessments use the same claim dimensions as invoice-derived ones.
-- They never create cash or invent regional tax eligibility/ordering rules.
DEFINE FUNCTION OVERWRITE fn::tax::base($id: record<tax_assessment>, $account: record<money_account>, $amount: decimal, $at: datetime) {
    LET $target = fn::tax::target($account, $account.a_currency);
    RETURN { origin: $id, origin_at: $at, account: $account, party: $target.party, kind: $target.kind, currency: $account.a_currency, amount: $amount };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::tax::members($row: object) {
    LET $c = $row.z20_ctx;
    RETURN [
        fn::tree::member($row.id, 'z_claim', $c.account, 'z_book', $row.a_effective_at,
            object::from_entries([[$c.kind, $c.amount]]), { currency: $c.currency }, {}, false),
        fn::tree::member($row.id, 'z_party', $c.party, 'z_book', $row.a_effective_at,
            object::from_entries([[$c.kind, $c.amount]]), { currency: $c.currency }, {}, false),
        fn::tree::member($row.id, 'z_original', $c.origin, 'z_history', $row.a_effective_at,
            { amount: $c.amount }, { currency: $c.currency }, {}, false),
        fn::calc::note($row, $c.amount, $c.currency, NONE)
    ];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::tax::validate($row: object) {
    IF $row.a_effective_at < $row.z20_ctx.origin_at { THROW 'CALC_CHILD_BEFORE_ORIGINAL'; };
    IF $row.z_history != NONE { fn::calc::history($row); };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE tax_assessment SCHEMAFULL COMMENT '@rebase-members fn::tax::members @rebase-validate fn::tax::validate';
DEFINE FIELD OVERWRITE a_tax_account ON tax_assessment TYPE record<money_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON tax_assessment TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON tax_assessment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON tax_assessment TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON tax_assessment TYPE { origin: record<tax_assessment>, origin_at: datetime, account: record<money_account>, party: record<money_account>, kind: string, currency: record<currency>, amount: decimal } VALUE fn::tax::base($this.id, $this.a_tax_account, $this.a_amount, $this.a_effective_at) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_history ON tax_assessment TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_claim ON tax_assessment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_party ON tax_assessment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON tax_assessment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tax_assessment.z_history';
DEFINE FIELD OVERWRITE z_note ON tax_assessment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner adjustment_note.z_book';

DEFINE TABLE OVERWRITE tax_adjustment SCHEMAFULL COMMENT '@rebase-members fn::tax::members @rebase-validate fn::tax::validate';
DEFINE FIELD OVERWRITE a_original ON tax_adjustment TYPE record<tax_assessment> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_note ON tax_adjustment TYPE record<adjustment_note> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_delta ON tax_adjustment TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON tax_adjustment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON tax_adjustment TYPE string DEFAULT '' COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON tax_adjustment TYPE { origin: record<tax_assessment>, origin_at: datetime, account: record<money_account>, party: record<money_account>, kind: string, currency: record<currency>, amount: decimal } VALUE object::extend($this.a_original.z20_ctx, { amount: $this.a_delta }) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_claim ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_party ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner money_account.z_book';
DEFINE FIELD OVERWRITE z_original ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tax_assessment.z_history';
DEFINE FIELD OVERWRITE z_note ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner adjustment_note.z_book';
