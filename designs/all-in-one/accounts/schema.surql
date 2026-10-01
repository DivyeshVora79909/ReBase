-- Entities are identities; a dimension account owns state in one currency/resource.
DEFINE TABLE OVERWRITE organization SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON organization TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_code ON organization TYPE option<string> COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE organization_code ON organization FIELDS a_code UNIQUE;

DEFINE TABLE OVERWRITE currency SCHEMAFULL;
DEFINE FIELD OVERWRITE a_code ON currency TYPE string READONLY ASSERT string::matches($value, /^[A-Z0-9][A-Z0-9._-]{0,15}$/);
DEFINE FIELD OVERWRITE a_name ON currency TYPE string;
DEFINE FIELD OVERWRITE a_precision ON currency TYPE int DEFAULT 2 READONLY ASSERT $value >= 0 AND $value <= 18;
DEFINE INDEX OVERWRITE currency_code ON currency FIELDS a_code UNIQUE;

DEFINE TABLE OVERWRITE treasury_account SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON treasury_account TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_organization ON treasury_account TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE TABLE OVERWRITE misc_account SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON misc_account TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_organization ON misc_account TYPE option<record<organization>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

-- Direct-tax allocations hold assets; indirect assessments hold claims.
-- Rates, jurisdictions, eligibility and application order are client policy.
DEFINE TABLE OVERWRITE tax_asset SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON tax_asset TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_organization ON tax_asset TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE TABLE OVERWRITE tax_receivable SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON tax_receivable TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_organization ON tax_receivable TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE TABLE OVERWRITE tax_payable SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON tax_payable TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_organization ON tax_payable TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE money_account SCHEMAFULL COMMENT '@rebase-validate fn::calc::money_owner';
DEFINE FIELD OVERWRITE a_entity ON money_account TYPE record<organization | treasury_account | misc_account | tax_asset | tax_receivable | tax_payable> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_currency ON money_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_nonnegative ON money_account TYPE bool DEFAULT true COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_party ON money_account TYPE option<record<money_account>> REFERENCE ON DELETE REJECT VALUE fn::calc::party($this.a_entity, $this.a_currency) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_book ON money_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE money_account_dimension ON money_account FIELDS a_entity, a_currency UNIQUE;

-- Resolve once through the native unique dimension index. Dimensions are immutable;
-- the stored tracked reference protects deletion and supplies direct ancestor access.
DEFINE FUNCTION OVERWRITE fn::calc::party($entity: record, $currency: record<currency>) {
    IF record::tb($entity) = 'organization' OR $entity.a_organization = NONE { RETURN NONE; };
    LET $party = (SELECT VALUE id FROM money_account WHERE a_entity = $entity.a_organization AND a_currency = $currency LIMIT 1)[0];
    IF $party = NONE { THROW 'CALC_ORGANIZATION_CURRENCY_ACCOUNT_REQUIRED'; };
    RETURN $party;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::calc::money_owner($row: object) {
    LET $s = $row.z_book.summary;
    IF $row.a_nonnegative AND ($s.measures.asset.min_prefix ?? 0dec) < 0dec { THROW 'CALC_NEGATIVE_ASSET_HISTORY'; };
    IF ($s.measures.receivable.min_prefix ?? 0dec) < 0dec OR ($s.measures.payable.min_prefix ?? 0dec) < 0dec { THROW 'CALC_NEGATIVE_CLAIM_HISTORY'; };
    IF record::tb($row.a_entity) IN ['tax_receivable', 'tax_payable'] AND
        (($s.measures.asset.min ?? 0dec) != 0dec OR ($s.measures.asset.max ?? 0dec) != 0dec) { THROW 'CALC_CLAIM_IS_NOT_CASH'; };
    IF $s.tags.currency != NONE AND (!$s.tags.currency.uniform OR $s.tags.currency.value != $row.a_currency) { THROW 'CALC_CURRENCY_MISMATCH'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE currency_exchange SCHEMAFULL COMMENT '@rebase-validate fn::calc::exchange_owner';
DEFINE FIELD OVERWRITE a_from ON currency_exchange TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_to ON currency_exchange TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rate ON currency_exchange TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON currency_exchange TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_usage ON currency_exchange TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FUNCTION OVERWRITE fn::calc::exchange_owner($row: object) {
    IF $row.z_usage.summary.count > 0 AND $row.z_usage.summary.first[0] < $row.a_effective_at { THROW 'CALC_EXCHANGE_AFTER_USAGE'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::calc::convert($amount: decimal, $from: record<currency>, $to: record<currency>, $exchange: option<record<currency_exchange>>) {
    IF $exchange = NONE AND $from != $to { THROW 'CALC_EXCHANGE_REQUIRED'; };
    IF $exchange != NONE AND ($exchange.a_from != $from OR $exchange.a_to != $to) { THROW 'CALC_EXCHANGE_DIMENSIONS'; };
    RETURN <decimal>math::fixed($amount * ($exchange.a_rate ?? 1dec), $to.a_precision);
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE operating_unit SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON operating_unit TYPE string;
DEFINE FIELD OVERWRITE a_organization ON operating_unit TYPE record<organization> REFERENCE ON DELETE REJECT READONLY;
-- Activity is unitless: heterogeneous item quantities/currencies are never summed here.
DEFINE FIELD OVERWRITE z_activity ON operating_unit TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE TABLE OVERWRITE misc_inventory_node SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON misc_inventory_node TYPE string;
DEFINE TABLE OVERWRITE item SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON item TYPE string;
DEFINE FIELD OVERWRITE a_unit ON item TYPE string DEFAULT 'unit' READONLY;
DEFINE FIELD OVERWRITE a_sku ON item TYPE option<string>;
DEFINE INDEX OVERWRITE item_sku ON item FIELDS a_sku UNIQUE;
DEFINE TABLE OVERWRITE service SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON service TYPE string;
DEFINE FIELD OVERWRITE a_unit ON service TYPE string DEFAULT 'unit' READONLY;

-- Items and services share capacity algebra. Ordinary deliveries grant/consume it.
DEFINE TABLE OVERWRITE stock_account SCHEMAFULL COMMENT '@rebase-validate fn::calc::stock_owner';
DEFINE FIELD OVERWRITE a_endpoint ON stock_account TYPE record<operating_unit | organization | misc_inventory_node> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_subject ON stock_account TYPE record<item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_nonnegative ON stock_account TYPE bool DEFAULT true COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z10_organization ON stock_account TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE fn::calc::stock_party($this.a_endpoint) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_book ON stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE stock_account_dimension ON stock_account FIELDS a_endpoint, a_subject UNIQUE;
DEFINE FUNCTION OVERWRITE fn::calc::stock_party($endpoint: record) {
    RETURN IF record::tb($endpoint) = 'organization' THEN $endpoint ELSE $endpoint.a_organization END;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::calc::stock_owner($row: object) {
    IF $row.a_nonnegative AND ($row.z_book.summary.measures.quantity.min_prefix ?? 0dec) < 0dec { THROW 'CALC_NEGATIVE_STOCK_HISTORY'; };
    IF $row.z_book.summary.tags.subject != NONE AND (!$row.z_book.summary.tags.subject.uniform OR $row.z_book.summary.tags.subject.value != $row.a_subject) { THROW 'CALC_SUBJECT_MISMATCH'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::calc::history($row: object) {
    LET $s = $row.z_history.summary;
    IF $s.count > 0 AND $s.first[0] < $row.a_effective_at { THROW 'CALC_CHILD_BEFORE_ORIGINAL'; };
    IF object::values($s.measures).any(|$m| $m.min_prefix < 0dec) { THROW 'CALC_HISTORY_CAPACITY'; };
    IF object::values($s.tags).any(|$t| !$t.uniform) { THROW 'CALC_HISTORY_DIMENSIONS'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE adjustment_note SCHEMAFULL COMMENT '@rebase-validate fn::calc::note_owner';
DEFINE FIELD OVERWRITE a_effective_at ON adjustment_note TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_reason ON adjustment_note TYPE string ASSERT string::len(string::trim($value)) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_number ON adjustment_note TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_currency ON adjustment_note TYPE record<currency> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_invoice ON adjustment_note TYPE option<record<invoice>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_book ON adjustment_note TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FUNCTION OVERWRITE fn::calc::note_owner($row: object) {
    LET $s = $row.z_book.summary;
    IF $s.count > 0 AND $s.last[0] > $row.a_effective_at { THROW 'CALC_CORRECTION_AFTER_NOTE'; };
    IF $s.tags.currency != NONE AND (!$s.tags.currency.uniform OR $s.tags.currency.value != $row.a_currency) { THROW 'CALC_NOTE_CURRENCY'; };
    IF $row.a_invoice != NONE AND $s.count > 0 AND
        ($s.tags.invoice = NONE OR !$s.tags.invoice.uniform OR $row.a_invoice != $s.tags.invoice.value) { THROW 'CALC_NOTE_INVOICE'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::calc::note($row: object, $amount: decimal, $currency: record<currency>, $invoice: option<record<invoice>>) {
    -- Missing tags do not affect uniformity. Preserve absence explicitly so a
    -- scoped note checks every correction, including corrections without an invoice.
    RETURN fn::tree::member($row.id, 'z_note', $row.a_note, 'z_book', $row.a_effective_at,
        { amount: $amount }, { currency: $currency, invoice: $invoice ?? false }, {}, false);
} PERMISSIONS NONE;

-- Trusted native rule family: fixed + rate*basis, optional cap, explicit rounding.
DEFINE TABLE OVERWRITE calculation_rule SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON calculation_rule TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_rate ON calculation_rule TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_fixed ON calculation_rule TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_cap ON calculation_rule TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FUNCTION OVERWRITE fn::calc::rule($basis: decimal, $rate: decimal, $fixed: decimal, $cap: option<decimal>, $precision: int) {
    LET $amount = $fixed + $basis * $rate;
    LET $bounded = IF $cap = NONE THEN $amount ELSE math::min([$amount, $cap]) END;
    RETURN <decimal>math::fixed($bounded, $precision);
} PERMISSIONS FULL;
