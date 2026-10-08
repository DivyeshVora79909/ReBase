-- Native decimal algebra. Each account declares its own unit and guards.

DEFINE FUNCTION OVERWRITE fn::accounting::round($amount: decimal, $precision: int) {
    RETURN IF $precision = 0 THEN <decimal>math::fixed($amount / 10dec, 1) * 10dec ELSE <decimal>math::fixed($amount, $precision) END;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::effects($real: decimal, $receivable: decimal, $payable: decimal) {
    RETURN { real: $real, receivable: $receivable, payable: $payable, net: $receivable - $payable, available: $real - $payable };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::claim($sale: bool, $amount: decimal) {
    RETURN fn::accounting::effects(0dec, IF $sale THEN $amount ELSE 0dec END, IF $sale THEN 0dec ELSE $amount END);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::rate_validate($from: record, $to: record, $rate: decimal) {
    IF $rate <= 0dec OR ($from = $to AND $rate != 1dec) { THROW 'ACCOUNTING_EXCHANGE_RATE'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::precision_validate($amount: decimal, $currency: record) {
    IF fn::accounting::round($amount, $currency.precision) != $amount { THROW 'ACCOUNTING_AMOUNT_PRECISION'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::balance_member($row: object, $slot: string, $account: record, $at: datetime, $effects: object, $dependent: bool) {
    RETURN fn::tree::member($row.id, $slot, $account, 'z_history', $at, $effects,
        { currency: $account.currency, resource: $account.resource }, {}, $dependent);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::invoice_member($row: object, $amount: decimal, $paid: decimal) {
    RETURN fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_history', $row.effective_at,
        object::extend(fn::accounting::claim($row.is_sale, $amount - $paid),
            { amount: $amount, paid: $paid, balance: $amount - $paid }),
        { organization: $row.organization, currency: $row.currency }, {}, false);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::commercial_members($row: object, $amount: decimal, $paid: decimal) {
    RETURN [fn::accounting::balance_member($row, 'z_organization', $row.organization, $row.effective_at,
        fn::accounting::claim($row.is_sale, $amount - $paid), false),
        fn::accounting::invoice_member($row, $amount, $paid),
        fn::accounting::adjustment_note_member($row, $amount, $paid)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::prefix($owner: record, $root: string, $measure: string, $at: datetime) {
    RETURN fn::tree::read($owner, $root, 'before', [$at]).measures[$measure].sum ?? 0dec;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::phase($at: datetime, $invoice_date: datetime, $adjustment: bool) {
    IF $adjustment AND $at <= $invoice_date { THROW 'ADJUSTMENT_AFTER_INVOICE'; };
    IF !$adjustment AND $at > $invoice_date { THROW 'ORIGINAL_ON_OR_BEFORE_INVOICE'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::resource_validate($row: object) {
    IF $row.available_from != NONE AND $row.available_until != NONE AND $row.available_until <= $row.available_from { THROW 'RESOURCE_TIME_WINDOW'; };
    IF $row.minimum_duration != NONE AND $row.maximum_duration != NONE AND $row.minimum_duration > $row.maximum_duration { THROW 'RESOURCE_DURATION_ORDER'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE currency SCHEMAFULL;
DEFINE FIELD OVERWRITE code ON currency TYPE string READONLY ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE name ON currency TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE precision ON currency TYPE int READONLY DEFAULT 2 ASSERT $value >= 0 AND $value <= 18 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_accounts ON currency TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE currency_code ON currency FIELDS tenant, code UNIQUE;

DEFINE TABLE OVERWRITE measure_unit SCHEMAFULL;
DEFINE FIELD OVERWRITE code ON measure_unit TYPE string READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE name ON measure_unit TYPE string COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE measure_unit_code ON measure_unit FIELDS tenant, code UNIQUE;

DEFINE TABLE OVERWRITE item SCHEMAFULL COMMENT '@rebase-validate fn::accounting::resource_validate';
DEFINE FIELD OVERWRITE name ON item TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON item TYPE record<measure_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE available_from ON item TYPE option<datetime> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE available_until ON item TYPE option<datetime> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_duration ON item TYPE option<duration> ASSERT $value = NONE OR $value >= 0s COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE maximum_duration ON item TYPE option<duration> ASSERT $value = NONE OR $value > 0s COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_accounts ON item TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE service SCHEMAFULL COMMENT '@rebase-validate fn::accounting::resource_validate';
DEFINE FIELD OVERWRITE name ON service TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON service TYPE record<measure_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE available_from ON service TYPE option<datetime> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE available_until ON service TYPE option<datetime> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_duration ON service TYPE option<duration> ASSERT $value = NONE OR $value >= 0s COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE maximum_duration ON service TYPE option<duration> ASSERT $value = NONE OR $value > 0s COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_accounts ON service TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE operating_unit SCHEMAFULL COMMENT '@rebase-validate fn::accounting::operating_validate';
DEFINE FIELD OVERWRITE name ON operating_unit TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE capacity ON operating_unit TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_accounts ON operating_unit TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_account_keys ON operating_unit TYPE object COMMENT '@rebase-tree-root @rebase-tree-key record,record';

DEFINE FUNCTION OVERWRITE fn::accounting::operating_validate($row: object) {
    IF ($row.z_capacity.summary.measures.used.instant_min ?? 0dec) < 0dec { THROW 'CAPACITY_NEGATIVE'; };
    IF $row.capacity != NONE AND ($row.z_capacity.summary.measures.used.instant_max ?? 0dec) > $row.capacity { THROW 'OPERATING_CAPACITY'; };
} PERMISSIONS FULL;
