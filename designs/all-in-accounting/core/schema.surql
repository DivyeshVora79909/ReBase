-- Native units, independent projections and complete-time linear measures.
DEFINE FUNCTION OVERWRITE fn::accounting::round($amount: decimal, $precision: int) {
    RETURN IF $precision = 0 THEN <decimal>math::fixed($amount / 10dec, 1) * 10dec
        ELSE <decimal>math::fixed($amount, $precision) END;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::quantize($amount: decimal, $resource: record) {
    RETURN IF record::tb($resource) = 'currency' THEN fn::accounting::round($amount, $resource.precision) ELSE $amount END;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::precision_validate($amount: decimal, $resource: record) {
    IF fn::accounting::quantize($amount, $resource) != $amount { THROW 'ACCOUNTING_AMOUNT_PRECISION'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::effects($real: decimal, $receivable: decimal, $payable: decimal) {
    IF $receivable < 0dec OR $payable < 0dec { THROW 'ACCOUNTING_NEGATIVE_DIRECTION'; };
    RETURN {real:$real,receivable:$receivable,payable:$payable,net:$receivable-$payable,available:$real};
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::claim($signed: decimal) {
    RETURN fn::accounting::effects(0dec,math::max([$signed,0dec]),math::max([-$signed,0dec]));
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::prefix($owner: record, $slot: string, $measure: string, $at: datetime) {
    RETURN fn::tree::read($owner,$slot,'before',[$at]).measures[$measure].sum ?? 0dec;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::same_subsidiary($left: record, $right: record) {
    IF $left.subsidiary != $right.subsidiary { THROW 'ACCOUNTING_SUBSIDIARY'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::resource_validate($row: object) {
    IF $row.available_from != NONE AND $row.available_until != NONE AND $row.available_until <= $row.available_from { THROW 'RESOURCE_TIME_WINDOW'; };
    IF $row.minimum_duration != NONE AND $row.maximum_duration != NONE AND $row.minimum_duration > $row.maximum_duration { THROW 'RESOURCE_DURATION_ORDER'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE currency SCHEMAFULL;

DEFINE FIELD OVERWRITE code ON currency TYPE string READONLY ASSERT string::len($value)>0 COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE name ON currency TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE precision ON currency TYPE int READONLY DEFAULT 2 ASSERT $value>=0 AND $value<=18 COMMENT '@rebase-audit';

DEFINE INDEX OVERWRITE currency_code ON currency FIELDS tenant,code UNIQUE;

DEFINE TABLE OVERWRITE measure_unit SCHEMAFULL;

DEFINE FIELD OVERWRITE code ON measure_unit TYPE string READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE name ON measure_unit TYPE string COMMENT '@rebase-audit';

DEFINE INDEX OVERWRITE measure_unit_code ON measure_unit FIELDS tenant,code UNIQUE;

DEFINE TABLE OVERWRITE item SCHEMAFULL COMMENT '@rebase-validate fn::accounting::resource_validate';

DEFINE FIELD OVERWRITE name ON item TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE unit ON item TYPE record<measure_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE available_from ON item TYPE option<datetime> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE available_until ON item TYPE option<datetime> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_duration ON item TYPE option<duration> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE maximum_duration ON item TYPE option<duration> COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE service SCHEMAFULL COMMENT '@rebase-validate fn::accounting::resource_validate';

DEFINE FIELD OVERWRITE name ON service TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE unit ON service TYPE record<measure_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE available_from ON service TYPE option<datetime> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE available_until ON service TYPE option<datetime> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_duration ON service TYPE option<duration> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE maximum_duration ON service TYPE option<duration> COMMENT '@rebase-audit';
