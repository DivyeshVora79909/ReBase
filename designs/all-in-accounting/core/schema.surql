-- A1 core identities and immutable posting dimensions.
-- Authorization ownership remains distinct from economic identity.

DEFINE TABLE OVERWRITE organization SCHEMAFULL;
DEFINE FIELD OVERWRITE name ON organization TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE code ON organization TYPE option<string> ASSERT $value = NONE OR string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE organization_code ON organization FIELDS code UNIQUE;

DEFINE TABLE OVERWRITE currency SCHEMAFULL;
DEFINE FIELD OVERWRITE code ON currency TYPE string ASSERT string::matches($value, /^[A-Z0-9][A-Z0-9._-]{0,15}$/) READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE name ON currency TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE precision ON currency TYPE int DEFAULT 2 READONLY ASSERT $value >= 0 AND $value <= 18 COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE currency_code ON currency FIELDS code UNIQUE;

DEFINE TABLE OVERWRITE treasury SCHEMAFULL;
DEFINE FIELD OVERWRITE name ON treasury TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE treasury_account SCHEMAFULL COMMENT '@rebase-validate fn::account::treasury_account';
DEFINE FIELD OVERWRITE economic_entity ON treasury_account TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE treasury ON treasury_account TYPE record<treasury> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON treasury_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_balance ON treasury_account TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON treasury_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE treasury_account_dimensions ON treasury_account FIELDS economic_entity, treasury, currency UNIQUE;
DEFINE FUNCTION OVERWRITE fn::account::treasury_account($row: object) {
    -- Cash capacity is measured after all same-timestamp movements; record-ID order is not economic order.
    IF ($row.z_history.summary.measures.balance.instant_min ?? 0dec) < $row.minimum_balance { THROW 'ACCOUNT_TREASURY_MINIMUM_BALANCE'; };
    IF $row.z_history.summary.tags.currency != NONE AND
        (!$row.z_history.summary.tags.currency.uniform OR $row.z_history.summary.tags.currency.value != $row.currency) { THROW 'ACCOUNT_TREASURY_CURRENCY_MISMATCH'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE tax_account SCHEMAFULL;
DEFINE FIELD OVERWRITE authority ON tax_account TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE jurisdiction ON tax_account TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE label ON tax_account TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE classification ON tax_account TYPE option<string> COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE misc_account SCHEMAFULL;
DEFINE FIELD OVERWRITE label ON misc_account TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE purpose ON misc_account TYPE option<string> COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE claim_account SCHEMAFULL COMMENT '@rebase-validate fn::account::claim_account';
DEFINE FIELD OVERWRITE economic_entity ON claim_account TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE opponent ON claim_account TYPE record<rebase_user | organization | tax_account | misc_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON claim_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON claim_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON claim_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON claim_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE claim_account_dimensions ON claim_account FIELDS economic_entity, opponent, currency UNIQUE;
DEFINE FUNCTION OVERWRITE fn::account::claim_account($row: object) {
    -- Financial claim capacity is measured after all same-timestamp effects; record-ID tie order is not economic order.
    IF ($row.z_history.summary.measures.receivable.instant_min ?? 0dec) < 0dec
        OR ($row.z_history.summary.measures.payable.instant_min ?? 0dec) < 0dec {
        THROW 'ACCOUNT_CLAIM_HISTORY_NEGATIVE';
    };
    IF ($row.z_history.summary.measures.recognized_credit.min_prefix ?? 0dec) < 0dec {
        THROW 'ACCOUNT_CLAIM_RECOGNIZED_CREDIT_NEGATIVE';
    };
    IF $row.net_floor != NONE AND $row.net_ceiling != NONE AND $row.net_floor > $row.net_ceiling {
        THROW 'ACCOUNT_CLAIM_NET_LIMIT_ORDER';
    };
    IF $row.net_floor != NONE AND ($row.z_history.summary.measures.net.instant_min ?? 0dec) < $row.net_floor {
        THROW 'ACCOUNT_CLAIM_NET_FLOOR';
    };
    IF $row.net_ceiling != NONE AND ($row.z_history.summary.measures.net.instant_max ?? 0dec) > $row.net_ceiling {
        THROW 'ACCOUNT_CLAIM_NET_CEILING';
    };
    IF $row.z_history.summary.tags.currency != NONE AND
        (!$row.z_history.summary.tags.currency.uniform OR $row.z_history.summary.tags.currency.value != $row.currency) {
        THROW 'ACCOUNT_CLAIM_CURRENCY_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE operating_unit SCHEMAFULL;
DEFINE FIELD OVERWRITE economic_entity ON operating_unit TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE name ON operating_unit TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE code ON operating_unit TYPE option<string> ASSERT $value = NONE OR string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE operating_unit_entity_code ON operating_unit FIELDS economic_entity, code UNIQUE;

DEFINE TABLE OVERWRITE measure_unit SCHEMAFULL;
DEFINE FIELD OVERWRITE code ON measure_unit TYPE string ASSERT string::matches($value, /^[a-z][a-z0-9._-]{0,31}$/) READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE dimension ON measure_unit TYPE string ASSERT $value IN ['count', 'mass', 'volume', 'duration'] READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE name ON measure_unit TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE measure_unit_code ON measure_unit FIELDS code UNIQUE;

DEFINE TABLE OVERWRITE item SCHEMAFULL;
DEFINE FIELD OVERWRITE name ON item TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE code ON item TYPE option<string> ASSERT $value = NONE OR string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON item TYPE record<measure_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE item_code ON item FIELDS code UNIQUE;

DEFINE TABLE OVERWRITE service SCHEMAFULL;
DEFINE FIELD OVERWRITE name ON service TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE code ON service TYPE option<string> ASSERT $value = NONE OR string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON service TYPE record<measure_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE service_code ON service FIELDS code UNIQUE;

DEFINE TABLE OVERWRITE work_type SCHEMAFULL;
DEFINE FIELD OVERWRITE name ON work_type TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE code ON work_type TYPE option<string> ASSERT $value = NONE OR string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON work_type TYPE record<measure_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE work_type_code ON work_type FIELDS code UNIQUE;

DEFINE TABLE OVERWRITE stock_account SCHEMAFULL COMMENT '@rebase-validate fn::account::stock_account';
DEFINE FIELD OVERWRITE economic_entity ON stock_account TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE operating_unit ON stock_account TYPE record<operating_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON stock_account TYPE record<item | service | work_type> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON stock_account TYPE record<measure_unit> VALUE $this.resource.unit READONLY COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_quantity ON stock_account TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_gross_input ON stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE stock_account_dimensions ON stock_account FIELDS economic_entity, operating_unit, resource UNIQUE;
DEFINE FUNCTION OVERWRITE fn::account::stock_account($row: object) {
    IF $row.economic_entity != $row.operating_unit.economic_entity { THROW 'ACCOUNT_STOCK_ENTITY_MISMATCH'; };
    -- Stock capacity is measured after all same-timestamp movements; record-ID order is not economic order.
    IF ($row.z_history.summary.measures.quantity.instant_min ?? 0dec) < $row.minimum_quantity { THROW 'ACCOUNT_STOCK_MINIMUM_QUANTITY'; };
    IF ($row.z_history.summary.measures.available.instant_min ?? 0dec) < 0dec { THROW 'ACCOUNT_STOCK_AVAILABLE_CAPACITY'; };
    IF $row.z_history.summary.tags.resource != NONE AND
        (!$row.z_history.summary.tags.resource.uniform OR $row.z_history.summary.tags.resource.value != $row.resource) { THROW 'ACCOUNT_STOCK_RESOURCE_MISMATCH'; };
    IF $row.z_history.summary.tags.unit != NONE AND
        (!$row.z_history.summary.tags.unit.uniform OR $row.z_history.summary.tags.unit.value != $row.unit) { THROW 'ACCOUNT_STOCK_UNIT_MISMATCH'; };
} PERMISSIONS FULL;
