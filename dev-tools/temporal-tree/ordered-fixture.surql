-- Focused compiled-tree fixture, independent of framework authentication.
-- Every root has a tenant; source ownership deliberately differs from its root.
DEFINE TABLE rebase_user SCHEMAFULL;
DEFINE TABLE rebase_tenant SCHEMAFULL;
DEFINE FIELD name ON rebase_tenant TYPE string;
DEFINE FIELD name ON rebase_user TYPE string;
DEFINE FIELD parents ON rebase_user TYPE array<record<rebase_tenant>>;
DEFINE TABLE ordered_tenant SCHEMAFULL;
DEFINE TABLE ordered_catalog SCHEMAFULL PERMISSIONS FOR select WHERE $auth != NONE
    COMMENT '@rebase-validate fn::ordered::validate';
DEFINE FIELD tenant ON ordered_catalog TYPE record<ordered_tenant> REFERENCE ON DELETE REJECT;
DEFINE FIELD owned_by ON ordered_catalog TYPE record;
DEFINE FIELD currency ON ordered_catalog TYPE string DEFAULT 'USD';
DEFINE FIELD budget ON ordered_catalog TYPE option<decimal>;
DEFINE FIELD z_identifier ON ordered_catalog TYPE object COMMENT '@rebase-tree-root @rebase-tree-key string';
DEFINE FIELD z_price ON ordered_catalog TYPE object COMMENT '@rebase-tree-root @rebase-tree-key decimal @rebase-tree-duplicates';
DEFINE FIELD z_partition ON ordered_catalog TYPE object COMMENT '@rebase-tree-root @rebase-tree-key record,string,datetime @rebase-tree-duplicates';
DEFINE FIELD z_nominal ON ordered_catalog TYPE object COMMENT '@rebase-tree-root @rebase-tree-key record,string';
DEFINE FIELD z_boolean ON ordered_catalog TYPE object COMMENT '@rebase-tree-root @rebase-tree-key bool';
DEFINE FIELD z_uuid ON ordered_catalog TYPE object COMMENT '@rebase-tree-root @rebase-tree-key uuid';
DEFINE FIELD z_record ON ordered_catalog TYPE object COMMENT '@rebase-tree-root @rebase-tree-key record';

DEFINE TABLE ordered_a SCHEMAFULL PERMISSIONS FOR select WHERE $auth != NONE
    COMMENT '@rebase-members fn::ordered::members';
DEFINE FIELD tenant ON ordered_a TYPE record<ordered_tenant> REFERENCE ON DELETE REJECT;
DEFINE FIELD owned_by ON ordered_a TYPE record;
DEFINE FIELD catalog ON ordered_a TYPE record<ordered_catalog> REFERENCE ON DELETE REJECT;
DEFINE FIELD identifier ON ordered_a TYPE option<string>;
DEFINE FIELD price ON ordered_a TYPE option<number>;
DEFINE FIELD category ON ordered_a TYPE string DEFAULT 'a';
DEFINE FIELD at ON ordered_a TYPE datetime;
DEFINE FIELD currency ON ordered_a TYPE string DEFAULT 'USD';
DEFINE FIELD weight ON ordered_a TYPE decimal DEFAULT 1dec;
DEFINE FIELD boolean_key ON ordered_a TYPE option<bool>;
DEFINE FIELD uuid_key ON ordered_a TYPE option<uuid>;
DEFINE FIELD record_key ON ordered_a TYPE option<record<ordered_catalog>> REFERENCE ON DELETE REJECT;
DEFINE FIELD duplicate_identifier ON ordered_a TYPE bool DEFAULT false;
DEFINE FIELD second_price ON ordered_a TYPE option<number>;
DEFINE FIELD z_identifier ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key string @rebase-tree-owner ordered_catalog.z_identifier';
DEFINE FIELD z_duplicate_identifier ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key string @rebase-tree-owner ordered_catalog.z_identifier';
DEFINE FIELD z_price ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key decimal @rebase-tree-owner ordered_catalog.z_price';
DEFINE FIELD z_second_price ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key decimal @rebase-tree-owner ordered_catalog.z_price';
DEFINE FIELD z_partition ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,string,datetime @rebase-tree-owner ordered_catalog.z_partition';
DEFINE FIELD z_nominal ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,string @rebase-tree-owner ordered_catalog.z_nominal';
DEFINE FIELD z_boolean ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key bool @rebase-tree-owner ordered_catalog.z_boolean';
DEFINE FIELD z_uuid ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key uuid @rebase-tree-owner ordered_catalog.z_uuid';
DEFINE FIELD z_record ON ordered_a TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner ordered_catalog.z_record';

DEFINE TABLE ordered_b SCHEMAFULL PERMISSIONS FOR select WHERE $auth != NONE
    COMMENT '@rebase-members fn::ordered::members';
DEFINE FIELD tenant ON ordered_b TYPE record<ordered_tenant> REFERENCE ON DELETE REJECT;
DEFINE FIELD owned_by ON ordered_b TYPE record;
DEFINE FIELD catalog ON ordered_b TYPE record<ordered_catalog> REFERENCE ON DELETE REJECT;
DEFINE FIELD identifier ON ordered_b TYPE option<string>;
DEFINE FIELD price ON ordered_b TYPE option<number>;
DEFINE FIELD category ON ordered_b TYPE string DEFAULT 'a';
DEFINE FIELD at ON ordered_b TYPE datetime;
DEFINE FIELD currency ON ordered_b TYPE string DEFAULT 'USD';
DEFINE FIELD weight ON ordered_b TYPE decimal DEFAULT 1dec;
DEFINE FIELD boolean_key ON ordered_b TYPE option<bool>;
DEFINE FIELD uuid_key ON ordered_b TYPE option<uuid>;
DEFINE FIELD record_key ON ordered_b TYPE option<record<ordered_catalog>> REFERENCE ON DELETE REJECT;
DEFINE FIELD duplicate_identifier ON ordered_b TYPE bool DEFAULT false;
DEFINE FIELD second_price ON ordered_b TYPE option<number>;
DEFINE FIELD z_identifier ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key string @rebase-tree-owner ordered_catalog.z_identifier';
DEFINE FIELD z_duplicate_identifier ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key string @rebase-tree-owner ordered_catalog.z_identifier';
DEFINE FIELD z_price ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key decimal @rebase-tree-owner ordered_catalog.z_price';
DEFINE FIELD z_second_price ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key decimal @rebase-tree-owner ordered_catalog.z_price';
DEFINE FIELD z_partition ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,string,datetime @rebase-tree-owner ordered_catalog.z_partition';
DEFINE FIELD z_nominal ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,string @rebase-tree-owner ordered_catalog.z_nominal';
DEFINE FIELD z_boolean ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key bool @rebase-tree-owner ordered_catalog.z_boolean';
DEFINE FIELD z_uuid ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key uuid @rebase-tree-owner ordered_catalog.z_uuid';
DEFINE FIELD z_record ON ordered_b TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner ordered_catalog.z_record';

DEFINE FUNCTION fn::ordered::members($row: object) {
    RETURN [
        IF $row.identifier = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_identifier', $row.catalog,
            'z_identifier', [$row.identifier], {}, {}) END,
        IF !$row.duplicate_identifier OR $row.identifier = NONE THEN NONE ELSE fn::tree::ordered_member($row.id,
            'z_duplicate_identifier', $row.catalog, 'z_identifier', [$row.identifier], {}, {}) END,
        IF $row.price = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_price', $row.catalog,
            'z_price', [$row.price], { weight: $row.weight }, { currency: $row.currency }) END,
        IF $row.second_price = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_second_price', $row.catalog,
            'z_price', [$row.second_price], { weight: $row.weight }, { currency: $row.currency }) END,
        fn::tree::ordered_member($row.id, 'z_partition', $row.catalog, 'z_partition',
            [$row.tenant, $row.category, $row.at], { weight: $row.weight }, {}),
        IF $row.identifier = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_nominal', $row.catalog,
            'z_nominal', [$row.tenant, $row.identifier], {}, {}) END,
        IF $row.boolean_key = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_boolean', $row.catalog,
            'z_boolean', [$row.boolean_key], {}, {}) END,
        IF $row.uuid_key = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_uuid', $row.catalog,
            'z_uuid', [$row.uuid_key], {}, {}) END,
        IF $row.record_key = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_record', $row.catalog,
            'z_record', [$row.record_key], {}, {}) END
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION fn::ordered::validate($row: object) {
    LET $summary = $row.z_price.summary;
    IF $summary.count > 0 AND (!$summary.tags.currency.uniform OR $summary.tags.currency.value != $row.currency) {
        THROW 'ORDERED_CURRENCY';
    };
    IF $row.budget != NONE AND ($summary.measures.weight.sum ?? 0dec) > $row.budget { THROW 'ORDERED_BUDGET'; };
} PERMISSIONS NONE;
