-- C2a compiled fixture: four positions per source in each of two key types.
-- Slot declaration order deliberately differs from both lexical/provider order.
-- Membership owner pointers use native references so the compiler can include
-- their direct-parent reader propagation and reject dangling owner records.
DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL ;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL ;

DEFINE TABLE OVERWRITE position_owner SCHEMAFULL
    COMMENT '@rebase-members fn::positions::members @rebase-validate fn::positions::validate';
DEFINE FIELD OVERWRITE a_time_owner ON position_owner TYPE option<record<position_owner>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_order_owner ON position_owner TYPE option<record<position_owner>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_reverse ON position_owner TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_fail ON position_owner TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_time_limit ON position_owner TYPE number DEFAULT 1000 ASSERT type::is_int($value) AND $value >= 0;
DEFINE FIELD OVERWRITE a_order_limit ON position_owner TYPE number DEFAULT 1000 ASSERT type::is_int($value) AND $value >= 0;
DEFINE FIELD OVERWRITE a_instant_floor ON position_owner TYPE option<decimal>;
DEFINE FIELD OVERWRITE a_instant_capacity ON position_owner TYPE option<decimal>;
DEFINE FIELD OVERWRITE a_floor ON position_owner TYPE option<decimal>;
DEFINE FIELD OVERWRITE rb_time ON position_owner TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE rb_order ON position_owner TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int';
DEFINE FIELD OVERWRITE a_time_z ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_z ON position_owner TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_z ON position_owner TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_z ON position_owner TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_z ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_time_a ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_a ON position_owner TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_a ON position_owner TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_a ON position_owner TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_a ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_time_m ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_m ON position_owner TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_m ON position_owner TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_m ON position_owner TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_m ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_time_b ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_b ON position_owner TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_b ON position_owner TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_b ON position_owner TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_b ON position_owner TYPE option<datetime>;
DEFINE FIELD OVERWRITE rb_time_z ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_time_a ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_time_m ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_time_b ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_order_z ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';
DEFINE FIELD OVERWRITE rb_order_a ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';
DEFINE FIELD OVERWRITE rb_order_m ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';
DEFINE FIELD OVERWRITE rb_order_b ON position_owner TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';

DEFINE TABLE OVERWRITE position_fact SCHEMAFULL
    COMMENT '@rebase-members fn::positions::members @rebase-validate fn::positions::validate';
DEFINE FIELD OVERWRITE a_time_owner ON position_fact TYPE option<record<position_owner>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_order_owner ON position_fact TYPE option<record<position_owner>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_reverse ON position_fact TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_fail ON position_fact TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_time_z ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_z ON position_fact TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_z ON position_fact TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_z ON position_fact TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_z ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_time_a ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_a ON position_fact TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_a ON position_fact TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_a ON position_fact TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_a ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_time_m ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_m ON position_fact TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_m ON position_fact TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_m ON position_fact TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_m ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_time_b ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_order_b ON position_fact TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_weight_b ON position_fact TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_tag_b ON position_fact TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE a_span_b ON position_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE rb_time_z ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_time_a ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_time_m ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_time_b ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner position_owner.rb_time';
DEFINE FIELD OVERWRITE rb_order_z ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';
DEFINE FIELD OVERWRITE rb_order_a ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';
DEFINE FIELD OVERWRITE rb_order_m ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';
DEFINE FIELD OVERWRITE rb_order_b ON position_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner position_owner.rb_order';

DEFINE FUNCTION OVERWRITE fn::positions::members($row: object) {
    LET $time_owner = $row.a_time_owner;
    LET $order_owner = $row.a_order_owner;
    LET $parts = array::flatten(['b', 'm', 'a', 'z'].map(|$suffix| [
        IF $row['a_time_' + $suffix] = NONE THEN NONE ELSE
            fn::tree::member($row.id, 'rb_time_' + $suffix, $time_owner, 'rb_time',
                $row['a_time_' + $suffix], { weight: $row['a_weight_' + $suffix] },
                { unit: $row['a_tag_' + $suffix] }, { basis: $row['a_span_' + $suffix] }, false) END,
        IF $row['a_order_' + $suffix] = NONE THEN NONE ELSE
            fn::tree::int_member($row.id, 'rb_order_' + $suffix, $order_owner, 'rb_order',
                $row['a_order_' + $suffix], { weight: $row['a_weight_' + $suffix] },
                { unit: $row['a_tag_' + $suffix] }) END
    ]));
    RETURN IF $row.a_reverse THEN array::reverse($parts) ELSE $parts END;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::positions::validate($row: object) {
    IF $row.a_fail { THROW 'POSITIONS_SOURCE_GUARD'; };
    IF record::tb($row.id) = 'position_owner' {
        LET $instant = $row.rb_time.summary.measures.weight;
        IF $row.rb_time.summary.count > $row.a_time_limit OR $row.rb_order.summary.count > $row.a_order_limit {
            THROW 'POSITIONS_OWNER_LIMIT';
        };
        IF $row.a_floor != NONE AND ($row.rb_time.summary.measures.weight.sum ?? 0dec) < $row.a_floor {
            THROW 'POSITIONS_OWNER_FLOOR';
        };
        IF $row.a_instant_floor != NONE AND ($instant.instant_min ?? 0dec) < $row.a_instant_floor {
            THROW 'POSITIONS_INSTANT_FLOOR';
        };
        IF $row.a_instant_capacity != NONE AND ($instant.instant_max ?? 0dec) > $row.a_instant_capacity {
            THROW 'POSITIONS_INSTANT_CAPACITY';
        };
    };
} PERMISSIONS NONE;
