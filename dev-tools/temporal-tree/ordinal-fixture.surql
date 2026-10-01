-- Disposable primitive experiment, intentionally not a compiler profile.
-- Load src/temporal.surql first. No replacement AVL or reactive consumers.
-- Flexible internal storage is narrowed at every key-bearing field; compiled
-- field/record authorization and full structural typing are separate gates.

DEFINE TABLE ordinal_owner SCHEMAFULL;
DEFINE FIELD max_count ON ordinal_owner TYPE int DEFAULT 100 ASSERT $value >= 0;
DEFINE FIELD rb_order ON ordinal_owner TYPE object FLEXIBLE
    DEFAULT { height: 0, revision: 0, refreshing: false, summary: fn::tree::empty() }
    PERMISSIONS NONE;
DEFINE FIELD rb_order.dirty ON ordinal_owner TYPE option<[int, string, string]>;
DEFINE FIELD rb_order.cursor ON ordinal_owner TYPE option<[int, string, string]>;
DEFINE FIELD rb_order.summary ON ordinal_owner TYPE object FLEXIBLE;
DEFINE FIELD rb_order.summary.first ON ordinal_owner TYPE option<[int, string, string]>;
DEFINE FIELD rb_order.summary.last ON ordinal_owner TYPE option<[int, string, string]>;

DEFINE TABLE ordinal_fact SCHEMAFULL;
DEFINE FIELD owner ON ordinal_fact TYPE record<ordinal_owner> REFERENCE ON DELETE REJECT;
-- SurrealDB 3.2.0 aborts on fractional decimal -> option<int> coercion.
-- Preserve numeric input, then require its native type before building a key.
DEFINE FIELD order_value ON ordinal_fact TYPE option<number>
    ASSERT $value = NONE OR type::is_int($value);
DEFINE FIELD weight ON ordinal_fact TYPE decimal DEFAULT 1dec;
DEFINE FIELD rb_order ON ordinal_fact TYPE option<object> FLEXIBLE PERMISSIONS NONE;
DEFINE FIELD rb_order.key ON ordinal_fact TYPE [int, string, string];
DEFINE FIELD rb_order.value ON ordinal_fact TYPE object FLEXIBLE;
DEFINE FIELD rb_order.value.first ON ordinal_fact TYPE [int, string, string];
DEFINE FIELD rb_order.value.last ON ordinal_fact TYPE [int, string, string];
DEFINE FIELD rb_order.summary ON ordinal_fact TYPE object FLEXIBLE;
DEFINE FIELD rb_order.summary.first ON ordinal_fact TYPE [int, string, string];
DEFINE FIELD rb_order.summary.last ON ordinal_fact TYPE [int, string, string];

DEFINE FUNCTION fn::rebase::root_allowed($link: object) {
    RETURN record::tb($link.rid) = 'ordinal_owner' AND $link.slot = 'rb_order';
} PERMISSIONS FULL;

DEFINE FUNCTION fn::rebase::root_key_type($link: object) {
    IF !fn::rebase::root_allowed($link) { THROW 'TREE_UNKNOWN_ROOT'; };
    RETURN 'int';
} PERMISSIONS FULL;

DEFINE FUNCTION fn::rebase::membership_allowed($link: object, $owner: object) {
    RETURN record::tb($link.rid) = 'ordinal_fact' AND $link.slot = 'rb_order'
        AND fn::rebase::root_allowed($owner);
} PERMISSIONS NONE;

DEFINE FUNCTION fn::rebase::slots($rid: record) {
    RETURN IF record::tb($rid) = 'ordinal_fact' THEN ['rb_order'] ELSE [] END;
} PERMISSIONS NONE;

DEFINE FUNCTION fn::rebase::members($row: option<object>) {
    IF $row = NONE OR record::tb($row.id) != 'ordinal_fact' OR $row.order_value = NONE {
        RETURN [];
    };
    LET $key = [$row.order_value, <string>$row.id, 'rb_order'];
    RETURN [{
        link: { rid: $row.id, slot: 'rb_order' },
        owner: { rid: $row.owner, slot: 'rb_order' }, key: $key,
        value: fn::tree::value($key, { weight: $row.weight }, {}, {}, false)
    }];
} PERMISSIONS NONE;

DEFINE FUNCTION fn::rebase::derive($row: object) { RETURN {}; } PERMISSIONS NONE;
DEFINE FUNCTION fn::rebase::dependents($before: option<object>, $after: option<object>) {
    RETURN [];
} PERMISSIONS NONE;

DEFINE FUNCTION fn::rebase::validate($row: object) {
    IF record::tb($row.id) = 'ordinal_owner' AND $row.rb_order.summary.count > $row.max_count {
        THROW 'ORDINAL_OWNER_LIMIT';
    };
} PERMISSIONS NONE;

-- The normal refresh/sync/drain/publish/validate runtime executes each source
-- mutation. Internal link/summary repairs do not retrigger source events.
DEFINE EVENT ordinal_refresh ON ordinal_fact
WHEN $event != 'UPDATE' OR $before.owner != $after.owner
    OR $before.order_value != $after.order_value OR $before.weight != $after.weight THEN {
    LET $old = IF $event = 'CREATE' THEN NONE ELSE $before END;
    fn::rebase::finish(fn::rebase::refresh($after.id ?? $before.id, $old, true));
};

DEFINE EVENT ordinal_refresh ON ordinal_owner
WHEN $event != 'UPDATE' OR $before.max_count != $after.max_count THEN {
    IF $event = 'DELETE' AND $before.rb_order.summary.count > 0 {
        THROW 'TREE_OWNER_NOT_EMPTY';
    };
    LET $old = IF $event = 'CREATE' THEN NONE ELSE $before END;
    fn::rebase::finish(fn::rebase::refresh($after.id ?? $before.id, $old, true));
};
