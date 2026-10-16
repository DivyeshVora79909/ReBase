-- A fixed query belongs to a declared field on its business record. All reads
-- below are pure; index repair and source fencing occur at explicit boundaries.
DEFINE FUNCTION OVERWRITE fn::dependency::value($query: option<object>) {
    RETURN $query.result.value;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::dependency::current($query: object) {
    LET $owner = { rid: $query.source, slot: $query.source_slot };
    IF $query.kind = 'range' {
        RETURN fn::value::at(fn::tree::range($owner, $query.arguments[0], $query.arguments[1]), $query.path) ?? $query.fallback.value;
    };
    LET $link = IF $query.kind = 'exact' THEN fn::tree::find($owner, $query.arguments)
        ELSE fn::tree::seek($owner, $query.arguments[0], $query.kind = 'latest', $query.arguments[1] ?? false) END;
    LET $value = fn::tree::get($link).value;
    LET $selected = IF $link = NONE THEN NONE ELSE object::extend($value, { record: $link.rid, key: $value.first }) END;
    RETURN fn::value::at($selected, $query.path) ?? $query.fallback.value;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::resolve($input: option<object>, $kind: string, $phase: string, $targets: array, $live: bool) {
    IF $input = NONE OR $input.source = NONE { RETURN NONE; };
    IF !type::is_record($input.source) { THROW 'REBASE_DEPENDENCY_SOURCE'; };
    LET $targets = $targets.filter(|$target| $target.table = record::tb($input.source)
        AND ($input.slot = NONE OR $input.slot = $target.slot));
    IF array::len($targets) != 1 { THROW 'REBASE_DEPENDENCY_SOURCE'; };
    LET $target = $targets[0];
    LET $key_type = fn::rebase::root_key_type({ rid: $input.source, slot: $target.slot });
    LET $arguments = $input.arguments;
    IF !type::is_array($arguments) { THROW 'REBASE_DEPENDENCY_ARGUMENT'; };
    IF $kind = 'range' {
        IF array::len($arguments) != 2 OR !$arguments.all(|$bound| $bound = NONE OR fn::tree::valid_key($bound, $key_type, false)) {
            THROW 'REBASE_DEPENDENCY_ARGUMENT';
        };
    } ELSE IF $kind = 'exact' {
        IF !fn::tree::valid_key($arguments, $key_type, false)
            OR array::len($arguments) != array::len(string::split($key_type, ',')) { THROW 'REBASE_DEPENDENCY_ARGUMENT'; };
    } ELSE IF $kind IN ['latest', 'next'] {
        IF array::len($arguments) < 1 OR array::len($arguments) > 2
            OR !fn::tree::valid_key($arguments[0], $key_type, false)
            OR (array::len($arguments) = 2 AND !type::is_bool($arguments[1])) { THROW 'REBASE_DEPENDENCY_ARGUMENT'; };
    } ELSE { THROW 'REBASE_DEPENDENCY_OPERATION'; };
    LET $query = { source: $input.source, source_slot: $target.slot, index: $target.index, kind: $kind, phase: $phase,
        arguments: $arguments, path: $input.path ?? '', fallback: { value: $input.fallback } };
    LET $exists = (SELECT VALUE id FROM ONLY $query.source) != NONE;
    IF !$exists { THROW 'REBASE_DEPENDENCY_SOURCE'; };
    LET $value = IF $live THEN fn::dependency::current($query)
        ELSE fn::tree::read_value($query.source, $query.source_slot, $kind, $arguments, $query.path, $input.fallback) END;
    RETURN object::extend($query, { result: { value: $value } });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::dependency::members($row: option<object>) {
    RETURN fn::dependency::bindings($row, NONE).map(|$binding| {
        LET $query = $binding.query;
        IF $query.kind = 'range' {
            LET $lower = $query.arguments[0]; LET $upper = $query.arguments[1];
            IF $lower != NONE AND $upper != NONE AND $lower >= $upper { RETURN NONE; };
            RETURN fn::tree::interval_member($row.id, $binding.link.slot, $query.source, $query.index,
                [$lower ?? []], IF $upper = NONE THEN NONE ELSE [$upper] END, {}, {});
        };
        LET $position = IF $query.kind = 'exact' THEN $query.arguments ELSE $query.arguments[0] END;
        RETURN fn::tree::ordered_member($row.id, $binding.link.slot, $query.source, $query.index, [$position], {}, {});
    }).filter(|$member| $member != NONE);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::sync($rid: record, $before: option<object>, $after: option<object>) {
    LET $slots = fn::dependency::slots($rid);
    IF array::len($slots) = 0 { RETURN NONE; };
    LET $work = fn::tree::sync($rid, $before, fn::dependency::members($after), $slots);
    FOR $owner IN $work.owners {
        fn::tree::publish($owner);
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::points_from($cursor: option<object>, $owner: object,
    $lower: option<array>, $upper: option<array>, $budget: int) {
    IF $cursor = NONE { RETURN []; };
    IF $budget <= 0 { THROW 'REBASE_DEPENDENCY_INDEX_BUDGET'; };
    LET $node = fn::tree::get($cursor);
    IF $node.owner != $owner { THROW 'REBASE_DEPENDENCY_INDEX'; };
    LET $position = $node.key[0];
    IF $lower != NONE AND $position < $lower { RETURN fn::dependency::points_from($node.right, $owner, $lower, $upper, $budget - 1); };
    IF $upper != NONE AND $position > $upper { RETURN fn::dependency::points_from($node.left, $owner, $lower, $upper, $budget - 1); };
    RETURN array::concat(fn::dependency::points_from($node.left, $owner, $lower, $upper, $budget - 1),
        [fn::dependency::binding($cursor)], fn::dependency::points_from($node.right, $owner, $lower, $upper, $budget - 1));
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::points($owner: object, $lower: option<array>, $upper: option<array>) {
    LET $head = fn::tree::get($owner);
    RETURN fn::dependency::points_from($head.root, $owner, $lower, $upper, $head.height + 1);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::candidates($source: object, $group: object, $key: array) {
    LET $index = { rid: $source.rid, slot: $group.index };
    IF $group.kind = 'range' {
        RETURN fn::tree::read($source.rid, $group.index, 'intervals', [$key]).map(|$link| fn::dependency::binding($link));
    };
    IF $group.kind = 'latest' {
        LET $next = fn::tree::seek($source, $key, false, false);
        RETURN fn::dependency::points($index, $key, fn::tree::get($next).key);
    };
    IF $group.kind = 'next' {
        LET $previous = fn::tree::seek($source, $key, true, false);
        RETURN fn::dependency::points($index, fn::tree::get($previous).key, $key);
    };
    LET $business = fn::tree::business_key($key);
    RETURN fn::dependency::points($index, $business, $business);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::channel($path: string) {
    IF $path = '' { RETURN '*'; };
    LET $parts = string::split($path, '.');
    IF $parts[0] IN ['measures', 'tags', 'spans'] AND array::len($parts) >= 2 {
        RETURN $parts[0] + ':' + $parts[1];
    };
    -- Whole containers and other augmentations can change at a fixed key.
    RETURN IF $parts[0] IN ['count', 'first', 'last', 'record', 'key'] THEN 'order' ELSE '*' END;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::channels($old: option<object>, $new: option<object>) {
    IF $old != NONE AND $new != NONE AND $old.owner = $new.owner AND $old.key = $new.key {
        RETURN array::concat(['*'], ['measures', 'tags', 'spans'].map(|$kind|
            array::union(object::keys($old.value[$kind]), object::keys($new.value[$kind]))
                .filter(|$field| $old.value[$kind][$field] != $new.value[$kind][$field])
                .map(|$field| $kind + ':' + $field)).flatten());
    };
    RETURN array::concat(['*', 'order'], ['measures', 'tags', 'spans'].map(|$kind|
        array::union(object::keys($old.value[$kind] ?? {}), object::keys($new.value[$kind] ?? {}))
            .map(|$field| $kind + ':' + $field)).flatten());
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::pending($bindings: array, $phase: string) {
    RETURN $bindings.any(|$binding| {
        LET $current = fn::dependency::binding($binding.link).query;
        RETURN $current != NONE AND $current.phase = $phase
            AND ((($binding.force ?? false) AND $current.source = $binding.query.source)
                OR fn::dependency::current($current) != $current.result.value);
    });
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::position($query: object) {
    RETURN IF $query.kind = 'range' THEN $query.arguments[1] ?? $query.arguments[0] ?? []
        ELSE IF $query.kind = 'exact' THEN $query.arguments ELSE $query.arguments[0] END;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::dependency::changed($before: option<object>, $after: option<object>, $sync: object) {
    LET $source = $after.id ?? $before.id;
    LET $direct = IF $after != NONE AND fn::dependency::owner_changed($before, $after) THEN
        fn::dependency::groups($source).map(|$group| fn::dependency::points({ rid: $source, slot: $group.index }, NONE, NONE)
            .map(|$binding| object::extend($binding, { force: true }))).flatten() ELSE [] END;
    LET $changes = array::concat($sync.removed ?? [], $sync.added ?? []);
    LET $ordered = $changes.map(|$member| {
        IF (SELECT VALUE id FROM ONLY $member.owner.rid) = NONE { RETURN []; };
        LET $old = $sync.removed.filter(|$item| $item.link = $member.link)[0];
        LET $new = $sync.added.filter(|$item| $item.link = $member.link)[0];
        LET $channels = fn::dependency::channels($old, $new);
        RETURN fn::dependency::groups($member.owner.rid).filter(|$group| $group.slot = $member.owner.slot)
            .map(|$group| fn::dependency::candidates($member.owner, $group, $member.key)
                .filter(|$binding| fn::dependency::channel($binding.query.path) IN $channels)).flatten();
    }).flatten();
    RETURN array::distinct(array::concat($direct, $ordered)).filter(|$binding|
        fn::dependency::pending([$binding], $binding.query.phase));
} PERMISSIONS NONE;
