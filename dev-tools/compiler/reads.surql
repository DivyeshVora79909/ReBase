-- Pure reads are usable in native VALUE fields and ordinary application queries.
-- Only generated private callers collect subscriptions.
DEFINE FUNCTION OVERWRITE fn::record::read_value($rid: record, $path: string, $fallback: any) {
    LET $parts = string::split($path, '.');
    IF $path = '' OR $parts[0] IN fn::rebase::slots($rid) { THROW 'REBASE_READ_RECORD_FIELD'; };
    IF fn::rebase::root_allowed({ rid: $rid, slot: $parts[0] }) {
        IF $parts[1] != 'summary' { THROW 'REBASE_READ_RECORD_FIELD'; };
        RETURN fn::tree::read_value($rid, $parts[0], 'summary', [], array::join(array::slice($parts, 2), '.'), $fallback);
    };
    LET $row = SELECT * FROM ONLY $rid;
    RETURN fn::reads::project($row, $path) ?? $fallback;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::reads::project($value: any, $path: string) {
    IF $path = '' { RETURN $value; };
    IF !string::matches($path, '^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*$') { THROW 'REBASE_READ_PATH'; };
    RETURN string::split($path, '.').fold($value, |$value, $part| {
        IF $value = NONE { RETURN NONE; };
        IF !type::is_object($value) { THROW 'REBASE_READ_PATH'; };
        RETURN $value[$part];
    });
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::tree::read_value($owner: record, $slot: string, $operation: string,
    $arguments: array, $path: string, $fallback: any) {
    IF $operation IN ['before', 'range', 'summary'] {
        RETURN fn::reads::project(fn::tree::read($owner, $slot, $operation, $arguments), $path) ?? $fallback;
    };
    IF $operation IN ['latest', 'next', 'exact'] {
        IF $operation != 'exact' AND (array::len($arguments) < 1 OR array::len($arguments) > 2) { THROW 'TREE_READ_ARGUMENT'; };
        LET $link = IF $operation = 'exact' THEN fn::tree::read($owner, $slot, 'find', $arguments)
            ELSE fn::tree::read($owner, $slot, 'seek', [$arguments[0], $operation = 'latest', $arguments[1] ?? false]) END;
        LET $value = fn::tree::read($owner, $slot, 'value', [$link]);
        LET $selected = IF $link = NONE THEN NONE ELSE object::extend($value, { record: $link.rid, key: $value.first }) END;
        RETURN fn::reads::project($selected, $path) ?? $fallback;
    };
    THROW 'REBASE_READ_OPERATION';
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::reads::begin($reader: record, $phase: string) {
    IF !fn::rebase::captures($reader, $phase) { RETURN { reader: $reader, phase: $phase, active: false }; };
    LET $frame = type::record('rebase_read_frame', [$reader, $phase]);
    LET $version = ((SELECT VALUE version FROM ONLY $frame) ?? 0) + 1;
    -- A frame is persisted only if this evaluation actually executes a read.
    RETURN { reader: $reader, tenant: (SELECT VALUE tenant FROM ONLY $reader), phase: $phase, version: $version, active: true };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::fence($source: record, $tenant: record) {
    LET $lock = type::record('rebase_read_lock', [$source]);
    LET $old = SELECT * FROM ONLY $lock;
    IF $old != NONE AND $old.tenant != $tenant { THROW 'REBASE_READ_TENANT'; };
    UPSERT $lock SET tenant = $tenant, revision = ($old.revision ?? 0) + 1 RETURN NONE;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::channel($path: string) {
    IF $path = '' { RETURN '*'; };
    LET $parts = string::split($path, '.');
    RETURN IF $parts[0] IN ['measures', 'tags', 'spans'] AND array::len($parts) >= 2
        THEN $parts[0] + ':' + $parts[1] ELSE 'order' END;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::span_members($row: object) {
    IF $row.kind != 'range' {
        RETURN [fn::tree::ordered_member($row.id, 'z_position', $row.group, 'z_positions', [$row.position], {}, {})];
    };
    IF $row.kind != 'range' OR $row.arguments[0] >= $row.arguments[1] { RETURN []; };
    LET $member = fn::tree::ordered_member($row.id, 'z_interval', $row.group, 'z_intervals', [$row.arguments[0]], {}, {});
    RETURN [object::extend($member, { value: object::extend($member.value, { end_key: $row.arguments[1] }) })];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::remember($scope: object, $source: record, $slot: string, $kind: string,
    $arguments: array, $path: string, $fallback: any, $value: any) {
    LET $tenant = SELECT VALUE tenant FROM ONLY $source;
    IF $tenant = NONE OR $tenant != $scope.tenant { THROW 'REBASE_READ_TENANT'; };
    LET $channel = IF $kind = 'record' THEN IF $path = '' THEN '*' ELSE string::split($path, '.')[0] END
        ELSE fn::reads::channel($path) END;
    LET $group = type::record('rebase_read_group', [$source, $slot, $kind, $channel]);
    LET $position = IF $kind IN ['latest', 'next', 'range'] THEN $arguments[0]
        ELSE IF $kind IN ['before', 'exact'] THEN $arguments ELSE [] END;
    LET $fingerprint = crypto::sha256(<string>[$kind, $arguments, $path, $fallback]);
    LET $id = type::record('rebase_read', [$group, $position, <string>$scope.reader, $scope.phase, $fingerprint]);
    LET $inserted = INSERT IGNORE INTO rebase_read {
        id: $id, tenant: $tenant, reader: $scope.reader, reader_identity: <string>$scope.reader,
        phase: $scope.phase, version: $scope.version,
        source_root: $source, source_slot: $slot, kind: $kind, channel: $channel,
        arguments: $arguments, path: $path, fallback: { value: $fallback }, observed: { value: $value }, group: $group, position: $position
    } RETURN AFTER;
    IF array::len($inserted) > 0 {
        fn::reads::fence($source, $tenant);
        UPSERT $group SET tenant = $tenant, source_root = $source, source_slot = $slot,
            kind = $kind, channel = $channel RETURN NONE;
    };
    UPSERT type::record('rebase_read_frame', [$scope.reader, $scope.phase]) SET version = $scope.version RETURN NONE;
    IF array::len($inserted) = 0 {
        LET $current = SELECT * FROM ONLY $id;
        IF $current.version != $scope.version OR $current.observed.value != $value {
            UPDATE $id SET version = $scope.version, observed = { value: $value } RETURN NONE;
        };
    };
    IF array::len($inserted) > 0 {
        LET $row = SELECT * FROM ONLY $id;
        LET $work = fn::tree::sync($id, NONE, fn::reads::span_members($row), ['z_position', 'z_interval']);
        FOR $owner IN $work.owners {
            fn::tree::publish($owner);
            fn::tree::patch($owner, { dirty: NONE, cursor: NONE, refreshing: false });
        };
    };
    RETURN $value;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::tree($scope: object, $owner: record, $slot: string, $operation: string,
    $arguments: array, $path: string, $fallback: any) {
    LET $value = fn::reads::value($owner, $slot, $operation, $arguments, $path, $fallback);
    RETURN fn::reads::remember($scope, $owner, $slot, $operation, $arguments, $path, $fallback, $value);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::value($owner: record, $slot: string, $operation: string,
    $arguments: array, $path: string, $fallback: any) {
    IF $operation = 'summary' {
        IF array::len($arguments) != 0 { THROW 'TREE_READ_ARGUMENT'; };
        IF !fn::rebase::root_allowed({ rid: $owner, slot: $slot }) { THROW 'TREE_UNKNOWN_ROOT'; };
        LET $head = fn::tree::get({ rid: $owner, slot: $slot });
        LET $summary = fn::tree::get($head.root).summary ?? fn::tree::empty();
        RETURN fn::reads::project($summary, $path) ?? $fallback;
    };
    RETURN fn::tree::read_value($owner, $slot, $operation, $arguments, $path, $fallback);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::record($scope: object, $source: record, $path: string, $fallback: any) {
    LET $parts = string::split($path, '.');
    IF fn::rebase::root_allowed({ rid: $source, slot: $parts[0] }) {
        IF $parts[1] != 'summary' { THROW 'REBASE_READ_RECORD_FIELD'; };
        RETURN fn::reads::tree($scope, $source, $parts[0], 'summary', [], array::join(array::slice($parts, 2), '.'), $fallback);
    };
    LET $value = fn::record::read_value($source, $path, $fallback);
    RETURN fn::reads::remember($scope, $source, '', 'record', [], $path, $fallback, $value);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::before($scope: object, $owner: object, $key: array) {
    RETURN fn::reads::tree($scope, $owner.rid, $owner.slot, 'before', $key, '', fn::tree::empty());
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::range($scope: object, $owner: object, $lower: array, $upper: array) {
    RETURN fn::reads::tree($scope, $owner.rid, $owner.slot, 'range', [$lower, $upper], '', fn::tree::empty());
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::remove($read: object) {
    -- Unlink a range node while its row is still visible; THEN delete metadata.
    {
        LET $work = fn::tree::sync($read.id, $read, [], ['z_position', 'z_interval']);
        FOR $owner IN $work.owners {
            fn::tree::publish($owner);
            fn::tree::patch($owner, { dirty: NONE, cursor: NONE, refreshing: false });
        };
    };
    DELETE $read.id RETURN NONE;
    LET $group = $read.group;
    LET $remaining = SELECT VALUE id FROM rebase_read:[$group, NONE]..[$group, ..] LIMIT 1;
    IF array::len($remaining) = 0 {
        DELETE $group RETURN NONE;
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::end($scope: object) {
    IF !$scope.active { RETURN NONE; };
    LET $stale = SELECT * FROM rebase_read WHERE reader = $scope.reader AND phase = $scope.phase AND version != $scope.version;
    FOR $read IN $stale { fn::reads::remove($read); };
    IF array::len((SELECT VALUE id FROM rebase_read WHERE reader = $scope.reader AND phase = $scope.phase LIMIT 1)) = 0 {
        DELETE type::record('rebase_read_frame', [$scope.reader, $scope.phase]) RETURN NONE;
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::forget($reader: record) {
    FOR $read IN (SELECT * FROM rebase_read WHERE reader_identity = <string>$reader) { fn::reads::remove($read); };
    DELETE type::record('rebase_read_frame', [$reader, 'refresh']) RETURN NONE;
    DELETE type::record('rebase_read_frame', [$reader, 'validate']) RETURN NONE;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::current($read: object) {
    RETURN IF $read.kind = 'record' THEN fn::record::read_value($read.source_root, $read.path, $read.fallback.value)
        ELSE fn::reads::value($read.source_root, $read.source_slot, $read.kind, $read.arguments, $read.path, $read.fallback.value) END;
} PERMISSIONS NONE;

-- Reverse queries use the same typed comparison as source trees. Native record
-- ID encodings do not consistently preserve datetime/nanosecond value order.
DEFINE FUNCTION OVERWRITE fn::reads::points_from($link: option<object>, $owner: object,
    $lower: option<array>, $upper: option<array>, $budget: int) {
    IF $link = NONE { RETURN []; };
    IF $budget <= 0 { THROW 'REBASE_READ_INDEX_BUDGET'; };
    LET $node = fn::tree::get($link);
    IF $node.owner != $owner { THROW 'REBASE_READ_INDEX'; };
    IF $lower != NONE AND $node.key < $lower {
        RETURN fn::reads::points_from($node.right, $owner, $lower, $upper, $budget - 1);
    };
    IF $upper != NONE AND $node.key >= $upper {
        RETURN fn::reads::points_from($node.left, $owner, $lower, $upper, $budget - 1);
    };
    RETURN array::concat(
        fn::reads::points_from($node.left, $owner, $lower, $upper, $budget - 1),
        [(SELECT * FROM ONLY $link.rid)],
        fn::reads::points_from($node.right, $owner, $lower, $upper, $budget - 1)
    );
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::points($group: record, $lower: option<array>, $upper: option<array>) {
    LET $owner = { rid: $group, slot: 'z_positions' };
    LET $head = fn::tree::get($owner);
    IF $head.root = NONE { RETURN []; };
    LET $lower_key = IF $lower = NONE THEN NONE ELSE [$lower] END;
    LET $upper_key = IF $upper = NONE THEN NONE ELSE [$upper, '~'] END;
    RETURN fn::reads::points_from($head.root, $owner, $lower_key, $upper_key, $head.height + 1);
} PERMISSIONS NONE;

-- An interval AVL has fixed logical bounds, independent of source rotations.
-- The lower-key and maximum-upper-key summaries prune nonintersecting subtrees.
DEFINE FUNCTION OVERWRITE fn::reads::stab($link: option<object>, $key: array) {
    IF $link = NONE { RETURN []; };
    LET $node = fn::tree::get($link);
    IF $node.summary.end_key <= $key OR $node.summary.first[0] > $key { RETURN []; };
    LET $own = IF $node.key[0] <= $key AND $key < $node.value.end_key
        THEN [SELECT * FROM ONLY $link.rid] ELSE [] END;
    RETURN array::concat(fn::reads::stab($node.left, $key), $own, fn::reads::stab($node.right, $key));
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::candidates($group: object, $key: array) {
    LET $owner = { rid: $group.source_root, slot: $group.source_slot };
    IF $group.kind = 'latest' {
        LET $next = fn::tree::seek($owner, $key, false, false);
        RETURN fn::reads::points($group.id, $key, fn::tree::get($next).key);
    };
    IF $group.kind = 'next' {
        LET $previous = fn::tree::seek($owner, $key, true, false);
        RETURN fn::reads::points($group.id, fn::tree::get($previous).key, $key);
    };
    IF $group.kind = 'before' { RETURN fn::reads::points($group.id, $key, NONE); };
    IF $group.kind = 'exact' {
        LET $business = fn::tree::business_key($key);
        RETURN fn::reads::points($group.id, $business, $business);
    };
    IF $group.kind = 'range' { RETURN fn::reads::stab($group.z_intervals.root, $key); };
    RETURN fn::reads::points($group.id, NONE, NONE);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::channels($old: option<object>, $new: option<object>) {
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

DEFINE FUNCTION OVERWRITE fn::reads::changed($before: option<object>, $after: option<object>, $sync: object) {
    LET $source = $after.id ?? $before.id;
    LET $tenant = $after.tenant ?? $before.tenant;
    IF $tenant != NONE AND !($sync.publication ?? false) { fn::reads::fence($source, $tenant); };
    FOR $owner IN $sync.owners {
        fn::reads::fence($owner.rid, (SELECT VALUE tenant FROM ONLY $owner.rid));
    };
    LET $direct_groups = SELECT * FROM rebase_read_group:[$source, '', NONE]..[$source, '', ..];
    LET $direct = $direct_groups.filter(|$group| $group.channel = '*' OR $before[$group.channel] != $after[$group.channel])
        .map(|$group| fn::reads::points($group.id, NONE, NONE)).flatten();
    LET $changes = array::concat($sync.removed ?? [], $sync.added ?? []);
    LET $ordered = $changes.map(|$member| {
        LET $old = $sync.removed.filter(|$m| $m.link = $member.link)[0];
        LET $new = $sync.added.filter(|$m| $m.link = $member.link)[0];
        LET $channels = fn::reads::channels($old, $new);
        LET $owner = $member.owner;
        IF (SELECT VALUE id FROM ONLY $owner.rid) = NONE { RETURN []; };
        LET $groups = SELECT * FROM rebase_read_group:[$owner.rid, $owner.slot, NONE]..[$owner.rid, $owner.slot, ..];
        RETURN $groups.filter(|$group| $group.channel IN $channels).map(|$group|
            fn::reads::candidates($group, $member.key)).flatten();
    }).flatten();
    LET $reads = array::distinct(array::concat($direct, $ordered));
    RETURN $reads.filter(|$read| fn::reads::current($read) != $read.observed.value);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::reads::pending($ids: array, $phase: string) {
    LET $reads = SELECT * FROM $ids;
    RETURN $reads.any(|$read| $read.phase = $phase AND fn::reads::current($read) != $read.observed.value);
} PERMISSIONS NONE;
