-- Shared intrusive AVL. Business records own slots; owner records own roots.
-- Private mutation functions execute only inside the source write transaction.
-- Chronology and causal dependency links are independent of rotation topology.

DEFINE FUNCTION OVERWRITE fn::tree::empty() {
    RETURN { count: 0, dependents: 0, measures: {}, tags: {}, spans: {} };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::tree::value($key: array, $measures: object, $tags: object, $spans: object, $dependent: bool) {
    RETURN {
        count: 1, dependents: IF $dependent THEN 1 ELSE 0 END,
        first: $key, last: $key,
        measures: object::from_entries(object::entries($measures).map(|$pair| [$pair[0], {
            sum: <decimal>$pair[1], min_prefix: math::min([0dec, <decimal>$pair[1]]),
            max_prefix: math::max([0dec, <decimal>$pair[1]]),
            instant_min: math::min([0dec, <decimal>$pair[1]]),
            instant_max: math::max([0dec, <decimal>$pair[1]]),
            min: <decimal>$pair[1], max: <decimal>$pair[1]
        }])),
        tags: object::from_entries(object::entries($tags).filter(|$p| $p[1] != NONE)
            .map(|$p| [$p[0], { value: $p[1], uniform: true }])),
        spans: object::from_entries(object::entries($spans).filter(|$p| $p[1] != NONE)
            .map(|$p| [$p[0], { min: $p[1], max: $p[1] }]))
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::tree::combine($a: object, $b: object) {
    IF $a.count = 0 { RETURN $b; };
    IF $b.count = 0 { RETURN $a; };
    RETURN object::extend({
        count: $a.count + $b.count, dependents: $a.dependents + $b.dependents,
        first: $a.first, last: $b.last,
        measures: object::from_entries(array::union(object::keys($a.measures), object::keys($b.measures)).map(|$key| {
            LET $l = $a.measures[$key]; LET $r = $b.measures[$key];
            LET $l_sum = $l.sum ?? 0dec; LET $r_sum = $r.sum ?? 0dec;
            -- A missing measure is a zero contribution at each timestamp in its
            -- nonempty subtree. Preserve zero extrema when that subtree has an
            -- internal timestamp boundary, so an outer balance can shift it.
            LET $l_boundary_min = IF $l = NONE THEN
                IF $a.first[0] < $a.last[0] THEN 0dec ELSE NONE END ELSE $l.boundary_min END;
            LET $l_boundary_max = IF $l = NONE THEN
                IF $a.first[0] < $a.last[0] THEN 0dec ELSE NONE END ELSE $l.boundary_max END;
            LET $r_boundary_min = IF $r = NONE THEN
                IF $b.first[0] < $b.last[0] THEN 0dec ELSE NONE END ELSE $r.boundary_min END;
            LET $r_boundary_max = IF $r = NONE THEN
                IF $b.first[0] < $b.last[0] THEN 0dec ELSE NONE END ELSE $r.boundary_max END;
            LET $sum = $l_sum + $r_sum;
            LET $boundary_min_values = [
                $l_boundary_min, IF $r_boundary_min = NONE THEN NONE ELSE $l_sum + $r_boundary_min END,
                IF $a.last[0] < $b.first[0] THEN $l_sum ELSE NONE END
            ].filter(|$x| $x != NONE);
            LET $boundary_max_values = [
                $l_boundary_max, IF $r_boundary_max = NONE THEN NONE ELSE $l_sum + $r_boundary_max END,
                IF $a.last[0] < $b.first[0] THEN $l_sum ELSE NONE END
            ].filter(|$x| $x != NONE);
            LET $boundary_min = IF array::len($boundary_min_values) = 0 THEN NONE
                ELSE math::min($boundary_min_values) END;
            LET $boundary_max = IF array::len($boundary_max_values) = 0 THEN NONE
                ELSE math::max($boundary_max_values) END;
            RETURN [$key, {
                sum: $sum,
                min_prefix: math::min([$l.min_prefix ?? 0dec, $l_sum + ($r.min_prefix ?? 0dec)]),
                max_prefix: math::max([$l.max_prefix ?? 0dec, $l_sum + ($r.max_prefix ?? 0dec)]),
                boundary_min: $boundary_min, boundary_max: $boundary_max,
                instant_min: math::min([0dec, $sum, $boundary_min].filter(|$x| $x != NONE)),
                instant_max: math::max([0dec, $sum, $boundary_max].filter(|$x| $x != NONE)),
                min: math::min([$l.min, $r.min].filter(|$x| $x != NONE)),
                max: math::max([$l.max, $r.max].filter(|$x| $x != NONE))
            }];
        })),
        tags: object::from_entries(array::union(object::keys($a.tags), object::keys($b.tags)).map(|$key| {
            LET $l = $a.tags[$key]; LET $r = $b.tags[$key];
            RETURN [$key, IF $l = NONE THEN $r ELSE IF $r = NONE THEN $l ELSE {
                value: $l.value, uniform: $l.uniform AND $r.uniform AND $l.value = $r.value
            } END];
        })),
        spans: object::from_entries(array::union(object::keys($a.spans), object::keys($b.spans)).map(|$key| {
            LET $l = $a.spans[$key]; LET $r = $b.spans[$key];
            RETURN [$key, {
                min: array::sort([$l.min, $r.min].filter(|$x| $x != NONE))[0],
                max: array::sort([$l.max, $r.max].filter(|$x| $x != NONE)).last()
            }];
        }))
    }, IF $a.end_key = NONE AND $b.end_key = NONE THEN {} ELSE {
        end_key: array::last(array::sort([$a.end_key, $b.end_key].filter(|$key| $key != NONE)))
    } END);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::tree::get($link: option<object>) {
    IF $link = NONE { RETURN NONE; };
    LET $value = (SELECT VALUE type::field($link.slot) FROM ONLY $link.rid);
    IF $value = NONE { THROW 'AVL_MISSING_SLOT:' + <string>$link.rid + '/' + $link.slot; };
    RETURN $value;
} PERMISSIONS NONE;

-- A deleted source is already invisible to SELECT. Keep only its declared
-- slots in a transient frame; all other links still read/write the live tree.
-- Public reads cannot supply a frame. No source is recreated or staged in a table.
DEFINE FUNCTION OVERWRITE fn::tree::load($link: option<object>, $detached: option<object>) {
    IF $link = NONE { RETURN NONE; };
    IF $detached != NONE AND $link.rid = $detached.rid {
        LET $value = $detached.slots[$link.slot];
        IF $value = NONE { THROW 'AVL_MISSING_SLOT:' + <string>$link.rid + '/' + $link.slot; };
        RETURN $value;
    };
    RETURN fn::tree::get($link);
} PERMISSIONS NONE;

-- Mutators return the updated frame (NONE for normal live writes). The caller
-- threads it through every edit so linked deleted slots never use stale images.
DEFINE FUNCTION OVERWRITE fn::tree::put($link: object, $value: object, $detached: option<object>) {
    IF $value = NONE { THROW 'AVL_PUT_VALUE_NONE:' + <string>$link; };
    LET $stored = object::from_entries(object::entries($value).filter(|$entry| $entry[1] != NONE));
    IF $detached != NONE AND $link.rid = $detached.rid {
        RETURN object::extend($detached, { slots: object::extend($detached.slots ?? {},
            object::from_entries([[$link.slot, $stored]])) });
    };
    LET $old = (SELECT VALUE type::field($link.slot) FROM ONLY $link.rid);
    IF $old != $stored {
        UPDATE $link.rid PATCH [{ op: 'add', path: '/' + $link.slot, value: $stored }] RETURN NONE;
    };
    RETURN $detached;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::tree::patch($link: object, $patch: object, $detached: option<object>) {
    IF $patch = NONE { THROW 'AVL_PATCH_NONE:' + <string>$link; };
    IF $link = NONE { THROW 'AVL_PATCH_LINK_NONE:'; };
    IF $detached != NONE AND $link.rid = $detached.rid {
        RETURN fn::tree::put($link, object::extend(fn::tree::load($link, $detached), $patch), $detached);
    };
    -- Patch only the requested fields. Replacing a complete slot from a cached
    -- image can restore old links when several rotations touch the same node
    -- in one source transaction.
    LET $current = fn::tree::load($link, NONE);
    LET $operations = object::entries($patch).map(|$entry| {
        LET $path = '/' + $link.slot + '/' + $entry[0];
        IF $entry[1] = NONE {
            RETURN IF $current[$entry[0]] = NONE THEN NONE ELSE { op: 'remove', path: $path } END;
        };
        RETURN { op: IF $current[$entry[0]] = NONE THEN 'add' ELSE 'replace' END,
            path: $path, value: $entry[1] };
    }).filter(|$operation| $operation != NONE);
    IF array::len($operations) > 0 {
        UPDATE $link.rid PATCH $operations RETURN NONE;
    };
    RETURN $detached;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::tree::pull($link: object, $detached: option<object>) {
    LET $node = fn::tree::load($link, $detached);
    LET $left = fn::tree::load($node.left, $detached);
    LET $right = fn::tree::load($node.right, $detached);
    RETURN fn::tree::patch($link, {
        height: 1 + math::max([$left.height ?? 0, $right.height ?? 0]),
        summary: fn::tree::combine(
            fn::tree::combine($left.summary ?? fn::tree::empty(), $node.value),
            $right.summary ?? fn::tree::empty()
        )
    }, $detached);
} PERMISSIONS NONE;

-- Reconnect just one edge. The caller repairs the new child's parent link.
DEFINE FUNCTION OVERWRITE fn::tree::replace($owner: object, $parent: object, $old: object, $new: option<object>, $detached: option<object>) {
    LET $p = fn::tree::load($parent, $detached);
    IF $parent = $owner {
        IF $p.root != $old { THROW 'AVL_ROOT_MISMATCH'; };
        RETURN fn::tree::patch($parent, { root: $new }, $detached);
    } ELSE IF $p.left = $old {
        RETURN fn::tree::patch($parent, { left: $new }, $detached);
    } ELSE IF $p.right = $old {
        RETURN fn::tree::patch($parent, { right: $new }, $detached);
    } ELSE { THROW 'AVL_PARENT_MISMATCH'; };
} PERMISSIONS NONE;

-- One rotation, mirrored by direction; demoted node is pulled first.
DEFINE FUNCTION OVERWRITE fn::tree::rotate($owner: object, $pivot: object, $left: bool, $detached: option<object>) {
    LET $p = fn::tree::load($pivot, $detached);
    LET $up = IF $left THEN $p.right ELSE $p.left END;
    LET $u = fn::tree::load($up, $detached);
    LET $inner = IF $left THEN $u.left ELSE $u.right END;
    LET $detached = fn::tree::replace($owner, $p.parent, $pivot, $up, $detached);
    LET $detached = fn::tree::patch($pivot, IF $left
        THEN { parent: $up, right: $inner }
        ELSE { parent: $up, left: $inner } END, $detached);
    LET $detached = IF $inner != NONE THEN fn::tree::patch($inner, { parent: $pivot }, $detached) ELSE $detached END;
    LET $detached = fn::tree::patch($up, IF $left
        THEN { parent: $p.parent, left: $pivot }
        ELSE { parent: $p.parent, right: $pivot } END, $detached);
    LET $detached = fn::tree::pull($pivot, $detached);
    LET $detached = fn::tree::pull($up, $detached);
    RETURN { top: $up, detached: $detached };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::tree::balance($owner: object, $link: object, $detached: option<object>) {
    LET $node = fn::tree::load($link, $detached);
    LET $l = fn::tree::load($node.left, $detached);
    LET $r = fn::tree::load($node.right, $detached);
    LET $difference = ($l.height ?? 0) - ($r.height ?? 0);
    IF $difference > 1 {
        LET $detached = IF (fn::tree::load($l.left, $detached).height ?? 0) < (fn::tree::load($l.right, $detached).height ?? 0)
            THEN fn::tree::rotate($owner, $node.left, true, $detached).detached ELSE $detached END;
        RETURN fn::tree::rotate($owner, $link, false, $detached);
    };
    IF $difference < -1 {
        LET $detached = IF (fn::tree::load($r.right, $detached).height ?? 0) < (fn::tree::load($r.left, $detached).height ?? 0)
            THEN fn::tree::rotate($owner, $node.right, false, $detached).detached ELSE $detached END;
        RETURN fn::tree::rotate($owner, $link, true, $detached);
    };
    LET $detached = fn::tree::pull($link, $detached);
    RETURN { top: $link, detached: $detached };
} PERMISSIONS NONE;

-- The fold carries a cursor and the one deleted source's frame, never a subtree.
-- The budget is the pre-mutation AVL height + 3; exhaustion is an error.
DEFINE FUNCTION OVERWRITE fn::tree::repair($owner: object, $start: object, $budget: int, $detached: option<object>) {
    LET $end = array::range(0, $budget).fold({ cursor: $start, detached: $detached }, |$state, $_| {
        IF $state.cursor = $owner { RETURN $state; };
        LET $result = fn::tree::balance($owner, $state.cursor, $state.detached);
        RETURN { cursor: fn::tree::load($result.top, $result.detached).parent, detached: $result.detached };
    });
    IF $end.cursor != $owner { THROW 'AVL_REPAIR_BUDGET'; };
    RETURN $end.detached;
} PERMISSIONS NONE;

-- Recompute a changed node's complete local subtree bottom-up before repairing
-- its ancestors. Reactive readers can add several members to one private index
-- in the same cascade, so an ancestor must not consume a stale child summary.
DEFINE FUNCTION OVERWRITE fn::tree::rebuild_subtree($owner: object, $link: option<object>, $budget: int) {
    IF $link = NONE { RETURN NONE; };
    IF $budget <= 0 { THROW 'AVL_REBUILD_BUDGET'; };
    LET $node = fn::tree::get($link);
    IF $node.owner != $owner { THROW 'AVL_REBUILD_OWNER'; };
    fn::tree::rebuild_subtree($owner, $node.left, $budget - 1);
    fn::tree::rebuild_subtree($owner, $node.right, $budget - 1);
    fn::tree::pull($link, NONE);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::tree::insert($owner: object, $link: object, $key: array, $value: object) {
    LET $head = fn::tree::get($owner);
    LET $unique = fn::rebase::root_unique($owner);
    LET $business = fn::tree::business_key($key);
    LET $budget = (fn::tree::get($head.root).height ?? 0) + 3;
    LET $place = array::range(0, $budget).fold(
        { cursor: $head.root, parent: $owner, left: false, prev: NONE, next: NONE }, |$state, $_| {
            IF $state.cursor = NONE { RETURN $state; };
            LET $node = fn::tree::get($state.cursor);
            IF $key = $node.key { THROW 'AVL_DUPLICATE_KEY'; };
            IF $unique AND $business = fn::tree::business_key($node.key) { THROW 'TREE_DUPLICATE_VALUE'; };
            LET $left = $key < $node.key;
            RETURN {
                cursor: IF $left THEN $node.left ELSE $node.right END,
                parent: $state.cursor, left: $left,
                prev: IF $left THEN $state.prev ELSE $state.cursor END,
                next: IF $left THEN $state.cursor ELSE $state.next END
            };
        }
    );
    IF $place.cursor != NONE { THROW 'AVL_SEARCH_BUDGET'; };
    fn::tree::put($link, {
        owner: $owner, parent: $place.parent, left: NONE, right: NONE,
        prev: $place.prev, next: $place.next,
        key: $key, value: $value, height: 1, summary: $value
    });
    IF $place.prev != NONE { fn::tree::patch($place.prev, { next: $link }); };
    IF $place.next != NONE { fn::tree::patch($place.next, { prev: $link }); };
    IF $place.parent = $owner {
        fn::tree::patch($owner, { root: $link });
    } ELSE {
        fn::tree::patch($place.parent, IF $place.left
            THEN { left: $link } ELSE { right: $link } END);
        fn::tree::repair($owner, $place.parent, $budget);
    };
} PERMISSIONS NONE;

-- Transplant the successor's LINKS, never another record's business payload.
-- $node is the CURRENT slot image, from the frame after a physical DELETE.
DEFINE FUNCTION OVERWRITE fn::tree::remove($owner: object, $link: object, $node: object, $detached: option<object>) {
    LET $head = fn::tree::load($owner, $detached);
    LET $budget = (fn::tree::load($head.root, $detached).height ?? 0) + 3;
    LET $detached = IF $node.prev != NONE THEN fn::tree::patch($node.prev, { next: $node.next }, $detached) ELSE $detached END;
    LET $detached = IF $node.next != NONE THEN fn::tree::patch($node.next, { prev: $node.prev }, $detached) ELSE $detached END;
    IF $node.left = NONE OR $node.right = NONE {
        LET $child = $node.left ?? $node.right;
        LET $detached = fn::tree::replace($owner, $node.parent, $link, $child, $detached);
        LET $detached = IF $child != NONE THEN fn::tree::patch($child, { parent: $node.parent }, $detached) ELSE $detached END;
        RETURN fn::tree::repair($owner, $node.parent, $budget, $detached);
    };
    LET $successor = array::range(0, $budget).fold($node.right, |$cursor, $_| {
        RETURN fn::tree::load($cursor, $detached).left ?? $cursor;
    });
    LET $next = fn::tree::load($successor, $detached);
    IF $next.left != NONE { THROW 'AVL_SUCCESSOR_BUDGET'; };
    LET $direct = $next.parent = $link;
    LET $detached = IF !$direct {
        LET $detached = fn::tree::replace($owner, $next.parent, $successor, $next.right, $detached);
        LET $detached = IF $next.right != NONE THEN fn::tree::patch($next.right, { parent: $next.parent }, $detached) ELSE $detached END;
        LET $detached = fn::tree::patch($successor, { right: $node.right }, $detached);
        fn::tree::patch($node.right, { parent: $successor }, $detached);
    } ELSE { $detached; };
    LET $detached = fn::tree::replace($owner, $node.parent, $link, $successor, $detached);
    LET $detached = fn::tree::patch($successor, { parent: $node.parent, left: $node.left }, $detached);
    LET $detached = fn::tree::patch($node.left, { parent: $successor }, $detached);
    RETURN fn::tree::repair($owner, IF $direct THEN $successor ELSE $next.parent END, $budget, $detached);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::tree::change($owner: object, $link: object, $value: object) {
    LET $node = fn::tree::get($link);
    IF $node.value = $value { RETURN NONE; };
    fn::tree::patch($link, { value: $value }, NONE);
    fn::tree::repair($owner, $link, (fn::tree::get(fn::tree::get($owner).root).height ?? 0) + 3);
} PERMISSIONS NONE;

-- Publish only after all memberships of the source mutation are repaired.
-- Domain assertions are on the owner's summary, separate from the AVL code.
DEFINE FUNCTION OVERWRITE fn::tree::publish($owner: object) {
    LET $before = SELECT * FROM ONLY $owner.rid;
    LET $head = fn::tree::get($owner);
    LET $root = fn::tree::get($head.root);
    fn::tree::patch($owner, {
        height: $root.height ?? 0,
        summary: $root.summary ?? fn::tree::empty()
    });
    RETURN { before: $before, after: (SELECT * FROM ONLY $owner.rid) };
} PERMISSIONS NONE;

-- Exact 1-based selection. Percentile policy is a caller choice over k.
DEFINE FUNCTION OVERWRITE fn::tree::select($owner: object, $k: any, $dependent: bool) {
    IF !type::is_int($k) { THROW 'TREE_READ_ARGUMENT'; };
    LET $head = fn::tree::get($owner);
    LET $root = fn::tree::get($head.root);
    IF $k < 1 OR $k > (IF $dependent THEN $root.summary.dependents ?? 0 ELSE $root.summary.count ?? 0 END) { RETURN NONE; };
    LET $found = array::range(0, (fn::tree::get($head.root).height ?? 0) + 1).fold(
        { cursor: $head.root, k: $k, found: NONE }, |$state, $_| {
            IF $state.found != NONE { RETURN $state; };
            LET $node = fn::tree::get($state.cursor);
            LET $left_summary = fn::tree::get($node.left).summary;
            LET $left_count = IF $dependent THEN $left_summary.dependents ?? 0 ELSE $left_summary.count ?? 0 END;
            LET $own_count = IF $dependent THEN $node.value.dependents ELSE 1 END;
            IF $own_count = 1 AND $state.k = $left_count + 1 {
                RETURN { cursor: NONE, k: 0, found: $state.cursor };
            };
            RETURN IF $state.k <= $left_count
                THEN { cursor: $node.left, k: $state.k, found: NONE }
                ELSE { cursor: $node.right, k: $state.k - $left_count - $own_count, found: NONE } END;
        }
    );
    IF $found.found = NONE { THROW 'AVL_SELECT_BUDGET'; };
    RETURN $found.found;
} PERMISSIONS NONE;

-- Summary STRICTLY BEFORE a key: count is rank - 1 for an existing key.
-- Passing [value] gives a boundary before all ties at that primary value.
DEFINE FUNCTION OVERWRITE fn::tree::before($owner: object, $key: array) {
    LET $head = fn::tree::get($owner);
    IF !fn::tree::valid_key($key, fn::rebase::root_key_type($owner), false) { THROW 'TREE_READ_KEY'; };
    LET $result = array::range(0, (fn::tree::get($head.root).height ?? 0) + 1).fold(
        { cursor: $head.root, summary: fn::tree::empty() }, |$state, $_| {
            IF $state.cursor = NONE { RETURN $state; };
            LET $node = fn::tree::get($state.cursor);
            IF $node.key >= $key { RETURN { cursor: $node.left, summary: $state.summary }; };
            LET $left = fn::tree::get($node.left).summary ?? fn::tree::empty();
            RETURN {
                cursor: $node.right,
                summary: fn::tree::combine(fn::tree::combine($state.summary, $left), $node.value)
            };
        }
    );
    IF $result.cursor != NONE { THROW 'AVL_PREFIX_BUDGET'; };
    RETURN $result.summary;
} PERMISSIONS NONE;

-- Ordered range [lower, upper). Whole interior subtrees are merged in O(1).
-- At most two boundary paths are expanded; the stack never holds a subtree.
DEFINE FUNCTION OVERWRITE fn::tree::range($owner: object, $lower: array, $upper: array) {
    LET $head = fn::tree::get($owner);
    LET $key_type = fn::rebase::root_key_type($owner);
    IF !fn::tree::valid_key($lower, $key_type, false) OR !fn::tree::valid_key($upper, $key_type, false) {
        THROW 'TREE_READ_KEY';
    };
    IF $lower >= $upper OR $head.root = NONE { RETURN fn::tree::empty(); };
    LET $height = fn::tree::get($head.root).height;
    LET $result = array::range(0, 6 * $height + 3).fold(
        { stack: [{ link: $head.root }], summary: fn::tree::empty() }, |$state, $_| {
            IF array::len($state.stack) = 0 { RETURN $state; };
            LET $task = array::last($state.stack);
            LET $rest = array::slice($state.stack, 0, array::len($state.stack) - 1);
            IF $task.value != NONE {
                RETURN { stack: $rest, summary: fn::tree::combine($state.summary, $task.value) };
            };
            LET $node = fn::tree::get($task.link);
            IF $node = NONE OR $node.summary.last < $lower OR $node.summary.first >= $upper {
                RETURN { stack: $rest, summary: $state.summary };
            };
            IF $node.summary.first >= $lower AND $node.summary.last < $upper {
                RETURN { stack: $rest, summary: fn::tree::combine($state.summary, $node.summary) };
            };
            LET $own = IF $node.key >= $lower AND $node.key < $upper THEN [{ value: $node.value }] ELSE [] END;
            RETURN {
                stack: array::concat($rest, [{ link: $node.right }], $own, [{ link: $node.left }]),
                summary: $state.summary
            };
        }
    );
    IF array::len($result.stack) != 0 { THROW 'TREE_RANGE_BUDGET'; };
    RETURN $result.summary;
} PERMISSIONS NONE;

-- First matching boundary in either direction. Partial tuples are ordinary
-- lexicographic boundaries; a full key is an exact, stable pagination cursor.
DEFINE FUNCTION OVERWRITE fn::tree::seek($owner: object, $key: any, $reverse: bool, $inclusive: bool) {
    IF !fn::tree::valid_key($key, fn::rebase::root_key_type($owner), false) { THROW 'TREE_READ_KEY'; };
    LET $head = fn::tree::get($owner);
    LET $result = array::range(0, (fn::tree::get($head.root).height ?? 0) + 1).fold(
        { cursor: $head.root, found: NONE }, |$state, $_| {
            IF $state.cursor = NONE { RETURN $state; };
            LET $node = fn::tree::get($state.cursor);
            LET $match = IF $reverse THEN $node.key < $key OR ($inclusive AND $node.key = $key)
                ELSE $node.key > $key OR ($inclusive AND $node.key = $key) END;
            RETURN { cursor: IF $reverse = $match THEN $node.right ELSE $node.left END,
                found: IF $match THEN $state.cursor ELSE $state.found END };
        });
    IF $result.cursor != NONE { THROW 'AVL_SEEK_BUDGET'; };
    RETURN $result.found;
} PERMISSIONS NONE;

-- Find a complete business key across every source table in this root. The
-- default unique root returns at most one member; duplicate roots return first.
DEFINE FUNCTION OVERWRITE fn::tree::find($owner: object, $business: any) {
    LET $key_type = fn::rebase::root_key_type($owner);
    IF !fn::tree::valid_key($business, $key_type, false)
        OR array::len($business) != array::len(string::split($key_type, ',')) { THROW 'TREE_READ_KEY'; };
    LET $found = fn::tree::seek($owner, $business, false, true);
    RETURN IF $found != NONE AND fn::tree::business_key(fn::tree::get($found).key) = $business THEN $found ELSE NONE END;
} PERMISSIONS NONE;

-- One logarithmic seek followed by at most limit+1 next/prev record reads.
-- Links leave business-field projection to normal record permissions. Revision
-- lets callers detect changes between pages; this is not a cross-query snapshot.
DEFINE FUNCTION OVERWRITE fn::tree::page($owner: object, $limit: any, $after: any, $reverse: bool) {
    IF !type::is_int($limit) OR $limit < 1 OR $limit > 200 { THROW 'TREE_PAGE_LIMIT'; };
    LET $head = fn::tree::get($owner);
    LET $first = IF $after = NONE THEN
        fn::tree::select($owner, IF $reverse THEN $head.summary.count ELSE 1 END, false)
        ELSE fn::tree::seek($owner, $after, $reverse, false) END;
    LET $page = array::range(0, $limit + 1).fold({ cursor: $first, items: [] }, |$state, $_| {
        IF $state.cursor = NONE { RETURN $state; };
        LET $node = fn::tree::get($state.cursor);
        RETURN { cursor: IF $reverse THEN $node.prev ELSE $node.next END,
            items: array::append($state.items, { link: $state.cursor, key: $node.key }) };
    });
    LET $items = array::slice($page.items, 0, $limit);
    RETURN { items: $items, revision: $head.revision,
        next: IF array::len($page.items) > $limit THEN array::last($items).key ELSE NONE END };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::tree::business_key($key: array) {
    RETURN array::slice($key, 0, array::len($key) - 2);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::tree::valid_component($value: any, $kind: string) {
    RETURN IF $kind = 'datetime' THEN type::is_datetime($value)
        ELSE IF $kind = 'int' THEN type::is_int($value) AND $value >= -9007199254740991 AND $value <= 9007199254740991
        ELSE IF $kind = 'decimal' THEN type::is_decimal($value)
        ELSE IF $kind = 'string' THEN type::is_string($value)
        ELSE IF $kind = 'record' THEN type::is_record($value)
        ELSE IF $kind = 'bool' THEN type::is_bool($value)
        ELSE IF $kind = 'uuid' THEN type::is_uuid($value)
        ELSE IF $kind = 'tuple' THEN type::is_array($value)
            AND $value.all(|$part| type::is_datetime($part) OR type::is_int($part) OR type::is_decimal($part)
                OR type::is_string($part) OR type::is_record($part) OR type::is_bool($part) OR type::is_uuid($part))
        ELSE false END;
} PERMISSIONS FULL;

-- Validate before any typed storage or numeric coercion. Partial keys are
-- leading components for range boundaries; stored membership keys are full.
DEFINE FUNCTION OVERWRITE fn::tree::valid_key($key: any, $key_type: string, $full: bool) {
    IF !type::is_array($key) { RETURN false; };
    LET $parts = string::split($key_type, ',');
    IF array::len($parts) < 1 OR array::len($parts) > 16 { RETURN false; };
    IF !$parts.all(|$part| $part IN ['datetime', 'int', 'decimal', 'string', 'record', 'bool', 'uuid', 'tuple']) { RETURN false; };
    LET $types = array::concat($parts, ['string', 'string']);
    LET $size = array::len($key);
    IF $size < 1 OR $size > array::len($types) OR ($full AND $size != array::len($types)) { RETURN false; };
    RETURN array::range(0, $size).all(|$i| fn::tree::valid_component($key[$i], $types[$i]));
} PERMISSIONS FULL;

-- Explicit typed business components, plus a stable source/slot suffix. A
-- nominal component may be unique itself or partition an ordinal component.
-- Numeric measurements belong in measures, independently of their sort key.
DEFINE FUNCTION OVERWRITE fn::tree::ordered_member($rid: record, $slot: string, $owner: option<record>, $root: string,
    $business: any, $measures: object, $tags: object) {
    IF $owner = NONE OR $business = NONE { RETURN NONE; };
    IF !type::is_array($business) { THROW 'TREE_ORDERED_KEY'; };
    LET $key = array::concat($business, [<string>$rid, $slot]);
    IF !fn::tree::valid_key($key, fn::rebase::root_key_type({ rid: $owner, slot: $root }), true) { THROW 'TREE_ORDERED_KEY'; };
    RETURN { link: { rid: $rid, slot: $slot }, owner: { rid: $owner, slot: $root }, key: $key,
        value: fn::tree::value($key, $measures, $tags, {}, false) };
} PERMISSIONS NONE;

-- Integer ordinal codes are not timestamps or measured quantities. Missing
-- order values omit membership. Prefix-dependent formulas remain temporal.
-- `any` deliberately avoids SurrealDB 3.2's fractional -> option<int> panic.
DEFINE FUNCTION OVERWRITE fn::tree::int_member($rid: record, $slot: string, $owner: option<record>, $root: string,
    $order: any, $measures: object, $tags: object) {
    IF $owner = NONE OR $order = NONE { RETURN NONE; };
    LET $key = [$order, <string>$rid, $slot];
    IF !fn::tree::valid_key($key, 'int', true) { THROW 'TREE_INT_KEY'; };
    RETURN {
        link: { rid: $rid, slot: $slot }, owner: { rid: $owner, slot: $root }, key: $key,
        value: fn::tree::value($key, $measures, $tags, {}, false)
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::tree::member($rid: record, $slot: string, $owner: option<record>, $root: string,
    $at: any, $measures: object, $tags: object, $spans: object, $dependent: bool) {
    IF $owner = NONE { RETURN NONE; };
    LET $key = [$at, <string>$rid, $slot];
    IF !fn::tree::valid_key($key, 'datetime', true) { THROW 'TREE_DATETIME_KEY'; };
    RETURN {
        link: { rid: $rid, slot: $slot }, owner: { rid: $owner, slot: $root }, key: $key,
        value: fn::tree::value($key, $measures, $tags, $spans, $dependent)
    };
} PERMISSIONS NONE;

-- A source can occupy several primary keys in one owner. Coincident legs are
-- one net contribution, represented by the first SCHEMA-declared present slot.
-- Provider array order cannot choose the identity or a prefix consumer's key.
DEFINE FUNCTION OVERWRITE fn::tree::coalesce($members: array) {
    LET $present = $members.filter(|$m| $m != NONE);
    IF array::len(array::distinct($present.map(|$m| $m.link))) != array::len($present) { THROW 'TREE_DUPLICATE_MEMBERSHIP'; };
    LET $ordered = array::flatten(array::distinct($present.map(|$m| $m.link.rid)).map(|$rid| {
        LET $source = $present.filter(|$m| $m.link.rid = $rid);
        LET $slots = fn::rebase::slots($rid);
        IF $source.any(|$m| !($m.link.slot IN $slots)) { THROW 'TREE_INVALID_MEMBERSHIP'; };
        RETURN $slots.map(|$slot| $source.filter(|$m| $m.link.slot = $slot)[0]).filter(|$m| $m != NONE);
    }));
    RETURN array::distinct($ordered.map(|$m| [$m.link.rid, $m.owner,
        IF fn::rebase::root_unique($m.owner) THEN $m.key ELSE fn::tree::business_key($m.key) END])).map(|$group| {
        LET $parts = $ordered.filter(|$m| $m.link.rid = $group[0] AND $m.owner = $group[1]
            AND (IF fn::rebase::root_unique($m.owner) THEN $m.key ELSE fn::tree::business_key($m.key) END) = $group[2]);
        LET $first = $parts[0];
        IF array::len($parts) = 1 { RETURN $first; };
        IF $parts.any(|$m| $m.value.dependents > 0 AND $m.link != $first.link) { THROW 'TREE_COALESCE_CAUSAL_SLOT'; };
        LET $values = $parts.map(|$m| $m.value);
        LET $measures = array::distinct(array::flatten($values.map(|$v| object::keys($v.measures))));
        LET $tags = array::distinct(array::flatten($values.map(|$v| object::keys($v.tags))));
        LET $spans = array::distinct(array::flatten($values.map(|$v| object::keys($v.spans))));
        LET $tag_values = object::from_entries($tags.map(|$k| {
            LET $items = $values.filter(|$v| $v.tags[$k] != NONE).map(|$v| $v.tags[$k]);
            IF $items.any(|$t| !$t.uniform OR $t.value != $items[0].value) { THROW 'TREE_COALESCE_DIMENSION'; };
            RETURN [$k, $items[0].value];
        }));
        LET $span_values = object::from_entries($spans.map(|$k| {
            LET $items = $values.filter(|$v| $v.spans[$k] != NONE).map(|$v| $v.spans[$k]);
            IF $items.any(|$s| $s.min != $s.max OR $s.min != $items[0].min) { THROW 'TREE_COALESCE_SPAN'; };
            RETURN [$k, $items[0].min];
        }));
        RETURN object::extend($first, { value: fn::tree::value($first.key,
            object::from_entries($measures.map(|$k| [$k, math::sum($values.map(|$v| $v.measures[$k].sum ?? 0dec))])),
            $tag_values, $span_values, $values.any(|$v| $v.dependents > 0)) });
    });
} PERMISSIONS NONE;

-- Cached slots are the old truth: dereferencing an old business link would
-- read its NEW target state after a parent edit and lose the old contribution.
DEFINE FUNCTION OVERWRITE fn::tree::sync($rid: record, $before: option<object>, $members: array, $slots: array) {
    LET $tenant = (SELECT VALUE tenant FROM ONLY $rid);
    LET $old = $slots.filter(|$slot| $before[$slot] != NONE).map(|$slot| {
        LET $node = $before[$slot];
        RETURN { link: { rid: $rid, slot: $slot }, owner: $node.owner, key: $node.key, value: $node.value };
    });
    -- Validate EVERY projection before coalescing can discard a slot identity.
    FOR $member IN $members.filter(|$m| $m != NONE) {
        IF $member.link.rid != $rid OR !($member.link.slot IN $slots)
            OR !fn::rebase::membership_allowed($member.link, $member.owner) OR $member.link = $member.owner
            OR $member.value.count != 1 OR $member.value.first != $member.key OR $member.value.last != $member.key {
            THROW 'TREE_INVALID_MEMBERSHIP';
        };
        LET $key_type = fn::rebase::root_key_type($member.owner);
        LET $key_size = array::len(string::split($key_type, ','));
        IF !fn::tree::valid_key($member.key, $key_type, true)
            OR $member.key[$key_size] != <string>$rid OR $member.key[$key_size + 1] != $member.link.slot {
            THROW 'TREE_MEMBERSHIP_KEY';
        };
        IF $tenant != (SELECT VALUE tenant FROM ONLY $member.owner.rid) { THROW 'TREE_TENANT_MISMATCH'; };
        IF $key_type != 'datetime' AND $member.value.dependents != 0 { THROW 'TREE_INT_DEPENDENCY'; };
    };
    LET $new = fn::tree::coalesce($members);
    IF array::len(array::distinct($new.map(|$m| $m.link.slot))) != array::len($new) {
        THROW 'TREE_DUPLICATE_MEMBERSHIP';
    };
    LET $removed = $old.filter(|$m| !($m IN $new));
    LET $added = $new.filter(|$m| !($m IN $old));
    LET $changes = array::concat($removed, $added);
    -- record::exists can still be true in a synchronous DELETE event, while
    -- SELECT already sees the tombstone. Use the visible row as the boundary.
    LET $exists = (SELECT VALUE id FROM ONLY $rid) != NONE;
    LET $owners = array::distinct($changes.map(|$m| $m.owner))
        .filter(|$o| ($exists OR $o.rid != $rid) AND (SELECT VALUE id FROM ONLY $o.rid) != NONE);
    FOR $owner IN $owners {
        LET $head = fn::tree::get($owner);
        LET $keys = $changes.filter(|$m| $m.owner = $owner).map(|$m| $m.key);
        LET $first = array::sort($keys)[0];
        IF $head.refreshing = true AND $head.cursor != NONE AND $first < $head.cursor {
            THROW 'TREE_NONCAUSAL_REFRESH';
        };
        fn::tree::patch($owner, {
            revision: $head.revision + 1,
            dirty: IF $head.dirty = NONE OR $first < $head.dirty THEN $first ELSE $head.dirty END
        });
    };
    -- Carry the deleted row's slot edits across removals: a successor, parent,
    -- or chronological neighbor may be another slot on that same absent row.
    LET $detached = IF $exists THEN NONE ELSE { rid: $rid,
        slots: object::from_entries($slots.filter(|$slot| $before[$slot] != NONE).map(|$slot| [$slot, $before[$slot]]))
    } END;
    LET $detached = $removed.fold($detached, |$detached, $member| {
        LET $replacement = $new.filter(|$m| $m.link = $member.link)[0];
        IF ($replacement = NONE OR $replacement.owner != $member.owner OR $replacement.key != $member.key)
            AND $member.owner IN $owners {
            IF fn::tree::get($member.owner).refreshing = true { THROW 'TREE_TOPOLOGY_DURING_REFRESH'; };
            LET $node = fn::tree::load($member.link, $detached);
            LET $detached = fn::tree::remove($member.owner, $member.link, $node, $detached);
            IF $exists {
                UPDATE $rid MERGE object::from_entries([[$member.link.slot, NONE]]) RETURN NONE;
                RETURN $detached;
            };
            RETURN object::extend($detached, { slots: object::from_entries(
                object::entries($detached.slots ?? {}).filter(|$p| $p[0] != $member.link.slot)) });
        };
        RETURN $detached;
    });
    FOR $member IN $added {
        LET $previous = $old.filter(|$m| $m.link = $member.link)[0];
        IF $previous != NONE AND $previous.owner = $member.owner AND $previous.key = $member.key {
            fn::tree::change($member.owner, $member.link, $member.value);
        } ELSE {
            IF fn::tree::get($member.owner).refreshing = true { THROW 'TREE_TOPOLOGY_DURING_REFRESH'; };
            fn::tree::insert($member.owner, $member.link, $member.key, $member.value);
        };
    };
    RETURN { owners: $owners, records: [], removed: $removed, added: $added };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::rebase::work($items: array) {
    RETURN {
        owners: array::distinct(array::flatten($items.map(|$w| $w.owners ?? []))),
        records: array::distinct(array::flatten($items.map(|$w| $w.records ?? [])))
    };
} PERMISSIONS NONE;

-- Reconcile schema-owned outputs by stable (source, role) record IDs. Managed
-- output table events skip their own finish; this outer refresh returns every
-- child image so all trees and guards settle in the source operation.
DEFINE FUNCTION OVERWRITE fn::rebase::sync_required_outputs($source: record, $desired: array) {
    -- A direct reference to another managed-output table is a lifecycle edge:
    -- create prerequisites first and remove dependents first.
    LET $existing = fn::rebase::managed_outputs_reverse($source);
    LET $ordered_desired = fn::rebase::order_required_outputs($desired);
    IF array::len($ordered_desired) != array::len($desired) { THROW 'REBASE_REQUIRED_OUTPUT_TABLE'; };
    LET $source_row = SELECT * FROM ONLY $source;
    LET $dependencies = $source_row.rebase_dependency_sources ?? [];
    LET $reachable = array::flatten($dependencies.{..+collect}.rebase_dependency_sources);
    LET $dependency_targets = array::distinct(array::concat($dependencies, $reachable));
    LET $roles = $ordered_desired.map(|$output| $output.role);
    LET $ids = $ordered_desired.map(|$output| $output.id);
    IF array::len(array::distinct($roles)) != array::len($roles) { THROW 'REBASE_REQUIRED_DUPLICATE_ROLE'; };
    IF array::len(array::distinct($ids)) != array::len($ids) { THROW 'REBASE_REQUIRED_DUPLICATE_ID'; };
    LET $contracts = $ordered_desired.map(|$output| {
        IF !fn::rebase::is_managed_output_table(record::tb($output.id)) {
            THROW 'REBASE_REQUIRED_OUTPUT_TABLE';
        };
        IF $output.id != type::record(record::tb($output.id), [$source, $output.role]) {
            THROW 'REBASE_REQUIRED_OUTPUT_IDENTITY';
        };
        LET $candidate = object::extend($output.data, {
            id: $output.id, rebase_managed_source: <string>$source, rebase_managed_role: $output.role
        });
        LET $members = fn::rebase::members($candidate);
        IF $members.any(|$member| $member != NONE AND $member.owner.rid IN $dependency_targets) {
            THROW 'REBASE_REQUIRED_OUTPUT_FEEDBACK';
        };
        LET $before = SELECT * FROM ONLY $output.id;
        IF $before != NONE AND ($before.rebase_managed_source != <string>$source
            OR $before.rebase_managed_role != $output.role) {
            THROW 'REBASE_REQUIRED_OUTPUT_COLLISION';
        };
        RETURN $output;
    });
    -- Reconcile and refresh one child at a time. Earlier AVL edits may rewrite
    -- a sibling's cached slot, so each next child must capture its live image.
    LET $writes = $contracts.fold([], |$writes, $output| {
        LET $before = SELECT * FROM ONLY $output.id;
        LET $content = object::extend($output.data, {
            rebase_managed_source: <string>$source, rebase_managed_role: $output.role
        });
        IF $before = NONE {
            CREATE $output.id CONTENT $content RETURN NONE;
        } ELSE {
            UPDATE $output.id MERGE $content RETURN NONE;
        };
        RETURN array::append($writes, fn::rebase::refresh($output.id, $before, false));
    });
    LET $removed_ids = $existing.filter(|$output| !($output.id IN $ids)).map(|$output| $output.id);
    LET $removed = $removed_ids.fold([], |$removed, $id| {
        LET $before = SELECT * FROM ONLY $id;
        IF $before != NONE { DELETE $id RETURN NONE; };
        RETURN array::append($removed, fn::rebase::refresh($id, $before, false));
    });
    RETURN fn::rebase::work(array::concat($writes, $removed));
} PERMISSIONS NONE;

-- Enumerate only prefix consumers, never every fixed delta in the suffix.
-- During this sweep formulas may change contributions but not their topology.
-- Input/ancestor reference edits are refreshed BEFORE entering the sweep.
DEFINE FUNCTION OVERWRITE fn::tree::drain($owner: object) {
    LET $head = fn::tree::get($owner);
    IF $head.dirty = NONE OR $head.refreshing = true { RETURN { owners: [], records: [] }; };
    IF fn::rebase::root_key_type($owner) != 'datetime' {
        fn::tree::patch($owner, { dirty: NONE });
        RETURN { owners: [], records: [] };
    };
    LET $start = fn::tree::before($owner, $head.dirty).dependents;
    LET $count = fn::tree::get($head.root).summary.dependents ?? 0;
    LET $candidates = array::range($start, $count).map(|$i| fn::tree::select($owner, $i + 1, true));
    fn::tree::patch($owner, { refreshing: true });
    LET $work = $candidates.fold([], |$work, $link| {
        LET $node = fn::tree::get($link);
        fn::tree::patch($owner, { cursor: $node.key });
        RETURN array::append($work, fn::rebase::refresh($link.rid, (SELECT * FROM ONLY $link.rid), true));
    });
    fn::tree::patch($owner, { refreshing: false, cursor: NONE, dirty: NONE });
    RETURN fn::rebase::work($work);
} PERMISSIONS NONE;

-- The source transaction captures logical reads as its formulas execute.
DEFINE FUNCTION OVERWRITE fn::rebase::refresh($rid: record, $before: option<object>, $sweep: bool) {
    RETURN fn::rebase::refresh_path($rid, $before, $sweep, []);
} PERMISSIONS NONE;

-- Remove former positions before evaluating a moved contribution. Otherwise a
-- prefix at its new date could read its own old position. Affected predecessors
-- settle against the removal before the moving record computes its new value.
DEFINE FUNCTION OVERWRITE fn::rebase::prepare_move($rid: record, $before: option<object>, $current: option<object>, $path: array) {
    IF $before = NONE OR $current = NONE { RETURN { moved: false, owners: [], records: [] }; };
    LET $old = fn::rebase::slots($rid).filter(|$slot| $before[$slot] != NONE).map(|$slot| {
        LET $node = $before[$slot];
        RETURN { link: { rid: $rid, slot: $slot }, owner: $node.owner, key: $node.key, value: $node.value };
    });
    IF array::len($old) = 0 { RETURN { moved: false, owners: [], records: [] }; };
    LET $self_reads = SELECT * FROM rebase_read WHERE reader = $rid AND phase = 'refresh';
    IF !$self_reads.any(|$read| $old.any(|$member| $member.owner.rid = $read.source_root AND $member.owner.slot = $read.source_slot)) {
        RETURN { moved: false, owners: [], records: [] };
    };
    LET $planned = fn::tree::coalesce(fn::rebase::members($current));
    LET $retained = $old.filter(|$member| $planned.any(|$new| $new.link = $member.link AND $new.owner = $member.owner AND $new.key = $member.key));
    IF array::len($retained) = array::len($old) { RETURN { moved: false, owners: [], records: [] }; };
    fn::reads::forget($rid);
    LET $sync = fn::tree::sync($rid, $before, $retained, fn::rebase::slots($rid));
    LET $reads = fn::reads::changed($before, $before, $sync).filter(|$read| $read.reader != $rid);
    LET $ordered = array::sort($reads.filter(|$read| $read.phase = 'refresh').map(|$read| [$read.position, <string>$read.reader, $read.reader]));
    LET $children = array::distinct($ordered.map(|$item| $item[2]));
    LET $down = $children.fold([], |$down, $child| {
        IF fn::reads::pending($reads.filter(|$read| $read.reader = $child).id, 'refresh') {
            RETURN array::append($down, fn::rebase::refresh_path($child, (SELECT * FROM ONLY $child), false, $path));
        };
        RETURN array::append($down, { owners: [], records: [] });
    });
    RETURN object::extend(fn::rebase::work(array::concat([{ owners: $sync.owners,
        records: $reads.filter(|$read| $read.phase = 'validate').reader }], $down)), { moved: true });
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::rebase::refresh_path($rid: record, $before: option<object>, $sweep: bool, $path: array) {
    IF $rid IN $path { THROW 'REBASE_READ_CYCLE'; };
    LET $path = array::append($path, $rid);
    LET $current = SELECT * FROM ONLY $rid;
    LET $prepared = fn::rebase::prepare_move($rid, $before, $current, $path);
    LET $current = SELECT * FROM ONLY $rid;
    LET $slot_before = IF $prepared.moved THEN $current ELSE $before END;
    LET $scope = fn::reads::begin($rid, 'refresh');
    IF $current = NONE { fn::reads::forget($rid); };
    IF $current != NONE {
        LET $patch = fn::rebase::derive($current, $scope);
        IF object::len($patch) > 0 AND object::entries($patch).any(|$p| $current[$p[0]] != $p[1]) {
            UPDATE $rid PATCH object::entries($patch).filter(|$p| $current[$p[0]] != $p[1]).map(|$p| {
                RETURN IF $p[1] = NONE THEN { op: 'remove', path: '/' + $p[0] }
                    ELSE { op: IF $current[$p[0]] = NONE THEN 'add' ELSE 'replace' END, path: '/' + $p[0], value: $p[1] } END;
            }).filter(|$p| $p.op != 'remove' OR $current[string::slice($p.path, 1)] != NONE) RETURN NONE;
        };
    };
    LET $after = SELECT * FROM ONLY $rid;
    IF $after != NONE {
        LET $sources = $after.rebase_dependency_sources ?? [];
        LET $reachable = array::flatten($sources.{..+collect}.rebase_dependency_sources);
        IF $rid IN $sources OR $rid IN $reachable { THROW 'REBASE_DEPENDENCY_CYCLE'; };
    };
    LET $own = fn::tree::sync($rid, $slot_before, fn::rebase::captured_members($after, $scope), fn::rebase::slots($rid));
    LET $required = IF fn::rebase::has_required_outputs($rid) THEN
        fn::rebase::sync_required_outputs($rid, fn::rebase::captured_outputs($after, $scope))
        ELSE { owners: [], records: [] } END;
    IF $after != NONE { fn::reads::end($scope); };
    LET $reads = fn::reads::changed($before, $after, $own);
    LET $children = fn::rebase::dependents($before, $after);
    LET $positions = array::sort($reads.filter(|$read| $read.phase = 'refresh').map(|$read| [$read.position, <string>$read.reader, $read.reader]));
    LET $ordered = SELECT id, a_effective_at ?? effective_at AS at FROM $children ORDER BY at, id;
    LET $candidates = array::distinct(array::concat($positions.map(|$item| $item[2]), $ordered.id));
    LET $down = $candidates.fold([], |$down, $child| {
        LET $bindings = $reads.filter(|$r| $r.reader = $child).id;
        IF $child IN $children OR fn::reads::pending($bindings, 'refresh') {
            RETURN array::append($down, fn::rebase::refresh_path($child, (SELECT * FROM ONLY $child), false, $path));
        };
        RETURN array::append($down, { owners: [], records: [] });
    });
    LET $work = fn::rebase::work(array::concat([{ owners: $own.owners,
        records: array::concat([$rid], $reads.filter(|$r| $r.phase = 'validate').reader) }, $prepared, $required], $down));
    IF $after = NONE { DELETE type::record('rebase_read_lock', [$rid]) RETURN NONE; };
    -- A prerequisite that is also a root can be removed after its last child.
    -- Its former owner work remains in the transaction but has nothing to drain.
    LET $temporal = IF $sweep THEN $work.owners.filter(|$owner| (SELECT VALUE id FROM ONLY $owner.rid) != NONE)
        .fold([], |$drained, $owner| array::append($drained, fn::tree::drain($owner))) ELSE [] END;
    RETURN fn::rebase::work(array::concat([$work], $temporal));
} PERMISSIONS NONE;

-- Publish all roots as one phase. Guards run after causal recalculation, so a
-- parent edit never validates against still-stale descendant contributions.
DEFINE FUNCTION OVERWRITE fn::rebase::finish($work: object) {
    LET $published = $work.owners.filter(|$o| (SELECT VALUE id FROM ONLY $o.rid) != NONE)
        .fold([], |$published, $owner| array::append($published, fn::tree::publish($owner)));
    LET $reads = $published.map(|$p| fn::reads::changed($p.before, $p.after, { owners: [], removed: [], added: [], publication: true })).flatten();
    LET $direct = array::distinct($published.map(|$p| fn::rebase::dependents($p.before, $p.after)).flatten());
    LET $children = array::distinct(array::concat($direct, $reads.filter(|$read| $read.phase = 'refresh').reader));
    LET $down = fn::rebase::work($children.fold([], |$down, $rid| {
        IF $rid IN $direct OR fn::reads::pending($reads.filter(|$read| $read.reader = $rid).id, 'refresh') {
            RETURN array::append($down, fn::rebase::refresh($rid, (SELECT * FROM ONLY $rid), true));
        };
        RETURN array::append($down, { owners: [], records: [] });
    }));
    IF array::len($down.owners) > 0 OR array::len($down.records) > 0 { fn::rebase::finish($down); };
    FOR $rid IN array::distinct(array::concat($work.records, $work.owners.map(|$o| $o.rid), $reads.filter(|$read| $read.phase = 'validate').reader)) {
        LET $row = SELECT * FROM ONLY $rid;
        IF $row != NONE { fn::rebase::validate($row); };
    };
    LET $changed_read_groups = SELECT VALUE id FROM rebase_read_group WHERE tree_changed = true;
    FOR $group IN $changed_read_groups { fn::reads::settle_group($group); };
} PERMISSIONS NONE;
