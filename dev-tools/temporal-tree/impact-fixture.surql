-- Small proof of a predecessor function and its authored inverse impact.
DEFINE TABLE OVERWRITE impact_curve SCHEMAFULL COMMENT '@rebase-impact fn::impact_probe::initial';
DEFINE FIELD OVERWRITE initial ON impact_curve TYPE decimal;
DEFINE FIELD OVERWRITE z_points ON impact_curve TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_readers ON impact_curve TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FUNCTION OVERWRITE fn::impact_probe::value_at($curve: record, $at: datetime) {
    LET $previous = fn::tree::read($curve, 'z_points', 'seek', [[$at + 1ns], true, false]);
    RETURN IF $previous = NONE THEN (SELECT VALUE initial FROM ONLY $curve)
        ELSE (SELECT VALUE value FROM ONLY $previous.rid) END;
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::impact_probe::interval($curve: record, $at: datetime) {
    LET $next = fn::tree::seek({ rid: $curve, slot: 'z_points' }, [$at + 1ns], false, true);
    RETURN { owner: { rid: $curve, slot: 'z_readers' }, lower: [$at],
        upper: IF $next = NONE THEN NONE ELSE [fn::tree::get($next).key[0]] END };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::impact_probe::initial($before: option<object>, $after: option<object>) {
    IF $before = NONE OR $after = NONE OR $before.initial = $after.initial { RETURN []; };
    LET $first = fn::tree::select({ rid: $after.id, slot: 'z_points' }, 1, false);
    RETURN [{ owner: { rid: $after.id, slot: 'z_readers' }, lower: NONE,
        upper: IF $first = NONE THEN NONE ELSE [fn::tree::get($first).key[0]] END }];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::impact_probe::changed($before: option<object>, $after: option<object>) {
    IF $before.curve = $after.curve AND $before.effective_at = $after.effective_at AND $before.value = $after.value { RETURN []; };
    RETURN array::distinct([$before, $after].filter(|$row| $row != NONE).map(|$row|
        fn::impact_probe::interval($row.curve, $row.effective_at)));
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::impact_probe::point($row: object) {
    RETURN [fn::tree::member($row.id, 'z_point', $row.curve, 'z_points', $row.effective_at, { value: $row.value }, {}, {}, false)];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE impact_point SCHEMAFULL COMMENT '@rebase-members fn::impact_probe::point @rebase-impact fn::impact_probe::changed';
DEFINE FIELD OVERWRITE curve ON impact_point TYPE record<impact_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE effective_at ON impact_point TYPE datetime;
DEFINE FIELD OVERWRITE value ON impact_point TYPE decimal;
DEFINE FIELD OVERWRITE label ON impact_point TYPE option<string>;
DEFINE FIELD OVERWRITE z_point ON impact_point TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner impact_curve.z_points';

DEFINE TABLE OVERWRITE impact_total SCHEMAFULL;
DEFINE FIELD OVERWRITE z_history ON impact_total TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FUNCTION OVERWRITE fn::impact_probe::reader($row: object) {
    RETURN [fn::tree::member($row.id, 'z_reader', $row.curve, 'z_readers', $row.effective_at, {}, {}, {}, false),
        fn::tree::member($row.id, 'z_total', $row.total, 'z_history', $row.effective_at, { amount: $row.amount }, {}, {}, false)];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::impact_probe::validate($row: object) {
    IF $row.limit != NONE AND $row.amount > $row.limit { THROW 'IMPACT_PROBE_LIMIT'; };
} PERMISSIONS FULL;
DEFINE TABLE OVERWRITE impact_reader SCHEMAFULL COMMENT '@rebase-members fn::impact_probe::reader @rebase-validate fn::impact_probe::validate';
DEFINE FIELD OVERWRITE curve ON impact_reader TYPE record<impact_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE total ON impact_reader TYPE record<impact_total> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE effective_at ON impact_reader TYPE datetime;
DEFINE FIELD OVERWRITE quantity ON impact_reader TYPE decimal;
DEFINE FIELD OVERWRITE limit ON impact_reader TYPE option<decimal>;
DEFINE FIELD OVERWRITE rate ON impact_reader TYPE decimal VALUE fn::impact_probe::value_at($this.curve, $this.effective_at) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE amount ON impact_reader TYPE decimal VALUE $this.quantity * $this.rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_reader ON impact_reader TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner impact_curve.z_readers';
DEFINE FIELD OVERWRITE z_total ON impact_reader TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner impact_total.z_history';

DEFINE TABLE OVERWRITE impact_observer SCHEMAFULL;
DEFINE FIELD OVERWRITE source ON impact_observer TYPE record<impact_reader> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE amount ON impact_observer TYPE decimal VALUE $this.source.amount * 2dec COMMENT '@rebase-derived';
