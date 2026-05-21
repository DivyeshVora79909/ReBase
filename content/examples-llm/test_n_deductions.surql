DEFINE TABLE ledger SCHEMAFULL;
    DEFINE FIELD amount ON ledger TYPE decimal;
    DEFINE FIELD created_at ON ledger TYPE datetime DEFAULT time::now();

CREATE count:recompute SET view_updated_times = 0;

INSERT INTO ledger (<array> 1..=10000).map(|$i| {
    id: type::record('ledger', $i),
    amount: <decimal>($i % 100)
}) RETURN NONE;

DEFINE TABLE view_min_max AS
    SELECT
        "global" AS bucket,
        math::min(amount) AS lowest,
        math::max(amount) AS highest,
        count() AS total_records
    FROM ledger GROUP BY bucket;

DEFINE EVENT recompute_ping ON TABLE view_min_max WHEN $event = "UPDATE" THEN { UPDATE count:recompute SET view_updated_times += 1; };

CREATE ledger:x SET amount = 999dec; -- 6ms
count:recompute.view_updated_times; -- 1

CREATE ledger:y SET amount = -999dec; -- 1ms
count:recompute.view_updated_times; -- 2

UPDATE ledger:y SET amount = -999dec; -- 1ms
count:recompute.view_updated_times; -- 2

UPDATE ledger:x SET amount = 50dec; -- 300ms
count:recompute.view_updated_times; -- 3

UPDATE ledger:x SET created_at = time::now(); -- 1ms
count:recompute.view_updated_times; -- 3

UPDATE ledger:y SET created_at = time::now(); -- 1ms
count:recompute.view_updated_times; -- 3

DELETE ledger:x; -- 4ms
count:recompute.view_updated_times; --4

DELETE ledger:y; -- 300ms
count:recompute.view_updated_times; -- 5


DEFINE TABLE test SCHEMAFULL;
    DEFINE FIELD value_a ON test TYPE int;
    DEFINE FIELD value_b ON test TYPE int;
    DEFINE FIELD derived ON test TYPE bool VALUE value_a = value_b;

CREATE test:one SET value_a = 1, value_b = 1; -- true
UPDATE test:one SET value_a = 2; -- false
UPDATE test:one SET value_b = 2; -- true

-- DEDUCTIONS: VALUE clause executes on every write, VIEW only updates when derived value changes, so efficient for complex computations

DEFINE TABLE pulse SCHEMAFULL;
    DEFINE FIELD amount ON pulse TYPE decimal;
    DEFINE FIELD created_at ON pulse TYPE datetime DEFAULT time::now();

DEFINE TABLE pulse_view AS
    SELECT
        "one" AS bucket,
        math::min(amount) AS lowest,
        math::max(amount) AS highest,
        count() AS total_records
    FROM pulse GROUP BY bucket;

DEFINE EVENT probe_on_pulse ON TABLE pulse WHEN $event = "UPDATE" THEN {
    UPDATE clock_box:one SET n += 1;
    CREATE audit_line SET
        tag = "pulse_event",
        seq = (SELECT n FROM clock_box:one)[0].n,
        seen_lowest = (SELECT lowest FROM pulse_view)[0].lowest,
        seen_highest = (SELECT highest FROM pulse_view)[0].highest,
        seen_total = (SELECT total_records FROM pulse_view)[0].total_records,
        note = "source event";
};

DEFINE EVENT probe_on_view ON TABLE pulse_view WHEN $event = "UPDATE" THEN {
    UPDATE clock_box:one SET n += 1;
    CREATE audit_line SET
        tag = "view_event",
        seq = (SELECT n FROM clock_box:one)[0].n,
        seen_lowest = $after.lowest,
        seen_highest = $after.highest,
        seen_total = $after.total_records,
        note = "view event";
};

DEFINE TABLE audit_line SCHEMAFULL;
    DEFINE FIELD tag ON audit_line TYPE string;
    DEFINE FIELD seq ON audit_line TYPE int;
    DEFINE FIELD seen_lowest ON audit_line TYPE decimal;
    DEFINE FIELD seen_highest ON audit_line TYPE decimal;
    DEFINE FIELD seen_total ON audit_line TYPE int;
    DEFINE FIELD note ON audit_line TYPE string;
    DEFINE FIELD created_at ON audit_line TYPE datetime DEFAULT time::now();

DEFINE TABLE clock_box SCHEMAFULL;
    DEFINE FIELD n ON clock_box TYPE int;

CREATE clock_box:one SET n = 0;


CREATE pulse:one SET amount = 10dec;

UPDATE pulse:one SET amount = 99dec;

SELECT tag, seq, seen_lowest, seen_highest, seen_total, note FROM audit_line ORDER BY seq;
SELECT * FROM pulse_view;

-- ORDER OF EXECUTION: UPDATE pulse -> update pulse_view -> run pulse_view events -> run pulse events