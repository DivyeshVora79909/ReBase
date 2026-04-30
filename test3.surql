REMOVE DATABASE test;
DEFINE DATABASE test;
USE NS test DB test;

DEFINE TABLE target SCHEMAFULL;
DEFINE TABLE doc SCHEMAFULL;

-- Level 1
DEFINE FIELD level1 ON doc TYPE option<array<object>>;
DEFINE FIELD level1.*.ref1 ON doc TYPE option<record<target>>;

-- Level 2
DEFINE FIELD level1.*.level2 ON doc TYPE option<array<object>>;
DEFINE FIELD level1.*.level2.*.ref2 ON doc TYPE option<record<target>>;

DEFINE FIELD shadow_l1 ON doc TYPE set<record<target>>
    VALUE <set> (level1.ref1 ??[]).flatten().filter(|$v| $v != NONE)
    REFERENCE ON DELETE REJECT;

DEFINE FIELD shadow_l2 ON doc TYPE set<record<target>>
    VALUE <set> (level1.level2.ref2 ??[]).flatten().filter(|$v| $v != NONE)
    REFERENCE ON DELETE REJECT;

-- TEST
CREATE target:first_level_a;
CREATE target:second_level_x;

CREATE doc:test SET level1 =[
    {
        ref1: target:first_level_a,
        level2:[
            { ref2: target:second_level_x },
            { ref2: target:second_level_x }
        ]
    }
];

-- VERIFY
SELECT * FROM doc:test;
DELETE target:second_level_x;
DELETE target:first_level_a;

