REMOVE TABLE IF EXISTS target;
REMOVE TABLE IF EXISTS doc;

DEFINE TABLE target SCHEMAFULL;

DEFINE TABLE doc SCHEMAFULL;
    DEFINE FIELD level1 ON doc TYPE option<array<object>>;
    DEFINE FIELD level1.*.ref1 ON doc TYPE option<record<target>>;
    DEFINE FIELD level1.*.level2 ON doc TYPE option<array<object>>;
    DEFINE FIELD level1.*.level2.*.ref2 ON doc TYPE option<record<target>>;
    DEFINE FIELD shadow_l1 ON doc TYPE set<record<target>>
        VALUE <set> (level1.ref1 ??[]).flatten().filter(|$v| $v != NONE)
        REFERENCE ON DELETE REJECT;
    DEFINE FIELD shadow_l2 ON doc TYPE set<record<target>>
        VALUE <set> (level1.level2.ref2 ??[]).flatten().filter(|$v| $v != NONE)
        REFERENCE ON DELETE REJECT;

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

-- RESULT
SELECT * FROM doc:test;
DELETE target:second_level_x;
DELETE target:first_level_a;


"
[
	{
		id: doc:test,
		level1: [
			{
				level2: [
					{
						ref2: target:second_level_x
					},
					{
						ref2: target:second_level_x
					}
				],
				ref1: target:first_level_a
			}
		],
		shadow_l1: {target:first_level_a,},
		shadow_l2: {target:second_level_x,}
	}
]

'Cannot delete `target:second_level_x` as it is referenced by `doc:test` with an ON DELETE REJECT clause'

'Cannot delete `target:first_level_a` as it is referenced by `doc:test` with an ON DELETE REJECT clause'
"