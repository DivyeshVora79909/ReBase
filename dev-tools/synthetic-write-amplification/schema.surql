DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL;

DEFINE TABLE OVERWRITE stress_owner SCHEMAFULL;
DEFINE FIELD OVERWRITE z_book ON stress_owner TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE stress_rule SCHEMAFULL;
DEFINE FIELD OVERWRITE a_rate ON stress_rule TYPE decimal;

DEFINE TABLE OVERWRITE stress_fact SCHEMAFULL COMMENT '@rebase-members fn::stress::members';
DEFINE FIELD OVERWRITE a_kind ON stress_fact TYPE string;
DEFINE FIELD OVERWRITE a_sequence ON stress_fact TYPE int;
DEFINE FIELD OVERWRITE a_amount ON stress_fact TYPE decimal;
DEFINE FIELD OVERWRITE a_effective_at ON stress_fact TYPE datetime;
DEFINE FIELD OVERWRITE a_rule ON stress_fact TYPE record<stress_rule> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_01 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_02 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_03 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_04 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_05 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_06 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_07 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_08 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_09 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner_10 ON stress_fact TYPE record<stress_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE z11_rate ON stress_fact TYPE decimal VALUE $this.a_rule.a_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z12_amount ON stress_fact TYPE decimal VALUE $this.z11_rate * $this.a_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z01_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z02_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z03_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z04_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z05_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z06_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z07_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z08_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z09_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';
DEFINE FIELD OVERWRITE z10_leg ON stress_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stress_owner.z_book';

DEFINE FUNCTION OVERWRITE fn::stress::members($row: option<object>) {
    IF $row = NONE { RETURN []; };
    RETURN [
        fn::tree::member($row.id, 'z01_leg', $row.a_owner_01, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 1) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z02_leg', $row.a_owner_02, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 2) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z03_leg', $row.a_owner_03, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 3) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z04_leg', $row.a_owner_04, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 4) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z05_leg', $row.a_owner_05, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 5) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z06_leg', $row.a_owner_06, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 6) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z07_leg', $row.a_owner_07, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 7) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z08_leg', $row.a_owner_08, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 8) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z09_leg', $row.a_owner_09, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 9) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false),
        fn::tree::member($row.id, 'z10_leg', $row.a_owner_10, 'z_book', $row.a_effective_at, { amount: IF (($row.a_sequence + 10) % 2) = 0 THEN $row.z12_amount ELSE -$row.z12_amount END }, {}, {}, false)
    ];
} PERMISSIONS NONE;
