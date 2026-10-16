DEFINE TABLE OVERWRITE interval_book SCHEMAFULL;
DEFINE FIELD OVERWRITE z_ranges ON interval_book TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE interval_item SCHEMAFULL COMMENT '@rebase-members fn::interval_example::members';
DEFINE FIELD OVERWRITE book ON interval_item TYPE record<interval_book> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE lower ON interval_item TYPE int;
DEFINE FIELD OVERWRITE upper ON interval_item TYPE option<int>;
DEFINE FIELD OVERWRITE amount ON interval_item TYPE decimal;
DEFINE FIELD OVERWRITE z_range ON interval_item TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner interval_book.z_ranges';
DEFINE FIELD OVERWRITE extra_upper ON interval_item TYPE option<int>;
DEFINE FIELD OVERWRITE extra_amount ON interval_item TYPE option<decimal>;
DEFINE FIELD OVERWRITE z_extra ON interval_item TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner interval_book.z_ranges';

DEFINE FUNCTION OVERWRITE fn::interval_example::members($row: object) {
    RETURN array::concat([fn::tree::interval_member($row.id, 'z_range', $row.book, 'z_ranges', [$row.lower],
        IF $row.upper = NONE THEN NONE ELSE [$row.upper] END, { amount: $row.amount }, {})],
        IF $row.extra_amount = NONE THEN [] ELSE [
            fn::tree::interval_member($row.id, 'z_extra', $row.book, 'z_ranges', [$row.lower],
                IF $row.extra_upper = NONE THEN NONE ELSE [$row.extra_upper] END, { amount: $row.extra_amount }, {})
        ] END);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE interval_reader SCHEMAFULL;
DEFINE FIELD OVERWRITE book ON interval_reader TYPE record<interval_book> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE q_measures ON interval_reader TYPE option<object> FLEXIBLE
VALUE { source: $this.book, arguments: [NONE, NONE], path: 'measures', fallback: {} }
COMMENT '@rebase-dependency range @rebase-dependency-source interval_book.z_ranges';
DEFINE FIELD OVERWRITE q_upper ON interval_reader TYPE option<object> FLEXIBLE
VALUE { source: $this.book, arguments: [NONE, NONE], path: 'interval.upper', fallback: [] }
COMMENT '@rebase-dependency range @rebase-dependency-source interval_book.z_ranges';
DEFINE FIELD OVERWRITE measures ON interval_reader TYPE object FLEXIBLE
VALUE fn::dependency::value($this.q_measures) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE upper ON interval_reader TYPE array
VALUE fn::dependency::value($this.q_upper) COMMENT '@rebase-derived';
