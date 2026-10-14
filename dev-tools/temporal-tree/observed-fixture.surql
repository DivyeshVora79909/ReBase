-- A formula is the only dependency declaration. No impact functions/read slots.
DEFINE TABLE OVERWRITE read_curve SCHEMAFULL;
DEFINE FIELD OVERWRITE initial ON read_curve TYPE decimal;
DEFINE FIELD OVERWRITE z_points ON read_curve TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE published ON read_curve TYPE decimal COMPUTED $this.z_points.summary.measures.value.sum ?? 0dec;

DEFINE FUNCTION OVERWRITE fn::read_probe::point($row: object) {
    RETURN [fn::tree::ordered_member($row.id, 'z_point', $row.curve, 'z_points', [$row.at], { value: $row.value, other: $row.other }, {})];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE read_point SCHEMAFULL COMMENT '@rebase-members fn::read_probe::point';
DEFINE FIELD OVERWRITE curve ON read_point TYPE record<read_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON read_point TYPE int;
DEFINE FIELD OVERWRITE value ON read_point TYPE decimal;
DEFINE FIELD OVERWRITE other ON read_point TYPE decimal DEFAULT 0dec;
DEFINE FIELD OVERWRITE label ON read_point TYPE option<string>;
DEFINE FIELD OVERWRITE z_point ON read_point TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner read_curve.z_points';

DEFINE FUNCTION OVERWRITE fn::read_probe::lookup($row: object) {
    IF $row.disabled { RETURN 0dec; };
    LET $args = IF $row.operation IN ['latest', 'next'] THEN [[$row.at]]
        ELSE IF $row.operation = 'range' THEN [[$row.at], [$row.until]]
        ELSE IF $row.operation = 'summary' THEN [] ELSE [$row.at] END;
    LET $value = fn::tree::read_value($row.curve, 'z_points', $row.operation, $args, 'measures.value.sum',
        IF $row.operation IN ['latest', 'next', 'exact'] THEN NONE ELSE 0dec END);
    RETURN IF $value = NONE THEN fn::record::read_value($row.curve, 'initial', 0dec) ELSE $value END;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::read_probe::nested($row: object) {
    RETURN fn::read_probe::lookup($row);
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::read_probe::validate($row: object) {
    IF $row.limit != NONE AND $row.amount > $row.limit { THROW 'READ_PROBE_LIMIT'; };
    IF $row.guard != NONE AND fn::tree::read_value($row.curve, 'z_points', 'before', [$row.at], 'measures.value.sum', 0dec) > $row.guard {
        THROW 'READ_PROBE_GUARD';
    };
} PERMISSIONS FULL;
DEFINE TABLE OVERWRITE read_reader SCHEMAFULL COMMENT '@rebase-validate fn::read_probe::validate';
DEFINE FIELD OVERWRITE curve ON read_reader TYPE record<read_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON read_reader TYPE int;
DEFINE FIELD OVERWRITE until ON read_reader TYPE int DEFAULT 100;
DEFINE FIELD OVERWRITE operation ON read_reader TYPE string ASSERT $value IN ['latest', 'next', 'before', 'range', 'exact', 'summary'];
DEFINE FIELD OVERWRITE disabled ON read_reader TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE quantity ON read_reader TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE limit ON read_reader TYPE option<decimal>;
DEFINE FIELD OVERWRITE guard ON read_reader TYPE option<decimal>;
-- Deliberately disagree with alphabetic field order.
DEFINE FIELD OVERWRITE z_rate ON read_reader TYPE decimal VALUE fn::read_probe::nested($this) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_again ON read_reader TYPE decimal VALUE fn::read_probe::nested($this) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE a_amount ON read_reader TYPE decimal VALUE $this.quantity * $this.z_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE amount ON read_reader TYPE decimal VALUE $this.a_amount COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE read_observer SCHEMAFULL;
DEFINE FIELD OVERWRITE source ON read_observer TYPE record<read_reader> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE amount ON read_observer TYPE decimal VALUE $this.source.amount * 2dec COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE read_publication SCHEMAFULL;
DEFINE FIELD OVERWRITE curve ON read_publication TYPE record<read_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE published ON read_publication TYPE decimal VALUE fn::record::read_value($this.curve,'published',0dec) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE current ON read_publication TYPE decimal VALUE fn::record::read_value($this.curve,'z_points.summary.measures.value.sum',0dec) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE ranges ON read_publication TYPE array VALUE [
    fn::tree::read_value($this.curve,'z_points','range',[[0],[8]],'measures.value.sum',0dec),
    fn::tree::read_value($this.curve,'z_points','range',[[8],[30]],'measures.value.sum',0dec),
    fn::tree::read_value($this.curve,'z_points','range',[[0],[8]],'measures.value.sum',0dec)
] COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE selection ON read_publication TYPE object FLEXIBLE VALUE
    fn::tree::read_value($this.curve,'z_points','latest',[[100]],'',{}) COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE read_book SCHEMAFULL;
DEFINE FIELD OVERWRITE base ON read_book TYPE decimal;
DEFINE FIELD OVERWRITE z_adjustments ON read_book TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int';
DEFINE FUNCTION OVERWRITE fn::read_probe::adjust($row: object) {
    RETURN [fn::tree::ordered_member($row.id, 'z_delta', $row.book, 'z_adjustments', [$row.at], { quantity: $row.delta }, {})];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE read_adjustment SCHEMAFULL COMMENT '@rebase-members fn::read_probe::adjust';
DEFINE FIELD OVERWRITE book ON read_adjustment TYPE record<read_book> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON read_adjustment TYPE int;
DEFINE FIELD OVERWRITE target ON read_adjustment TYPE decimal;
DEFINE FIELD OVERWRITE delta ON read_adjustment TYPE decimal VALUE $this.target - (
    fn::record::read_value($this.book, 'base', 0dec) + fn::tree::read_value($this.book, 'z_adjustments', 'before', [$this.at], 'measures.quantity.sum', 0dec)
) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_delta ON read_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner read_book.z_adjustments';

DEFINE TABLE OVERWRITE read_feedback SCHEMAFULL;
DEFINE FIELD OVERWRITE peer ON read_feedback TYPE option<record<read_feedback>> REFERENCE ON DELETE UNSET;
DEFINE FIELD OVERWRITE value ON read_feedback TYPE decimal VALUE IF $this.peer = NONE THEN 1dec
    ELSE 1dec + fn::record::read_value($this.peer, 'value', 0dec) END COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE read_dates SCHEMAFULL;
DEFINE FIELD OVERWRITE initial ON read_dates TYPE decimal;
DEFINE FIELD OVERWRITE z_rates ON read_dates TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FUNCTION OVERWRITE fn::read_probe::dated($row: object) {
    RETURN [fn::tree::member($row.id,'z_rate',$row.curve,'z_rates',$row.at,{rate:$row.rate},{},{},false)];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE read_quote SCHEMAFULL COMMENT '@rebase-members fn::read_probe::dated';
DEFINE FIELD OVERWRITE curve ON read_quote TYPE record<read_dates> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON read_quote TYPE datetime;
DEFINE FIELD OVERWRITE rate ON read_quote TYPE decimal;
DEFINE FIELD OVERWRITE z_rate ON read_quote TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner read_dates.z_rates';
DEFINE TABLE OVERWRITE read_dated SCHEMAFULL;
DEFINE FIELD OVERWRITE curve ON read_dated TYPE record<read_dates> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON read_dated TYPE datetime;
DEFINE FIELD OVERWRITE rate ON read_dated TYPE decimal VALUE
    fn::tree::read_value($this.curve,'z_rates','latest',[[$this.at+1ns]],'measures.rate.sum',
        fn::record::read_value($this.curve,'initial',0dec)) COMMENT '@rebase-derived';
