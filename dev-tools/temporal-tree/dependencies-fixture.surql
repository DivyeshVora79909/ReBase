DEFINE TABLE OVERWRITE dep_curve SCHEMAFULL;
DEFINE FIELD OVERWRITE initial ON dep_curve TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE z_points ON dep_curve TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE dep_point SCHEMAFULL COMMENT '@rebase-members fn::dep_example::point';
DEFINE FIELD OVERWRITE curve ON dep_point TYPE record<dep_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON dep_point TYPE int;
DEFINE FIELD OVERWRITE amount ON dep_point TYPE decimal;
DEFINE FIELD OVERWRITE other ON dep_point TYPE decimal DEFAULT 0dec;
DEFINE FIELD OVERWRITE z_point ON dep_point TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner dep_curve.z_points';
DEFINE FUNCTION OVERWRITE fn::dep_example::point($row: object) {
    RETURN [fn::tree::ordered_member($row.id,'z_point',$row.curve,'z_points',[$row.at],{amount:$row.amount,other:$row.other},{})];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE dep_reader SCHEMAFULL COMMENT '@rebase-validate fn::dep_example::validate';
DEFINE FIELD OVERWRITE curve ON dep_reader TYPE record<dep_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON dep_reader TYPE int;
DEFINE FIELD OVERWRITE lower ON dep_reader TYPE option<int>;
DEFINE FIELD OVERWRITE upper ON dep_reader TYPE option<int>;
DEFINE FIELD OVERWRITE enabled ON dep_reader TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE limit ON dep_reader TYPE option<decimal>;

DEFINE FIELD OVERWRITE q_latest ON dep_reader TYPE option<object> FLEXIBLE
VALUE IF $this.enabled THEN {source:$this.curve,arguments:[[$this.at]],path:'measures.amount.sum',fallback:$this.curve.initial} ELSE NONE END
COMMENT '@rebase-dependency latest @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE q_next ON dep_reader TYPE option<object> FLEXIBLE
VALUE {source:$this.curve,arguments:[[$this.at]],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency next @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE q_exact ON dep_reader TYPE option<object> FLEXIBLE
VALUE {source:$this.curve,arguments:[$this.at],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency exact @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE q_prefix ON dep_reader TYPE option<object> FLEXIBLE
VALUE {source:$this.curve,arguments:[NONE,[$this.at]],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency range @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE q_range ON dep_reader TYPE option<object> FLEXIBLE
VALUE {source:$this.curve,arguments:[IF $this.lower=NONE THEN NONE ELSE [$this.lower] END,IF $this.upper=NONE THEN NONE ELSE [$this.upper] END],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency range @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE q_total ON dep_reader TYPE option<object> FLEXIBLE
VALUE {source:$this.curve,arguments:[NONE,NONE],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency range @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE q_guard ON dep_reader TYPE option<object> FLEXIBLE
VALUE IF $this.limit=NONE THEN NONE ELSE {source:$this.curve,arguments:[NONE,[$this.at]],path:'measures.amount.sum',fallback:0dec} END
COMMENT '@rebase-dependency range @rebase-dependency-source dep_curve.z_points @rebase-dependency-validate';

DEFINE FIELD OVERWRITE latest ON dep_reader TYPE decimal VALUE fn::dependency::value($this.q_latest)??0dec COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE next ON dep_reader TYPE decimal VALUE fn::dependency::value($this.q_next) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE exact ON dep_reader TYPE decimal VALUE fn::dependency::value($this.q_exact) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE prefix ON dep_reader TYPE decimal VALUE fn::dependency::value($this.q_prefix) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE segment ON dep_reader TYPE decimal VALUE fn::dependency::value($this.q_range) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE total ON dep_reader TYPE decimal VALUE fn::dependency::value($this.q_total) COMMENT '@rebase-derived';
DEFINE FUNCTION OVERWRITE fn::dep_example::validate($row: object) {
    IF $row.limit!=NONE AND fn::dependency::value($row.q_guard)>$row.limit { THROW 'DEPENDENCY_GUARD'; };
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE dep_child SCHEMAFULL;
DEFINE FIELD OVERWRITE source ON dep_child TYPE record<dep_reader> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE factor ON dep_child TYPE decimal DEFAULT 2dec;
DEFINE FIELD OVERWRITE amount ON dep_child TYPE decimal VALUE $this.source.latest*$this.factor COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE dep_join SCHEMAFULL;
DEFINE FIELD OVERWRITE first ON dep_join TYPE record<dep_child> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE second ON dep_join TYPE record<dep_child> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE amount ON dep_join TYPE decimal VALUE $this.first.amount+$this.second.amount COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE dep_feedback SCHEMAFULL COMMENT '@rebase-members fn::dep_example::feedback';
DEFINE FIELD OVERWRITE curve ON dep_feedback TYPE record<dep_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE q_total ON dep_feedback TYPE option<object> FLEXIBLE
VALUE {source:$this.curve,arguments:[NONE,NONE],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency range @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE amount ON dep_feedback TYPE decimal VALUE 1dec+fn::dependency::value($this.q_total) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_point ON dep_feedback TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner dep_curve.z_points';
DEFINE FUNCTION OVERWRITE fn::dep_example::feedback($row: object) {
    RETURN [fn::tree::ordered_member($row.id,'z_point',$row.curve,'z_points',[0],{amount:$row.amount},{})];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE dep_book SCHEMAFULL;
DEFINE FIELD OVERWRITE base ON dep_book TYPE decimal;
DEFINE FIELD OVERWRITE z_changes ON dep_book TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int @rebase-tree-duplicates';
DEFINE TABLE OVERWRITE dep_adjustment SCHEMAFULL COMMENT '@rebase-members fn::dep_example::adjustment';
DEFINE FIELD OVERWRITE book ON dep_adjustment TYPE record<dep_book> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON dep_adjustment TYPE int;
DEFINE FIELD OVERWRITE target ON dep_adjustment TYPE decimal;
DEFINE FIELD OVERWRITE q_before ON dep_adjustment TYPE option<object> FLEXIBLE
VALUE {source:$this.book,arguments:[NONE,[$this.at]],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency range @rebase-dependency-source dep_book.z_changes';
DEFINE FIELD OVERWRITE delta ON dep_adjustment TYPE decimal VALUE $this.target-$this.book.base-fn::dependency::value($this.q_before) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_change ON dep_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner dep_book.z_changes';
DEFINE FUNCTION OVERWRITE fn::dep_example::adjustment($row: object) {
    RETURN [fn::tree::ordered_member($row.id,'z_change',$row.book,'z_changes',[$row.at],{amount:$row.delta},{})];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE dep_moment SCHEMAFULL;
DEFINE FIELD OVERWRITE at ON dep_moment TYPE int;
DEFINE TABLE OVERWRITE dep_scheduled SCHEMAFULL COMMENT '@rebase-members fn::dep_example::adjustment';
DEFINE FIELD OVERWRITE book ON dep_scheduled TYPE record<dep_book> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE moment ON dep_scheduled TYPE record<dep_moment> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE target ON dep_scheduled TYPE decimal;
DEFINE FIELD OVERWRITE at ON dep_scheduled TYPE int VALUE $this.moment.at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE q_before ON dep_scheduled TYPE option<object> FLEXIBLE
VALUE {source:$this.book,arguments:[NONE,[$this.at]],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency range @rebase-dependency-source dep_book.z_changes';
DEFINE FIELD OVERWRITE delta ON dep_scheduled TYPE decimal VALUE $this.target-$this.book.base-fn::dependency::value($this.q_before) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_change ON dep_scheduled TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner dep_book.z_changes';
