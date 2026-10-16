-- Authoritative dated rates are independent of observed trade prices.
DEFINE FUNCTION OVERWRITE fn::accounting::pair_validate($row: object) {
    IF $row.given_resource = $row.received_resource { THROW 'EXCHANGE_IDENTICAL_RESOURCES'; };
    IF $row.z_rates.summary.count > 0 AND $row.z_rates.summary.first[0] < $row.effective_at { THROW 'RATE_BEFORE_PAIR'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::pair_matches($pair: option<record>, $from: record, $to: record) {
    IF $from = $to { IF $pair != NONE { THROW 'IDENTITY_RATE_HAS_PAIR'; }; RETURN NONE; };
    IF $pair = NONE OR $pair.given_resource != $from OR $pair.received_resource != $to { THROW 'EXCHANGE_PAIR_DIMENSIONS'; };
} PERMISSIONS FULL;

-- A pure descriptor; the declaration supplies the source root and operation.
DEFINE FUNCTION OVERWRITE fn::accounting::rate_query($pair: option<record>, $from: record, $to: record, $at: datetime) {
    fn::accounting::pair_matches($pair,$from,$to);
    IF $from = $to { RETURN NONE; };
    LET $source = SELECT * FROM ONLY $pair;
    IF $source.effective_at = NONE OR $at < $source.effective_at { THROW 'RATE_NOT_EFFECTIVE'; };
    RETURN {source:$pair,arguments:[[$at+1ns]],path:'measures.rate.sum',fallback:$source.initial_rate};
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::rate_members($row: object) {
    RETURN [fn::tree::member($row.id,'z_pair',$row.pair,'z_rates',$row.effective_at,{rate:$row.rate},{},{})];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::rate_validate($row: object) {
    IF $row.effective_at<$row.pair.effective_at { THROW 'RATE_BEFORE_PAIR'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE exchange_pair SCHEMAFULL COMMENT '@rebase-members fn::accounting::identity_members @rebase-validate fn::accounting::pair_validate';

DEFINE FIELD OVERWRITE given_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE received_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE initial_rate ON exchange_pair TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON exchange_pair TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON exchange_pair TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_rates ON exchange_pair TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FIELD OVERWRITE z_observations ON exchange_pair TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';


DEFINE TABLE OVERWRITE exchange_rate SCHEMAFULL COMMENT '@rebase-members fn::accounting::rate_members @rebase-validate fn::accounting::rate_validate';

DEFINE FIELD OVERWRITE pair ON exchange_rate TYPE record<exchange_pair> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON exchange_rate TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE rate ON exchange_rate TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON exchange_rate TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_pair ON exchange_rate TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_rates';
