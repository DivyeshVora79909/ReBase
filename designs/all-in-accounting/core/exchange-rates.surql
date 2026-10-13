-- Authoritative dated rates are independent of observed trade prices.
DEFINE FUNCTION OVERWRITE fn::accounting::pair_validate($row: object) {
    IF $row.given_resource = $row.received_resource { THROW 'EXCHANGE_IDENTICAL_RESOURCES'; };
    IF $row.z_rates.summary.count > 0 AND $row.z_rates.summary.first[0] < $row.effective_at { THROW 'RATE_BEFORE_PAIR'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::pair_matches($pair: option<record>, $from: record, $to: record) {
    IF $from = $to { IF $pair != NONE { THROW 'IDENTITY_RATE_HAS_PAIR'; }; RETURN NONE; };
    IF $pair = NONE OR $pair.given_resource != $from OR $pair.received_resource != $to { THROW 'EXCHANGE_PAIR_DIMENSIONS'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::rate_at($pair: option<record>, $from: record, $to: record, $at: datetime) {
    fn::accounting::pair_matches($pair,$from,$to);
    IF $from = $to { RETURN 1dec; };
    LET $context = SELECT * FROM ONLY $pair;
    IF $context = NONE OR $at < $context.effective_at { THROW 'RATE_NOT_EFFECTIVE'; };
    LET $link = fn::tree::read($pair,'z_rates','seek',[[$at+1ns],true,false]);
    RETURN IF $link = NONE THEN $context.initial_rate ELSE (SELECT VALUE rate FROM ONLY $link.rid) END;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::rate_interval($pair: record, $at: datetime) {
    LET $next = fn::tree::seek({rid:$pair,slot:'z_rates'},[$at+1ns],false,true);
    RETURN {owner:{rid:$pair,slot:'z_readers'},lower:[$at],upper:IF $next=NONE THEN NONE ELSE [fn::tree::get($next).key[0]] END};
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::rate_impact($before: option<object>, $after: option<object>) {
    IF $before.pair=$after.pair AND $before.effective_at=$after.effective_at AND $before.rate=$after.rate { RETURN []; };
    RETURN array::distinct([$before,$after].filter(|$r|$r!=NONE).map(|$r|fn::accounting::rate_interval($r.pair,$r.effective_at)));
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::pair_impact($before: option<object>, $after: option<object>) {
    IF $before=NONE OR $after=NONE { RETURN []; };
    IF $before.effective_at!=$after.effective_at {
        RETURN [{owner:{rid:$after.id,slot:'z_readers'},lower:NONE,upper:NONE}];
    };
    IF $before.initial_rate=$after.initial_rate { RETURN []; };
    LET $first=fn::tree::select({rid:$after.id,slot:'z_rates'},1,false);
    RETURN [{owner:{rid:$after.id,slot:'z_readers'},lower:NONE,upper:IF $first=NONE THEN NONE ELSE [fn::tree::get($first).key[0]] END}];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::rate_members($row: object) {
    RETURN [fn::tree::member($row.id,'z_pair',$row.pair,'z_rates',$row.effective_at,{rate:$row.rate},{},{},false)];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::rate_validate($row: object) {
    IF $row.effective_at<$row.pair.effective_at { THROW 'RATE_BEFORE_PAIR'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE exchange_pair SCHEMAFULL COMMENT '@rebase-validate fn::accounting::pair_validate @rebase-impact fn::accounting::pair_impact';

DEFINE FIELD OVERWRITE given_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE received_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE initial_rate ON exchange_pair TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON exchange_pair TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON exchange_pair TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_rates ON exchange_pair TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FIELD OVERWRITE z_readers ON exchange_pair TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_observations ON exchange_pair TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE INDEX OVERWRITE exchange_pair_identity ON exchange_pair FIELDS tenant,given_resource,received_resource UNIQUE;

DEFINE TABLE OVERWRITE exchange_rate SCHEMAFULL COMMENT '@rebase-members fn::accounting::rate_members @rebase-validate fn::accounting::rate_validate @rebase-impact fn::accounting::rate_impact';

DEFINE FIELD OVERWRITE pair ON exchange_rate TYPE record<exchange_pair> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON exchange_rate TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE rate ON exchange_rate TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON exchange_rate TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_pair ON exchange_rate TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_rates';
