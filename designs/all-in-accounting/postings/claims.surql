DEFINE FUNCTION OVERWRITE fn::accounting::claim_validate($row: object) {
    fn::accounting::precision_validate($row.amount,$row.resource);
    IF ($row.z_capacity.summary.measures.remaining.instant_min??0dec)<0dec { THROW 'CLAIM_SETTLEMENT_CAPACITY'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::claim_members($row: object) {
    LET $r=$row.claim_kind='receivable';
    RETURN array::concat(fn::accounting::post($row,'z_account',$row.account,$row.effective_at,
        object::extend(fn::accounting::claim(IF $r THEN $row.amount ELSE -$row.amount END),
            {credit_available:IF $r THEN $row.amount ELSE 0dec END,liability_available:IF $r THEN 0dec ELSE $row.amount END})),[
        fn::tree::member($row.id,'z_self',$row.id,'z_capacity',$row.effective_at,{remaining:$row.amount},{},{},false)]);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::claim_settlement_validate($row: object) {
    fn::accounting::same_subsidiary($row.account,$row.paid_account);
    IF $row.effective_at<$row.source_at { THROW 'CLAIM_BEFORE_SOURCE'; };
    fn::accounting::precision_validate($row.amount,$row.paid_resource);
    IF $row.account_amount<=0dec { THROW 'CLAIM_SETTLEMENT_ZERO'; };
    fn::accounting::fee_validate($row);
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::claim_settlement_members($row: object) {
    LET $claim_r=$row.claim_kind='receivable';
    LET $counterparty=$row.organization!=NONE;
    LET $receive=IF $counterparty THEN !$claim_r ELSE $claim_r END;
    LET $real=IF $receive THEN $row.amount ELSE -$row.amount END;
    LET $other_real=IF $receive THEN -$row.account_amount ELSE $row.account_amount END;
    RETURN array::concat(fn::accounting::post($row,'z_paid',$row.paid_account,$row.effective_at,fn::accounting::effects($real,0dec,0dec)),
        fn::accounting::post($row,'z_account',$row.account,$row.effective_at,
            object::extend(fn::accounting::claim(IF $claim_r THEN -$row.account_amount ELSE $row.account_amount END),
                {real:$other_real,credit_available:IF $claim_r THEN -$row.account_amount ELSE 0dec END,liability_available:IF $claim_r THEN 0dec ELSE -$row.account_amount END})),[
        fn::tree::member($row.id,'z_source',$row.source,'z_capacity',$row.effective_at,{remaining:-$row.account_amount},{},{},false),
        fn::tree::member($row.id,'z_fx',$row.exchange_pair,'z_readers',$row.effective_at,{},{},{},false)],fn::accounting::fee_members($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE account_claim SCHEMAFULL COMMENT '@rebase-members fn::accounting::claim_members @rebase-validate fn::accounting::claim_validate';

DEFINE FIELD OVERWRITE account ON account_claim TYPE record<organization_currency_account | organization_resource_account | direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE resource ON account_claim TYPE record<currency | item | service> REFERENCE ON DELETE REJECT VALUE $this.account.resource COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE effective_at ON account_claim TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON account_claim TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE claim_kind ON account_claim TYPE string ASSERT $value IN ['receivable','payable'] COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON account_claim TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_capacity ON account_claim TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_account ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history @rebase-tree-owner organization_resource_account.z_history @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_account_subsidiary ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_account_sub_rate ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_account_organization ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_account_org_rate ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_self ON account_claim TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner account_claim.z_capacity';

DEFINE TABLE OVERWRITE claim_settlement SCHEMAFULL COMMENT '@rebase-members fn::accounting::claim_settlement_members @rebase-validate fn::accounting::claim_settlement_validate';

DEFINE FIELD OVERWRITE source ON claim_settlement TYPE record<account_claim> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE paid_account ON claim_settlement TYPE record<treasury | misc_currency_account | stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE exchange_pair ON claim_settlement TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE amount ON claim_settlement TYPE decimal ASSERT $value>0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON claim_settlement TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON claim_settlement TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE account ON claim_settlement TYPE record<organization_currency_account | organization_resource_account | direct_tax_account | indirect_tax_account> REFERENCE ON DELETE REJECT VALUE $this.source.account COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE resource ON claim_settlement TYPE record<currency | item | service> REFERENCE ON DELETE REJECT VALUE $this.source.resource COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE paid_resource ON claim_settlement TYPE record<currency | item | service> REFERENCE ON DELETE REJECT VALUE $this.paid_account.resource COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization ON claim_settlement TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE $this.account.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE source_at ON claim_settlement TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE claim_kind ON claim_settlement TYPE string VALUE $this.source.claim_kind COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE exchange_rate ON claim_settlement TYPE decimal VALUE fn::accounting::rate_at($this.exchange_pair,$this.paid_resource,$this.resource,$this.effective_at) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE account_amount ON claim_settlement TYPE decimal VALUE fn::accounting::quantize($this.amount*$this.exchange_rate,$this.resource) COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE z_account ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization_currency_account.z_history @rebase-tree-owner organization_resource_account.z_history @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE z_account_subsidiary ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_account_sub_rate ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_account_organization ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE FIELD OVERWRITE z_account_org_rate ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_paid ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';

DEFINE FIELD OVERWRITE z_paid_subsidiary ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_paid_sub_rate ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';

DEFINE FIELD OVERWRITE z_source ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner account_claim.z_capacity';

DEFINE FIELD OVERWRITE z_fx ON claim_settlement TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_readers @rebase-tree-no-reader';
