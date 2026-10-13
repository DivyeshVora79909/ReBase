DEFINE FUNCTION OVERWRITE fn::accounting::report_validate($row: object) {
    LET $s=$row.z_history.summary;
    IF $s.count>0 AND (!$s.tags.currency.uniform OR $s.tags.currency.value!=$row.currency) { THROW 'REPORTING_CURRENCY'; };
    IF $s.count>0 AND $s.first[0]<$row.effective_at { THROW 'ACCOUNT_NOT_EFFECTIVE'; };
    IF $row.net_floor!=NONE AND ($s.measures.net.instant_min??0dec)<$row.net_floor { THROW 'ACCOUNT_NET_FLOOR'; };
    IF $row.net_ceiling!=NONE AND ($s.measures.net.instant_max??0dec)>$row.net_ceiling { THROW 'ACCOUNT_NET_CEILING'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::organization_members($row: object) {
    RETURN [fn::tree::ordered_member($row.id,'z_subsidiary',$row.subsidiary,'z_organizations',[$row.name],{},{})];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::operating_validate($row: object) {
    IF ($row.z_capacity.summary.measures.used.instant_min??0dec)<0dec { THROW 'CAPACITY_NEGATIVE'; };
    IF $row.capacity!=NONE AND ($row.z_capacity.summary.measures.used.instant_max??0dec)>$row.capacity { THROW 'OPERATING_CAPACITY'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::account_members($row: object) {
    RETURN [fn::tree::ordered_member($row.id,'z_subsidiary',$row.subsidiary,'z_accounts',[$row.resource],{},{}),
        IF $row.organization=NONE THEN NONE ELSE fn::tree::ordered_member($row.id,'z_organization',$row.organization,'z_accounts',[$row.resource],{},{}) END,
        IF record::tb($row.id)!='stock_account' THEN NONE ELSE fn::tree::ordered_member($row.id,'z_identity',$row.operating_unit,'z_stock_keys',[$row.resource],{},{}) END];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::account_validate($row: object) {
    fn::accounting::pair_matches($row.valuation_pair,$row.resource,$row.reporting_currency);
    IF $row.organization!=NONE {
        fn::accounting::same_subsidiary($row.id,$row.organization);
        fn::accounting::pair_matches($row.organization_pair,$row.resource,$row.organization_currency);
    };
    IF $row.operating_unit!=NONE { fn::accounting::same_subsidiary($row.id,$row.operating_unit); };
    LET $s=$row.z_history.summary;
    IF $s.count>0 AND (!$s.tags.resource.uniform OR $s.tags.resource.value!=$row.resource OR !$s.tags.subsidiary.uniform OR $s.tags.subsidiary.value!=$row.subsidiary) { THROW 'ACCOUNT_DIMENSIONS'; };
    IF $s.count>0 AND $s.first[0]<$row.effective_at { THROW 'ACCOUNT_NOT_EFFECTIVE'; };
    IF ($s.measures.receivable.min??0dec)<0dec OR ($s.measures.payable.min??0dec)<0dec { THROW 'ACCOUNTING_NEGATIVE_DIRECTION'; };
    IF $row.organization=NONE AND !(record::tb($row.id) IN ['direct_tax_account','indirect_tax_account']) {
        IF ($s.measures.receivable.sum??0dec)!=0dec OR ($s.measures.payable.sum??0dec)!=0dec { THROW 'OWNED_ACCOUNT_REAL_ONLY'; };
    };
    IF record::tb($row.id) IN ['direct_tax_account','indirect_tax_account'] {
        IF ($s.measures.credit_available.instant_min??0dec)<0dec OR ($s.measures.liability_available.instant_min??0dec)<0dec { THROW 'TAX_CLAIM_CAPACITY'; };
    };
    FOR $name IN ['real','available'] {
        IF $row['minimum_'+$name]!=NONE AND ($s.measures[$name].instant_min??0dec)<$row['minimum_'+$name] { THROW 'ACCOUNT_BALANCE_FLOOR'; };
    };
    IF $row.net_floor!=NONE AND ($s.measures.net.instant_min??0dec)<$row.net_floor { THROW 'ACCOUNT_NET_FLOOR'; };
    IF $row.net_ceiling!=NONE AND ($s.measures.net.instant_max??0dec)>$row.net_ceiling { THROW 'ACCOUNT_NET_CEILING'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE subsidiary SCHEMAFULL COMMENT '@rebase-validate fn::accounting::report_validate';

DEFINE FIELD OVERWRITE name ON subsidiary TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency ON subsidiary TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON subsidiary TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON subsidiary TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_accounts ON subsidiary TYPE object COMMENT '@rebase-tree-root @rebase-tree-key record @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_organizations ON subsidiary TYPE object COMMENT '@rebase-tree-root @rebase-tree-key string @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE net_floor ON subsidiary TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON subsidiary TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE organization SCHEMAFULL COMMENT '@rebase-members fn::accounting::organization_members @rebase-validate fn::accounting::report_validate';

DEFINE FIELD OVERWRITE name ON organization TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON organization TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE currency ON organization TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON organization TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON organization TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_accounts ON organization TYPE object COMMENT '@rebase-tree-root @rebase-tree-key record';

DEFINE FIELD OVERWRITE z_subsidiary ON organization TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key string @rebase-tree-owner subsidiary.z_organizations';

DEFINE FIELD OVERWRITE net_floor ON organization TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON organization TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE operating_unit SCHEMAFULL COMMENT '@rebase-validate fn::accounting::operating_validate';

DEFINE FIELD OVERWRITE name ON operating_unit TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON operating_unit TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE capacity ON operating_unit TYPE option<decimal> ASSERT $value=NONE OR $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_capacity ON operating_unit TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_stock_keys ON operating_unit TYPE object COMMENT '@rebase-tree-root @rebase-tree-key record';

DEFINE TABLE OVERWRITE treasury SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON treasury TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON treasury TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON treasury TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON treasury TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE NONE COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON treasury TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE resource ON treasury TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE reporting_currency ON treasury TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON treasury TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON treasury TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON treasury TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON treasury TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON treasury TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON treasury TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON treasury TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';

DEFINE TABLE OVERWRITE misc_currency_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON misc_currency_account TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON misc_currency_account TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON misc_currency_account TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON misc_currency_account TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE NONE COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON misc_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE resource ON misc_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE reporting_currency ON misc_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON misc_currency_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON misc_currency_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON misc_currency_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';

DEFINE TABLE OVERWRITE direct_tax_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON direct_tax_account TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON direct_tax_account TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON direct_tax_account TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON direct_tax_account TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE NONE COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON direct_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE resource ON direct_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE reporting_currency ON direct_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON direct_tax_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON direct_tax_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON direct_tax_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';

DEFINE TABLE OVERWRITE indirect_tax_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON indirect_tax_account TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON indirect_tax_account TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON indirect_tax_account TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON indirect_tax_account TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE NONE COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON indirect_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE resource ON indirect_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE reporting_currency ON indirect_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON indirect_tax_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON indirect_tax_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON indirect_tax_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';

DEFINE TABLE OVERWRITE organization_currency_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON organization_currency_account TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON organization_currency_account TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON organization_currency_account TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON organization_currency_account TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.organization.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization_currency ON organization_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.organization.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization_pair ON organization_currency_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_organization ON organization_currency_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner organization.z_accounts';

DEFINE FIELD OVERWRITE currency ON organization_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE resource ON organization_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE reporting_currency ON organization_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON organization_currency_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON organization_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON organization_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON organization_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON organization_currency_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON organization_currency_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON organization_currency_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';

DEFINE TABLE OVERWRITE stock_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON stock_account TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON stock_account TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON stock_account TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON stock_account TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE NONE COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE resource ON stock_account TYPE record<item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE unit ON stock_account TYPE record<measure_unit> REFERENCE ON DELETE REJECT VALUE $this.resource.unit COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE operating_unit ON stock_account TYPE record<operating_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_identity ON stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner operating_unit.z_stock_keys';

DEFINE FIELD OVERWRITE reporting_currency ON stock_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON stock_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON stock_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON stock_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';

DEFINE FIELD OVERWRITE z_gross ON stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE misc_stock_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON misc_stock_account TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON misc_stock_account TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON misc_stock_account TYPE record<subsidiary> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON misc_stock_account TYPE option<record<organization>> REFERENCE ON DELETE REJECT VALUE NONE COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE resource ON misc_stock_account TYPE record<item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE unit ON misc_stock_account TYPE record<measure_unit> REFERENCE ON DELETE REJECT VALUE $this.resource.unit COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE operating_unit ON misc_stock_account TYPE record<operating_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE reporting_currency ON misc_stock_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON misc_stock_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON misc_stock_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON misc_stock_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON misc_stock_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON misc_stock_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON misc_stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON misc_stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';

DEFINE FIELD OVERWRITE z_gross ON misc_stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE organization_resource_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';

DEFINE FIELD OVERWRITE name ON organization_resource_account TYPE string COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON organization_resource_account TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON organization_resource_account TYPE record<organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE subsidiary ON organization_resource_account TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.organization.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization_currency ON organization_resource_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.organization.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE organization_pair ON organization_resource_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_organization ON organization_resource_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner organization.z_accounts';

DEFINE FIELD OVERWRITE resource ON organization_resource_account TYPE record<item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE unit ON organization_resource_account TYPE record<measure_unit> REFERENCE ON DELETE REJECT VALUE $this.resource.unit COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE reporting_currency ON organization_resource_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.subsidiary.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE valuation_pair ON organization_resource_account TYPE option<record<exchange_pair>> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_real ON organization_resource_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE minimum_available ON organization_resource_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_floor ON organization_resource_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE net_ceiling ON organization_resource_account TYPE option<decimal> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON organization_resource_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE z_subsidiary ON organization_resource_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record @rebase-tree-owner subsidiary.z_accounts';
