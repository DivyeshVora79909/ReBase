DEFINE FUNCTION OVERWRITE fn::accounting::entry_validate($row: object) {
    IF $row.real=0dec AND $row.receivable=0dec AND $row.payable=0dec { THROW 'ENTRY_EMPTY'; };
    fn::accounting::precision_validate($row.real,$row.account.resource);
    fn::accounting::precision_validate($row.receivable,$row.account.resource);
    fn::accounting::precision_validate($row.payable,$row.account.resource);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::entry_members($row: object) {
    RETURN fn::accounting::post($row,'z_account',$row.account,$row.effective_at,
        object::extend(fn::accounting::effects($row.real,$row.receivable,$row.payable),
        {credit_available:$row.receivable,liability_available:$row.payable}), $row.q_account_reporting, $row.q_account_organization);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE account_entry SCHEMAFULL COMMENT '@rebase-members fn::accounting::entry_members @rebase-validate fn::accounting::entry_validate';

DEFINE FIELD OVERWRITE account ON account_entry TYPE record<treasury | misc_currency_account | direct_tax_account | indirect_tax_account | organization_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON account_entry TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON account_entry TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE real ON account_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE receivable ON account_entry TYPE decimal DEFAULT 0dec ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE payable ON account_entry TYPE decimal DEFAULT 0dec ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_account ON account_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history @rebase-tree-owner organization_currency_account.z_history';

DEFINE FIELD OVERWRITE q_account_reporting ON account_entry TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.account.valuation_pair,$this.account.resource,$this.account.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE q_account_organization ON account_entry TYPE option<object> FLEXIBLE
VALUE fn::accounting::organization_query($this.account,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_account_subsidiary ON account_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_account_organization ON account_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';

DEFINE TABLE OVERWRITE stock_entry SCHEMAFULL COMMENT '@rebase-members fn::accounting::entry_members @rebase-validate fn::accounting::entry_validate';

DEFINE FIELD OVERWRITE account ON stock_entry TYPE record<stock_account | misc_stock_account | organization_resource_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE effective_at ON stock_entry TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON stock_entry TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE real ON stock_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE receivable ON stock_entry TYPE decimal DEFAULT 0dec ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE payable ON stock_entry TYPE decimal DEFAULT 0dec ASSERT $value>=0dec COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_account ON stock_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history @rebase-tree-owner organization_resource_account.z_history';

DEFINE FIELD OVERWRITE q_account_reporting ON stock_entry TYPE option<object> FLEXIBLE
VALUE fn::accounting::rate_query($this.account.valuation_pair,$this.account.resource,$this.account.reporting_currency,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE q_account_organization ON stock_entry TYPE option<object> FLEXIBLE
VALUE fn::accounting::organization_query($this.account,$this.effective_at)
COMMENT '@rebase-dependency latest @rebase-dependency-source exchange_pair.z_rates';

DEFINE FIELD OVERWRITE z_account_subsidiary ON stock_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner subsidiary.z_history';

DEFINE FIELD OVERWRITE z_account_organization ON stock_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
