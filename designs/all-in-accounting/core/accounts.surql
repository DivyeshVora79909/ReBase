-- These are accounts themselves; descriptor indexes contain counts, not mixed balances.

DEFINE FUNCTION OVERWRITE fn::accounting::account_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_currency', $row.currency, 'z_accounts', $row.effective_at, {}, {}, {}, false),
        IF $row.operating_unit = NONE THEN NONE ELSE fn::tree::member($row.id, 'z_resource', $row.resource, 'z_accounts', $row.effective_at, {}, {}, {}, false) END,
        IF $row.operating_unit = NONE THEN NONE ELSE fn::tree::member($row.id, 'z_operating', $row.operating_unit, 'z_accounts', $row.effective_at, {}, {}, {}, false) END,
        IF $row.operating_unit = NONE THEN NONE ELSE fn::tree::ordered_member($row.id, 'z_identity', $row.operating_unit, 'z_account_keys', [$row.currency, $row.resource], {}, {}) END];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::account_validate($row: object) {
    LET $s = $row.z_history.summary;
    IF $s.count > 0 AND ($s.tags.currency = NONE OR !$s.tags.currency.uniform OR $s.tags.currency.value != $row.currency
        OR $s.tags.resource = NONE OR !$s.tags.resource.uniform OR $s.tags.resource.value != $row.resource) { THROW 'ACCOUNT_DIMENSIONS'; };
    IF $s.count > 0 AND $s.first[0] < $row.effective_at { THROW 'ACCOUNT_NOT_EFFECTIVE'; };
    FOR $name IN ['real', 'receivable', 'payable', 'available'] {
        LET $floor = $row['minimum_' + $name];
        IF $floor != NONE AND ($s.measures[$name].instant_min ?? 0dec) < $floor { THROW 'ACCOUNT_BALANCE_FLOOR'; };
    };
    IF $row.net_floor != NONE AND $row.net_ceiling != NONE AND $row.net_floor > $row.net_ceiling { THROW 'ACCOUNT_NET_LIMIT_ORDER'; };
    IF $row.net_floor != NONE AND ($s.measures.net.instant_min ?? 0dec) < $row.net_floor { THROW 'ACCOUNT_NET_FLOOR'; };
    IF $row.net_ceiling != NONE AND ($s.measures.net.instant_max ?? 0dec) > $row.net_ceiling { THROW 'ACCOUNT_NET_CEILING'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE organization SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';
DEFINE FIELD OVERWRITE name ON organization TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON organization TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON organization TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON organization TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_real ON organization TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_receivable ON organization TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_payable ON organization TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_available ON organization TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON organization TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON organization TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON organization TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_currency ON organization TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_accounts';

DEFINE TABLE OVERWRITE treasury SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';
DEFINE FIELD OVERWRITE name ON treasury TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON treasury TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON treasury TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON treasury TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_real ON treasury TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_receivable ON treasury TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_payable ON treasury TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_available ON treasury TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON treasury TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON treasury TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON treasury TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_currency ON treasury TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_accounts';

DEFINE TABLE OVERWRITE direct_tax_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';
DEFINE FIELD OVERWRITE name ON direct_tax_account TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON direct_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON direct_tax_account TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON direct_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_real ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_receivable ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_payable ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_available ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON direct_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON direct_tax_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_currency ON direct_tax_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_accounts';

DEFINE TABLE OVERWRITE indirect_tax_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';
DEFINE FIELD OVERWRITE name ON indirect_tax_account TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON indirect_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON indirect_tax_account TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON indirect_tax_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_real ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_receivable ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_payable ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_available ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON indirect_tax_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON indirect_tax_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_currency ON indirect_tax_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_accounts';

DEFINE TABLE OVERWRITE misc_currency_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';
DEFINE FIELD OVERWRITE name ON misc_currency_account TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON misc_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON misc_currency_account TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON misc_currency_account TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_real ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_receivable ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_payable ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_available ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON misc_currency_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON misc_currency_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_currency ON misc_currency_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_accounts';

DEFINE TABLE OVERWRITE stock_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';
DEFINE FIELD OVERWRITE name ON stock_account TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON stock_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON stock_account TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON stock_account TYPE record<item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE operating_unit ON stock_account TYPE record<operating_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON stock_account TYPE record<measure_unit> REFERENCE ON DELETE REJECT VALUE $this.resource.unit COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_real ON stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_receivable ON stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_payable ON stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_available ON stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON stock_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON stock_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_currency ON stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_accounts';
DEFINE FIELD OVERWRITE z_resource ON stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner item.z_accounts @rebase-tree-owner service.z_accounts';
DEFINE FIELD OVERWRITE z_operating ON stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_accounts';
DEFINE FIELD OVERWRITE z_identity ON stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,record @rebase-tree-owner operating_unit.z_account_keys';

DEFINE TABLE OVERWRITE misc_stock_account SCHEMAFULL COMMENT '@rebase-members fn::accounting::account_members @rebase-validate fn::accounting::account_validate';
DEFINE FIELD OVERWRITE name ON misc_stock_account TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON misc_stock_account TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON misc_stock_account TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON misc_stock_account TYPE record<item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE operating_unit ON misc_stock_account TYPE record<operating_unit> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit ON misc_stock_account TYPE record<measure_unit> REFERENCE ON DELETE REJECT VALUE $this.resource.unit COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_real ON misc_stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_receivable ON misc_stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_payable ON misc_stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE minimum_available ON misc_stock_account TYPE option<decimal> DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_floor ON misc_stock_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE net_ceiling ON misc_stock_account TYPE option<decimal> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON misc_stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_currency ON misc_stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency.z_accounts';
DEFINE FIELD OVERWRITE z_resource ON misc_stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner item.z_accounts @rebase-tree-owner service.z_accounts';
DEFINE FIELD OVERWRITE z_operating ON misc_stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_accounts';
DEFINE FIELD OVERWRITE z_identity ON misc_stock_account TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,record @rebase-tree-owner operating_unit.z_account_keys';
