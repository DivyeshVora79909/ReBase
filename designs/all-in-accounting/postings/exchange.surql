-- Explicit real exchanges. Rates are destination resource units per source unit.

DEFINE FUNCTION OVERWRITE fn::accounting::exchange_validate($row: object) {
    fn::accounting::fee_validate($row);
    IF $row.from_account = $row.to_account { THROW 'EXCHANGE_IDENTICAL_ACCOUNTS'; };
    fn::accounting::rate_validate($row.from_resource, $row.to_resource, $row.exchange_rate);
    IF record::tb($row.from_resource) = 'currency' { fn::accounting::precision_validate($row.from_amount, $row.from_currency); };
    IF $row.to_amount <= 0dec { THROW 'EXCHANGE_ZERO_AMOUNT'; };
    IF $row.production_output != NONE AND ($row.output_account != $row.from_account OR $row.effective_at < $row.output_at) { THROW 'EXCHANGE_OUTPUT_SOURCE'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::exchange_members($row: object) {
    RETURN array::concat(array::concat([fn::accounting::balance_member($row, 'z_from', $row.from_account, $row.effective_at, fn::accounting::effects(-$row.from_amount, 0dec, 0dec), false),
        fn::accounting::balance_member($row, 'z_to', $row.to_account, $row.effective_at, fn::accounting::effects($row.to_amount, 0dec, 0dec), false),
        IF $row.production_output = NONE THEN NONE ELSE fn::tree::member($row.id, 'z_output', $row.production_output, 'z_capacity', $row.effective_at, { quantity: -$row.from_amount }, {}, {}, false) END], fn::accounting::fee_members($row)), fn::accounting::exchange_observation($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE resource_exchange SCHEMAFULL COMMENT '@rebase-members fn::accounting::exchange_members @rebase-validate fn::accounting::exchange_validate';
DEFINE FIELD OVERWRITE from_account ON resource_exchange TYPE record<treasury | misc_currency_account | stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_account ON resource_exchange TYPE record<treasury | misc_currency_account | stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE production_output ON resource_exchange TYPE option<record<production_output>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE from_amount ON resource_exchange TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON resource_exchange TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON resource_exchange TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON resource_exchange TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE from_resource ON resource_exchange TYPE record<currency | item | service> REFERENCE ON DELETE REJECT VALUE $this.from_account.resource COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE from_currency ON resource_exchange TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.from_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE to_resource ON resource_exchange TYPE record<currency | item | service> REFERENCE ON DELETE REJECT VALUE $this.to_account.resource COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE to_currency ON resource_exchange TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.to_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE to_precision ON resource_exchange TYPE int VALUE $this.to_currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE to_amount ON resource_exchange TYPE decimal VALUE IF record::tb($this.to_resource) = 'currency' THEN fn::accounting::round($this.from_amount * $this.exchange_rate, $this.to_precision) ELSE $this.from_amount * $this.exchange_rate END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE output_account ON resource_exchange TYPE option<record<stock_account | misc_stock_account>> REFERENCE ON DELETE REJECT VALUE $this.production_output.stock_account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE output_at ON resource_exchange TYPE option<datetime> VALUE $this.production_output.ends_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_from ON resource_exchange TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_to ON resource_exchange TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_output ON resource_exchange TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner production_output.z_capacity';
