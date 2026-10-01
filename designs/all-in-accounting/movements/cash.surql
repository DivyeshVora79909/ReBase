-- Core real-money movements. External identities never receive an implicit
-- balance in this entity; only modeled treasury accounts get asset positions.

DEFINE FUNCTION OVERWRITE fn::movement::cash_position($id: record, $slot: string,
    $account: record<treasury_account>, $at: datetime, $delta: decimal) {
    RETURN fn::tree::member($id, $slot, $account, 'z_history', $at,
        { balance: $delta }, { currency: $account.currency }, {}, false);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_in_members($row: object) {
    RETURN [
        fn::movement::cash_position($row.id, 'z_to', $row.to_account, $row.effective_at, $row.amount),
        fn::tree::member($row.id, 'z_available_grant', $row.id, 'z_allocations', $row.effective_at,
            { available: $row.amount }, { currency: $row.to_account.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_out_members($row: object) {
    RETURN [fn::movement::cash_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.amount)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_transfer_members($row: object) {
    RETURN [
        fn::movement::cash_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.amount),
        fn::movement::cash_position($row.id, 'z_to', $row.to_account, $row.effective_at, $row.amount)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_fx_transfer_members($row: object) {
    RETURN [
        fn::movement::cash_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.from_amount),
        fn::movement::cash_position($row.id, 'z_to', $row.to_account, $row.effective_at, $row.to_amount),
        fn::tree::member($row.id, 'z_exchange', $row.exchange, 'z_usage', $row.effective_at,
            { source: $row.from_amount, target: $row.to_amount, residual: $row.rounding_residual },
            { from_currency: $row.exchange.from_currency, to_currency: $row.exchange.to_currency }, {}, false),
        fn::tree::member($row.id, 'z_pair', $row.pair, 'z_history', $row.effective_at,
            { quoted_given: $row.from_amount, quoted_received: $row.to_amount },
            { given_resource: $row.pair.given_resource, received_resource: $row.pair.received_resource }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_fx_transfer_reversal_members($row: object) {
    RETURN [
        fn::movement::cash_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.from_amount),
        fn::movement::cash_position($row.id, 'z_to', $row.to_account, $row.effective_at, $row.to_amount),
        fn::tree::member($row.id, 'z_pair', $row.pair, 'z_history', $row.effective_at,
            { quoted_given: -$row.to_amount, quoted_received: -$row.from_amount },
            { given_resource: $row.pair.given_resource, received_resource: $row.pair.received_resource }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_in_validate($row: object) {
    IF ($row.z_allocations.summary.measures.allocated.max_prefix ?? 0dec) > $row.amount {
        THROW 'ACCOUNTING_CASH_IN_OVERALLOCATED';
    };
    IF ($row.z_allocations.summary.measures.available.instant_min ?? 0dec) < 0dec {
        THROW 'ACCOUNTING_CASH_IN_ALLOCATION_CAPACITY';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_out_validate($row: object) {
    IF ($row.z_allocations.summary.measures.allocated.max_prefix ?? 0dec) > $row.amount {
        THROW 'ACCOUNTING_CASH_OUT_OVERALLOCATED';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_transfer_validate($row: object) {
    IF $row.from_account.economic_entity != $row.to_account.economic_entity {
        THROW 'ACCOUNTING_CASH_TRANSFER_ENTITY_MISMATCH';
    };
    IF $row.from_account.currency != $row.to_account.currency { THROW 'ACCOUNTING_CASH_TRANSFER_CURRENCY_MISMATCH'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_fx_transfer_validate($row: object) {
    IF record::tb($row.exchange.pair.given_resource) != 'currency'
        OR record::tb($row.exchange.pair.received_resource) != 'currency' {
        THROW 'ACCOUNTING_CASH_FX_CURRENCY_PAIR_REQUIRED';
    };
    IF $row.pair != $row.exchange.pair
        OR $row.pair.given_resource != $row.exchange.from_currency
        OR $row.pair.received_resource != $row.exchange.to_currency {
        THROW 'ACCOUNTING_CASH_FX_PAIR_MISMATCH';
    };
    IF $row.from_account.economic_entity != $row.to_account.economic_entity {
        THROW 'ACCOUNTING_CASH_FX_ENTITY_MISMATCH';
    };
    IF $row.from_account.currency != $row.exchange.from_currency
        OR $row.to_account.currency != $row.exchange.to_currency {
        THROW 'ACCOUNTING_CASH_FX_CURRENCY_MISMATCH';
    };
    IF $row.owned_by != $row.exchange.owned_by
        OR $row.from_account.owned_by != $row.exchange.owned_by
        OR $row.to_account.owned_by != $row.exchange.owned_by
        OR $row.economic_entity != $row.exchange.economic_entity {
        THROW 'ACCOUNTING_CASH_FX_OWNER_ENTITY_MISMATCH';
    };
    IF $row.effective_at < $row.exchange.effective_at { THROW 'ACCOUNTING_CASH_FX_QUOTE_NOT_EFFECTIVE'; };
    IF $row.from_amount <= 0dec OR $row.to_amount <= 0dec {
        THROW 'ACCOUNTING_CASH_FX_AMOUNTS_POSITIVE';
    };
    IF fn::accounting::currency_round($row.from_amount, $row.exchange.from_precision) != $row.from_amount {
        THROW 'ACCOUNTING_CASH_FX_SOURCE_PRECISION';
    };
    IF fn::accounting::currency_round($row.to_amount, $row.exchange.to_precision) != $row.to_amount {
        THROW 'ACCOUNTING_CASH_FX_TARGET_PRECISION';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_fx_transfer_reversal_validate($row: object) {
    IF $row.effective_at < $row.source_effective_at {
        THROW 'ACCOUNTING_CASH_FX_REVERSAL_BEFORE_SOURCE';
    };
    IF $row.owned_by != $row.source.owned_by
        OR $row.pair != $row.source.pair
        OR $row.economic_entity != $row.source.economic_entity {
        THROW 'ACCOUNTING_CASH_FX_REVERSAL_SCOPE_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE currency_exchange SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::currency_exchange_validate';
DEFINE FIELD OVERWRITE pair ON currency_exchange TYPE record<exchange_pair> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE from_currency ON currency_exchange TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_currency ON currency_exchange TYPE record<currency> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE economic_entity ON currency_exchange TYPE record<rebase_user | organization> VALUE $this.pair.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends pair.economic_entity';
DEFINE FIELD OVERWRITE rate ON currency_exchange TYPE decimal ASSERT $value > 0dec READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON currency_exchange TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE from_precision ON currency_exchange TYPE int VALUE $this.from_currency.precision READONLY COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE to_precision ON currency_exchange TYPE int VALUE $this.to_currency.precision READONLY COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_usage ON currency_exchange TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FUNCTION OVERWRITE fn::accounting::currency_exchange_validate($row: object) {
    IF $row.from_currency = $row.to_currency
        OR $row.pair.given_resource = $row.pair.received_resource {
        THROW 'ACCOUNTING_CASH_FX_SAME_CURRENCY';
    };
    IF record::tb($row.pair.given_resource) != 'currency'
        OR record::tb($row.pair.received_resource) != 'currency' {
        THROW 'ACCOUNTING_CASH_FX_CURRENCY_PAIR_REQUIRED';
    };
    IF $row.pair.given_resource != $row.from_currency
        OR $row.pair.received_resource != $row.to_currency {
        THROW 'ACCOUNTING_CASH_FX_PAIR_ORIENTATION_MISMATCH';
    };
    IF $row.owned_by != $row.pair.owned_by {
        THROW 'ACCOUNTING_CASH_FX_PAIR_OWNER_MISMATCH';
    };
    IF $row.z_usage.summary.count > 0 AND $row.z_usage.summary.first[0] < $row.effective_at {
        THROW 'ACCOUNTING_CASH_FX_QUOTE_USED_EARLY';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE cash_fx_transfer SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::cash_fx_transfer_members @rebase-validate fn::accounting::cash_fx_transfer_validate';
DEFINE FIELD OVERWRITE economic_entity ON cash_fx_transfer TYPE record<rebase_user | organization> VALUE $this.from_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends from_account.economic_entity';
DEFINE FIELD OVERWRITE from_account ON cash_fx_transfer TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_account ON cash_fx_transfer TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange ON cash_fx_transfer TYPE record<currency_exchange> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE from_amount ON cash_fx_transfer TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair ON cash_fx_transfer TYPE record<exchange_pair> REFERENCE ON DELETE REJECT VALUE $this.exchange.pair COMMENT '@rebase-derived @rebase-depends exchange.pair';
DEFINE FIELD OVERWRITE to_amount ON cash_fx_transfer TYPE decimal VALUE fn::accounting::currency_round($this.from_amount * $this.exchange.rate, $this.exchange.to_precision) COMMENT '@rebase-derived @rebase-depends exchange.rate, exchange.to_precision';
DEFINE FIELD OVERWRITE rounding_residual ON cash_fx_transfer TYPE decimal VALUE $this.from_amount * $this.exchange.rate - $this.to_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE effective_at ON cash_fx_transfer TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_from ON cash_fx_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_to ON cash_fx_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_exchange ON cash_fx_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner currency_exchange.z_usage';
DEFINE FIELD OVERWRITE z_pair ON cash_fx_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history';

DEFINE TABLE OVERWRITE cash_fx_transfer_reversal SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::cash_fx_transfer_reversal_members @rebase-validate fn::accounting::cash_fx_transfer_reversal_validate';
DEFINE FIELD OVERWRITE source ON cash_fx_transfer_reversal TYPE record<cash_fx_transfer> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair ON cash_fx_transfer_reversal TYPE record<exchange_pair> REFERENCE ON DELETE REJECT VALUE $this.source.pair COMMENT '@rebase-derived @rebase-depends source.pair';
DEFINE FIELD OVERWRITE exchange ON cash_fx_transfer_reversal TYPE record<currency_exchange> REFERENCE ON DELETE REJECT VALUE $this.source.exchange COMMENT '@rebase-derived @rebase-depends source.exchange';
DEFINE FIELD OVERWRITE from_account ON cash_fx_transfer_reversal TYPE record<treasury_account> REFERENCE ON DELETE REJECT VALUE $this.source.to_account COMMENT '@rebase-derived @rebase-depends source.to_account';
DEFINE FIELD OVERWRITE to_account ON cash_fx_transfer_reversal TYPE record<treasury_account> REFERENCE ON DELETE REJECT VALUE $this.source.from_account COMMENT '@rebase-derived @rebase-depends source.from_account';
DEFINE FIELD OVERWRITE from_amount ON cash_fx_transfer_reversal TYPE decimal VALUE $this.source.to_amount COMMENT '@rebase-derived @rebase-depends source.to_amount';
DEFINE FIELD OVERWRITE to_amount ON cash_fx_transfer_reversal TYPE decimal VALUE $this.source.from_amount COMMENT '@rebase-derived @rebase-depends source.from_amount';
DEFINE FIELD OVERWRITE economic_entity ON cash_fx_transfer_reversal TYPE record<rebase_user | organization> VALUE $this.source.economic_entity COMMENT '@rebase-derived @rebase-depends source.economic_entity';
DEFINE FIELD OVERWRITE source_effective_at ON cash_fx_transfer_reversal TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE effective_at ON cash_fx_transfer_reversal TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_from ON cash_fx_transfer_reversal TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_to ON cash_fx_transfer_reversal TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_pair ON cash_fx_transfer_reversal TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history';
DEFINE INDEX OVERWRITE cash_fx_transfer_reversal_source ON cash_fx_transfer_reversal FIELDS source UNIQUE;

DEFINE TABLE OVERWRITE cash_in SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::cash_in_members @rebase-validate fn::accounting::cash_in_validate';
DEFINE FIELD OVERWRITE economic_entity ON cash_in TYPE record<rebase_user | organization> VALUE $this.to_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends to_account.economic_entity';
DEFINE FIELD OVERWRITE from_party ON cash_in TYPE record<rebase_user | organization | tax_account | misc_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_account ON cash_in TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON cash_in TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON cash_in TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_to ON cash_in TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_allocations ON cash_in TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_available_grant ON cash_in TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_in.z_allocations';

DEFINE TABLE OVERWRITE cash_out SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::cash_out_members @rebase-validate fn::accounting::cash_out_validate';
DEFINE FIELD OVERWRITE economic_entity ON cash_out TYPE record<rebase_user | organization> VALUE $this.from_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends from_account.economic_entity';
DEFINE FIELD OVERWRITE from_account ON cash_out TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_party ON cash_out TYPE record<rebase_user | organization | tax_account | misc_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON cash_out TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON cash_out TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_from ON cash_out TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_allocations ON cash_out TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE cash_transfer SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::cash_transfer_members @rebase-validate fn::accounting::cash_transfer_validate';
DEFINE FIELD OVERWRITE economic_entity ON cash_transfer TYPE record<rebase_user | organization> VALUE $this.from_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends from_account.economic_entity';
DEFINE FIELD OVERWRITE from_account ON cash_transfer TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_account ON cash_transfer TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON cash_transfer TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON cash_transfer TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_from ON cash_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_to ON cash_transfer TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
