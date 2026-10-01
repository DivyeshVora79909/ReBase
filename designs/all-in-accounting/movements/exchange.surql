-- Directional resource-pair identity and entered currency exchange execution.
-- Quote observations stay in currency_exchange and cash_fx_transfer.

DEFINE FUNCTION OVERWRITE fn::accounting::exchange_pair_validate($row: object) {
    IF $row.given_resource = $row.received_resource {
        THROW 'ACCOUNTING_EXCHANGE_PAIR_SAME_RESOURCE';
    };
    IF ($row.z_history.summary.measures.executed_given.instant_min ?? 0dec) < 0dec
        OR ($row.z_history.summary.measures.executed_received.instant_min ?? 0dec) < 0dec
        OR ($row.z_history.summary.measures.quoted_given.instant_min ?? 0dec) < 0dec
        OR ($row.z_history.summary.measures.quoted_received.instant_min ?? 0dec) < 0dec {
        THROW 'ACCOUNTING_EXCHANGE_PAIR_NEGATIVE_NET_VOLUME';
    };
    IF $row.z_history.summary.tags.given_resource != NONE AND
        (!$row.z_history.summary.tags.given_resource.uniform
            OR $row.z_history.summary.tags.given_resource.value != $row.given_resource) {
        THROW 'ACCOUNTING_EXCHANGE_PAIR_GIVEN_RESOURCE_MISMATCH';
    };
    IF $row.z_history.summary.tags.received_resource != NONE AND
        (!$row.z_history.summary.tags.received_resource.uniform
            OR $row.z_history.summary.tags.received_resource.value != $row.received_resource) {
        THROW 'ACCOUNTING_EXCHANGE_PAIR_RECEIVED_RESOURCE_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE exchange_pair SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::exchange_pair_validate';
-- Declared before the composite index; the security generator supplies the
-- profile's standard owner validation/permissions later in the bundle.
DEFINE FIELD OVERWRITE owned_by ON exchange_pair TYPE record<rebase_user | rebase_group> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE economic_entity ON exchange_pair TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE given_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE received_resource ON exchange_pair TYPE record<currency | item | service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON exchange_pair TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE exchange_pair_scope_orientation ON exchange_pair
    FIELDS owned_by, economic_entity, given_resource, received_resource UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_exchange_members($row: object) {
    RETURN [
        fn::movement::cash_position($row.id, 'z_given', $row.from_account, $row.effective_at, -$row.given_amount),
        fn::movement::cash_position($row.id, 'z_received', $row.to_account, $row.effective_at, $row.received_amount),
        fn::tree::member($row.id, 'z_pair', $row.pair, 'z_history', $row.effective_at,
            { executed_given: $row.given_amount, executed_received: $row.received_amount },
            { given_resource: $row.pair.given_resource, received_resource: $row.pair.received_resource }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_exchange_validate($row: object) {
    IF record::tb($row.pair.given_resource) != 'currency'
        OR record::tb($row.pair.received_resource) != 'currency' {
        THROW 'ACCOUNTING_CASH_EXCHANGE_CURRENCY_PAIR_REQUIRED';
    };
    IF $row.from_account.currency != $row.pair.given_resource
        OR $row.to_account.currency != $row.pair.received_resource {
        THROW 'ACCOUNTING_CASH_EXCHANGE_ORIENTATION_MISMATCH';
    };
    IF $row.from_account.economic_entity != $row.pair.economic_entity
        OR $row.to_account.economic_entity != $row.pair.economic_entity {
        THROW 'ACCOUNTING_CASH_EXCHANGE_ENTITY_MISMATCH';
    };
    IF $row.owned_by != $row.pair.owned_by
        OR $row.from_account.owned_by != $row.pair.owned_by
        OR $row.to_account.owned_by != $row.pair.owned_by {
        THROW 'ACCOUNTING_CASH_EXCHANGE_OWNER_MISMATCH';
    };
    IF $row.given_amount <= 0dec OR $row.received_amount <= 0dec {
        THROW 'ACCOUNTING_CASH_EXCHANGE_AMOUNTS_POSITIVE';
    };
    IF fn::accounting::currency_round($row.given_amount, $row.pair.given_resource.precision) != $row.given_amount
        OR fn::accounting::currency_round($row.received_amount, $row.pair.received_resource.precision) != $row.received_amount {
        THROW 'ACCOUNTING_CASH_EXCHANGE_CURRENCY_PRECISION';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE cash_exchange SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::cash_exchange_members @rebase-validate fn::accounting::cash_exchange_validate';
DEFINE FIELD OVERWRITE pair ON cash_exchange TYPE record<exchange_pair> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE from_account ON cash_exchange TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE to_account ON cash_exchange TYPE record<treasury_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE economic_entity ON cash_exchange TYPE record<rebase_user | organization> VALUE $this.pair.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends pair.economic_entity';
DEFINE FIELD OVERWRITE given_amount ON cash_exchange TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE received_amount ON cash_exchange TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON cash_exchange TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_given ON cash_exchange TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_received ON cash_exchange TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_pair ON cash_exchange TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history';

DEFINE FUNCTION OVERWRITE fn::accounting::cash_exchange_reversal_members($row: object) {
    RETURN [
        fn::movement::cash_position($row.id, 'z_given', $row.from_account, $row.effective_at, -$row.given_amount),
        fn::movement::cash_position($row.id, 'z_received', $row.to_account, $row.effective_at, $row.received_amount),
        fn::tree::member($row.id, 'z_pair', $row.pair, 'z_history', $row.effective_at,
            { executed_given: -$row.source.given_amount, executed_received: -$row.source.received_amount },
            { given_resource: $row.pair.given_resource, received_resource: $row.pair.received_resource }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::cash_exchange_reversal_validate($row: object) {
    IF $row.effective_at < $row.source_effective_at {
        THROW 'ACCOUNTING_CASH_EXCHANGE_REVERSAL_BEFORE_SOURCE';
    };
    IF $row.owned_by != $row.source.owned_by
        OR $row.pair.owned_by != $row.source.pair.owned_by
        OR $row.economic_entity != $row.source.economic_entity {
        THROW 'ACCOUNTING_CASH_EXCHANGE_REVERSAL_SCOPE_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE cash_exchange_reversal SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::cash_exchange_reversal_members @rebase-validate fn::accounting::cash_exchange_reversal_validate';
DEFINE FIELD OVERWRITE source ON cash_exchange_reversal TYPE record<cash_exchange> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE pair ON cash_exchange_reversal TYPE record<exchange_pair> REFERENCE ON DELETE REJECT VALUE $this.source.pair COMMENT '@rebase-derived @rebase-depends source.pair';
DEFINE FIELD OVERWRITE from_account ON cash_exchange_reversal TYPE record<treasury_account> REFERENCE ON DELETE REJECT VALUE $this.source.to_account COMMENT '@rebase-derived @rebase-depends source.to_account';
DEFINE FIELD OVERWRITE to_account ON cash_exchange_reversal TYPE record<treasury_account> REFERENCE ON DELETE REJECT VALUE $this.source.from_account COMMENT '@rebase-derived @rebase-depends source.from_account';
DEFINE FIELD OVERWRITE given_amount ON cash_exchange_reversal TYPE decimal VALUE $this.source.received_amount COMMENT '@rebase-derived @rebase-depends source.received_amount';
DEFINE FIELD OVERWRITE received_amount ON cash_exchange_reversal TYPE decimal VALUE $this.source.given_amount COMMENT '@rebase-derived @rebase-depends source.given_amount';
DEFINE FIELD OVERWRITE economic_entity ON cash_exchange_reversal TYPE record<rebase_user | organization> VALUE $this.source.economic_entity COMMENT '@rebase-derived @rebase-depends source.economic_entity';
DEFINE FIELD OVERWRITE source_effective_at ON cash_exchange_reversal TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE effective_at ON cash_exchange_reversal TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_given ON cash_exchange_reversal TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_received ON cash_exchange_reversal TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury_account.z_history';
DEFINE FIELD OVERWRITE z_pair ON cash_exchange_reversal TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner exchange_pair.z_history';
DEFINE INDEX OVERWRITE cash_exchange_reversal_source ON cash_exchange_reversal FIELDS source UNIQUE;
