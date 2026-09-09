-- Accounts calculation kernel.
--
-- Naming contract:
--   a_* authoritative client facts
--   d_* deterministic derived shadows
--   e_* synchronous integrity guards
--   v_* sparse materialized projections
--
-- Mutable position rows are internal, rebuildable write anchors. Movement
-- facts remain the source of truth.

-- -------------------------------------------------------------------------
-- Shared Accounts primitives
-- -------------------------------------------------------------------------

DEFINE TABLE OVERWRITE organization SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON organization TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_code ON organization TYPE option<string> DEFAULT NONE VALUE
    IF $value = NONE THEN NONE ELSE string::uppercase(string::trim($value)) END;
DEFINE FIELD a_active ON organization TYPE bool DEFAULT true;
DEFINE INDEX OVERWRITE idx_accounts_organization_code ON TABLE organization FIELDS a_code UNIQUE;

-- A finance profile is metadata for an organization, never an implicit
-- currency source for a movement.  Transactions still carry their own
-- explicit currency or exchange legs.
DEFINE TABLE OVERWRITE organization_finance_profile SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_organization ON organization_finance_profile TYPE record<organization>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_functional_currency ON organization_finance_profile TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_reporting_currency ON organization_finance_profile TYPE option<record<currency>>
    REFERENCE ON DELETE REJECT DEFAULT NONE READONLY;
DEFINE INDEX OVERWRITE idx_accounts_organization_finance_profile_org
    ON TABLE organization_finance_profile FIELDS a_organization UNIQUE;

DEFINE TABLE OVERWRITE currency SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_code ON currency TYPE string VALUE string::uppercase(string::trim($value))
    ASSERT string::matches($value, /^[A-Z0-9][A-Z0-9._-]{0,15}$/) READONLY;
DEFINE FIELD a_name ON currency TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_minor_unit_precision ON currency TYPE int DEFAULT 2
    ASSERT $value >= 0 AND $value <= 18;
DEFINE FIELD a_symbol ON currency TYPE option<string> DEFAULT NONE;
DEFINE FIELD a_active ON currency TYPE bool DEFAULT true;
DEFINE INDEX OVERWRITE idx_accounts_currency_code ON TABLE currency FIELDS a_code UNIQUE;

DEFINE TABLE OVERWRITE fx_rate SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_base_currency ON fx_rate TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_quote_currency ON fx_rate TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_rate ON fx_rate TYPE decimal ASSERT $value > 0dec READONLY;
DEFINE FIELD a_effective_at ON fx_rate TYPE datetime READONLY;
DEFINE FIELD a_source ON fx_rate TYPE option<string> DEFAULT NONE READONLY;
DEFINE FIELD e_guard ON fx_rate TYPE bool VALUE {
    IF $this.a_base_currency = $this.a_quote_currency {
        THROW 'ACCOUNTS_FX_SAME_CURRENCY';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_fx_pair_time ON TABLE fx_rate
    FIELDS a_base_currency, a_quote_currency, a_effective_at;

DEFINE TABLE OVERWRITE treasury_account SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON treasury_account TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_currency ON treasury_account TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_active ON treasury_account TYPE bool DEFAULT true;

DEFINE TABLE OVERWRITE misc_account SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON misc_account TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_currency ON misc_account TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_guard_non_negative ON misc_account TYPE bool DEFAULT false READONLY;
DEFINE FIELD a_active ON misc_account TYPE bool DEFAULT true;

DEFINE TABLE OVERWRITE operating_unit SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON operating_unit TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_kind ON operating_unit TYPE string DEFAULT 'unit'
    ASSERT $value IN ['unit', 'warehouse', 'office', 'branch', 'plant'];
DEFINE FIELD a_active ON operating_unit TYPE bool DEFAULT true;

DEFINE TABLE OVERWRITE misc_inventory_node SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON misc_inventory_node TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;

DEFINE TABLE OVERWRITE item SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON item TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_sku ON item TYPE option<string> DEFAULT NONE VALUE
    IF $value = NONE THEN NONE ELSE string::trim($value) END;
DEFINE FIELD a_unit ON item TYPE string DEFAULT 'unit' VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_active ON item TYPE bool DEFAULT true;
DEFINE INDEX OVERWRITE idx_accounts_item_sku ON TABLE item FIELDS a_sku UNIQUE;

DEFINE TABLE OVERWRITE service SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON service TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_code ON service TYPE option<string> DEFAULT NONE VALUE
    IF $value = NONE THEN NONE ELSE string::trim($value) END;
DEFINE FIELD a_unit ON service TYPE string DEFAULT 'unit' VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_active ON service TYPE bool DEFAULT true;
DEFINE INDEX OVERWRITE idx_accounts_service_code ON TABLE service FIELDS a_code UNIQUE;

DEFINE TABLE OVERWRITE tax_rule SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON tax_rule TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_code ON tax_rule TYPE option<string> DEFAULT NONE VALUE
    IF $value = NONE THEN NONE ELSE string::trim($value) END;
DEFINE FIELD a_default_rate ON tax_rule TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec;
DEFINE FIELD a_active ON tax_rule TYPE bool DEFAULT true;
DEFINE INDEX OVERWRITE idx_accounts_tax_rule_code ON TABLE tax_rule FIELDS a_code UNIQUE;

-- -------------------------------------------------------------------------
-- Internal position anchors
-- -------------------------------------------------------------------------

DEFINE TABLE OVERWRITE money_position SCHEMAFULL
    COMMENT '@rebase-internal';
DEFINE FIELD endpoint ON money_position
    TYPE record<treasury_account | misc_account> REFERENCE ON DELETE CASCADE READONLY
    PERMISSIONS NONE;
DEFINE FIELD currency ON money_position TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY PERMISSIONS NONE;
DEFINE FIELD balance ON money_position TYPE decimal DEFAULT 0dec PERMISSIONS NONE;
DEFINE FIELD total_in ON money_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD total_out ON money_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD revision ON money_position TYPE int DEFAULT 0 ASSERT $value >= 0
    PERMISSIONS NONE;
DEFINE FIELD e_guard ON money_position TYPE bool VALUE {
    LET $balance = $this.balance ?? 0dec;
    LET $guarded = record::tb($this.endpoint) = 'treasury_account'
        OR (record::tb($this.endpoint) = 'misc_account' AND $this.endpoint.a_guard_non_negative = true);
    IF $guarded AND $balance < 0dec { THROW 'ACCOUNTS_NEGATIVE_MONEY_POSITION'; };
    IF $this.endpoint != NONE AND $this.currency != NONE
        AND $this.currency != $this.endpoint.a_currency {
        THROW 'ACCOUNTS_MONEY_POSITION_CURRENCY';
    };
    RETURN true;
} ASSERT $value = true PERMISSIONS NONE;
DEFINE INDEX OVERWRITE idx_accounts_money_position_key ON TABLE money_position
    FIELDS endpoint, currency UNIQUE;

DEFINE TABLE OVERWRITE inventory_position SCHEMAFULL
    COMMENT '@rebase-internal';
DEFINE FIELD operating_unit ON inventory_position TYPE record<operating_unit>
    REFERENCE ON DELETE CASCADE READONLY PERMISSIONS NONE;
DEFINE FIELD item ON inventory_position TYPE record<item>
    REFERENCE ON DELETE REJECT READONLY PERMISSIONS NONE;
DEFINE FIELD opening_quantity ON inventory_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD quantity ON inventory_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD total_in ON inventory_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD total_out ON inventory_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD revision ON inventory_position TYPE int DEFAULT 0 ASSERT $value >= 0
    PERMISSIONS NONE;
DEFINE FIELD e_guard ON inventory_position TYPE bool VALUE {
    IF ($this.quantity ?? 0dec) < 0dec { THROW 'ACCOUNTS_NEGATIVE_INVENTORY_POSITION'; };
    RETURN true;
} ASSERT $value = true PERMISSIONS NONE;
DEFINE INDEX OVERWRITE idx_accounts_inventory_position_key ON TABLE inventory_position
    FIELDS operating_unit, item UNIQUE;

DEFINE TABLE OVERWRITE service_position SCHEMAFULL
    COMMENT '@rebase-internal';
DEFINE FIELD operating_unit ON service_position TYPE record<operating_unit>
    REFERENCE ON DELETE CASCADE READONLY PERMISSIONS NONE;
DEFINE FIELD service ON service_position TYPE record<service>
    REFERENCE ON DELETE REJECT READONLY PERMISSIONS NONE;
DEFINE FIELD granted ON service_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD consumed ON service_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD remaining ON service_position TYPE decimal DEFAULT 0dec
    ASSERT $value >= 0dec PERMISSIONS NONE;
DEFINE FIELD revision ON service_position TYPE int DEFAULT 0 ASSERT $value >= 0
    PERMISSIONS NONE;
DEFINE FIELD e_guard ON service_position TYPE bool VALUE {
    LET $remaining = $this.remaining ?? 0dec;
    LET $consumed = $this.consumed ?? 0dec;
    LET $granted = $this.granted ?? 0dec;
    IF $remaining < 0dec { THROW 'ACCOUNTS_SERVICE_CAPACITY_EXCEEDED'; };
    IF $consumed < 0dec OR $granted < 0dec { THROW 'ACCOUNTS_SERVICE_POSITION_NEGATIVE'; };
    RETURN true;
} ASSERT $value = true PERMISSIONS NONE;
DEFINE INDEX OVERWRITE idx_accounts_service_position_key ON TABLE service_position
    FIELDS operating_unit, service UNIQUE;

-- Durable ordered entries back the effective-time replay check.  They are
-- internal facts, not a second public ledger: source rows remain authoritative
-- and these rows are rebuilt from them when a position is repaired.
DEFINE TABLE OVERWRITE position_entry SCHEMAFULL
    COMMENT '@rebase-internal';
DEFINE FIELD position ON position_entry
    TYPE record<money_position | inventory_position | service_position>
    REFERENCE ON DELETE CASCADE READONLY PERMISSIONS NONE;
DEFINE FIELD source ON position_entry TYPE record<
    money_opening_balance | money_movement | money_exchange | money_adjustment_line | money_refund |
    inventory_opening_balance | inventory_movement | inventory_adjustment_line | inventory_return |
    service_capacity | service_delivery
> REFERENCE ON DELETE CASCADE READONLY PERMISSIONS NONE;
DEFINE FIELD effective_at ON position_entry TYPE datetime READONLY PERMISSIONS NONE;
DEFINE FIELD delta ON position_entry TYPE decimal ASSERT $value != 0dec PERMISSIONS NONE;
DEFINE INDEX OVERWRITE idx_accounts_position_entry_key ON position_entry
    FIELDS position, source UNIQUE;
DEFINE INDEX OVERWRITE idx_accounts_position_entry_order ON position_entry
    FIELDS position, effective_at;

-- Opening balances are ordinary dated facts so they participate in the same
-- atomic position path as every later movement.  There is no mutable scalar
-- on an account that can silently bypass replay or concurrency control.
DEFINE TABLE OVERWRITE money_opening_balance SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_endpoint ON money_opening_balance
    TYPE record<treasury_account | misc_account>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_currency ON money_opening_balance TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_amount ON money_opening_balance TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD a_effective_at ON money_opening_balance TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON money_opening_balance TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD e_guard ON money_opening_balance TYPE bool VALUE {
    IF $this.a_endpoint.a_currency != $this.a_currency {
        THROW 'ACCOUNTS_OPENING_MONEY_CURRENCY';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_money_opening_unique ON TABLE money_opening_balance
    FIELDS a_endpoint, a_currency UNIQUE;
DEFINE INDEX OVERWRITE idx_accounts_money_opening_idempotency ON TABLE money_opening_balance
    FIELDS a_idempotency_key UNIQUE;

DEFINE TABLE OVERWRITE inventory_opening_balance SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_operating_unit ON inventory_opening_balance TYPE record<operating_unit>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_item ON inventory_opening_balance TYPE record<item>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_quantity ON inventory_opening_balance TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD a_effective_at ON inventory_opening_balance TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON inventory_opening_balance TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE INDEX OVERWRITE idx_accounts_inventory_opening_unique ON TABLE inventory_opening_balance
    FIELDS a_operating_unit, a_item UNIQUE;
DEFINE INDEX OVERWRITE idx_accounts_inventory_opening_idempotency ON TABLE inventory_opening_balance
    FIELDS a_idempotency_key UNIQUE;

-- -------------------------------------------------------------------------
-- Resource movement facts
-- -------------------------------------------------------------------------

DEFINE TABLE OVERWRITE money_movement SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_from ON money_movement
    TYPE record<treasury_account | misc_account | organization>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_to ON money_movement
    TYPE record<treasury_account | misc_account | organization>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_currency ON money_movement TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
-- Amounts are mutable source facts.  The position event applies the old/new
-- delta atomically; endpoint, currency, and effective time remain immutable.
DEFINE FIELD a_amount ON money_movement TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_effective_at ON money_movement TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON money_movement TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD a_contexts ON money_movement TYPE array<record> DEFAULT []
    REFERENCE ON DELETE UNSET COMMENT '@rebase-provenance';
DEFINE FIELD a_description ON money_movement TYPE option<string> DEFAULT NONE;
DEFINE FIELD d1_from_is_position ON money_movement TYPE bool VALUE
    record::tb($this.a_from) = 'treasury_account' OR record::tb($this.a_from) = 'misc_account';
DEFINE FIELD d2_to_is_position ON money_movement TYPE bool VALUE
    record::tb($this.a_to) = 'treasury_account' OR record::tb($this.a_to) = 'misc_account';
DEFINE FIELD d3_adjustment ON money_movement TYPE decimal VALUE {
    LET $movement_id = $this.id;
    RETURN array::fold(
        (SELECT VALUE a_delta FROM money_adjustment_line WHERE a_target = $movement_id),
        0dec,
        |$total, $delta| $total + ($delta ?? 0dec)
    );
};
DEFINE FIELD d4_net_amount ON money_movement TYPE decimal VALUE
    ($this.a_amount ?? 0dec) + ($this.d3_adjustment ?? 0dec) ASSERT $value > 0dec;
DEFINE FIELD e_guard ON money_movement TYPE bool VALUE {
    LET $from_type = record::tb($this.a_from);
    LET $to_type = record::tb($this.a_to);
    IF $this.a_from = $this.a_to { THROW 'ACCOUNTS_MONEY_SAME_ENDPOINT'; };
    IF !$this.d1_from_is_position AND !$this.d2_to_is_position {
        THROW 'ACCOUNTS_MONEY_REQUIRES_POSITION';
    };
    IF $this.d1_from_is_position AND ($this.a_from.a_currency != $this.a_currency) {
        THROW 'ACCOUNTS_MONEY_FROM_CURRENCY';
    };
    IF $this.d2_to_is_position AND ($this.a_to.a_currency != $this.a_currency) {
        THROW 'ACCOUNTS_MONEY_TO_CURRENCY';
    };
    IF $from_type = 'organization' AND $to_type = 'organization' {
        THROW 'ACCOUNTS_MONEY_EXTERNAL_TO_EXTERNAL';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_money_movement_idempotency ON TABLE money_movement
    FIELDS a_idempotency_key UNIQUE;
DEFINE INDEX OVERWRITE idx_accounts_money_movement_time ON TABLE money_movement
    FIELDS a_effective_at;

-- Cross-currency transfers are a distinct primitive.  A single amount cannot
-- safely update two differently denominated positions, so an exchange stores
-- both explicit legs and one immutable FX snapshot.  The amounts are still
-- authoritative facts: rounding, fees, and client policy may make them differ
-- from a naive multiplication of the quoted rate.
DEFINE TABLE OVERWRITE money_exchange SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_from ON money_exchange
    TYPE record<treasury_account | misc_account | organization>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_to ON money_exchange
    TYPE record<treasury_account | misc_account | organization>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_from_currency ON money_exchange TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_to_currency ON money_exchange TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_from_amount ON money_exchange TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_to_amount ON money_exchange TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_fx_rate ON money_exchange TYPE record<fx_rate>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_effective_at ON money_exchange TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON money_exchange TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD a_contexts ON money_exchange TYPE array<record> DEFAULT []
    REFERENCE ON DELETE UNSET COMMENT '@rebase-provenance';
DEFINE FIELD d1_from_is_position ON money_exchange TYPE bool VALUE
    record::tb($this.a_from) = 'treasury_account' OR record::tb($this.a_from) = 'misc_account';
DEFINE FIELD d2_to_is_position ON money_exchange TYPE bool VALUE
    record::tb($this.a_to) = 'treasury_account' OR record::tb($this.a_to) = 'misc_account';
DEFINE FIELD e_guard ON money_exchange TYPE bool VALUE {
    LET $from_type = record::tb($this.a_from);
    LET $to_type = record::tb($this.a_to);
    IF $this.a_from = $this.a_to { THROW 'ACCOUNTS_EXCHANGE_SAME_ENDPOINT'; };
    IF $this.a_from_currency = $this.a_to_currency {
        THROW 'ACCOUNTS_EXCHANGE_SAME_CURRENCY';
    };
    IF !$this.d1_from_is_position AND !$this.d2_to_is_position {
        THROW 'ACCOUNTS_EXCHANGE_REQUIRES_POSITION';
    };
    IF $this.d1_from_is_position AND $this.a_from.a_currency != $this.a_from_currency {
        THROW 'ACCOUNTS_EXCHANGE_FROM_CURRENCY';
    };
    IF $this.d2_to_is_position AND $this.a_to.a_currency != $this.a_to_currency {
        THROW 'ACCOUNTS_EXCHANGE_TO_CURRENCY';
    };
    IF $from_type = 'organization' AND $to_type = 'organization' {
        THROW 'ACCOUNTS_EXCHANGE_EXTERNAL_TO_EXTERNAL';
    };
    IF !(
        ($this.a_fx_rate.a_base_currency = $this.a_from_currency
            AND $this.a_fx_rate.a_quote_currency = $this.a_to_currency)
        OR ($this.a_fx_rate.a_base_currency = $this.a_to_currency
            AND $this.a_fx_rate.a_quote_currency = $this.a_from_currency)
    ) { THROW 'ACCOUNTS_EXCHANGE_FX_PAIR'; };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_money_exchange_idempotency ON TABLE money_exchange
    FIELDS a_idempotency_key UNIQUE;
DEFINE INDEX OVERWRITE idx_accounts_money_exchange_time ON TABLE money_exchange
    FIELDS a_effective_at;

DEFINE TABLE OVERWRITE inventory_movement SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_from ON inventory_movement
    TYPE record<operating_unit | organization | misc_inventory_node>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_to ON inventory_movement
    TYPE record<operating_unit | organization | misc_inventory_node>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_item ON inventory_movement TYPE record<item>
    REFERENCE ON DELETE REJECT READONLY;
-- Quantity edits are applied as an atomic old/new delta to inventory
-- positions.  The item, endpoints, and effective time stay immutable.
DEFINE FIELD a_quantity ON inventory_movement TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_unit_value ON inventory_movement TYPE option<decimal> DEFAULT NONE
    ASSERT $value = NONE OR $value >= 0dec;
DEFINE FIELD a_value_currency ON inventory_movement TYPE option<record<currency>>
    REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_effective_at ON inventory_movement TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON inventory_movement TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD a_contexts ON inventory_movement TYPE array<record> DEFAULT []
    REFERENCE ON DELETE UNSET COMMENT '@rebase-provenance';
DEFINE FIELD a_description ON inventory_movement TYPE option<string> DEFAULT NONE;
DEFINE FIELD d1_from_is_position ON inventory_movement TYPE bool VALUE
    record::tb($this.a_from) = 'operating_unit';
DEFINE FIELD d2_to_is_position ON inventory_movement TYPE bool VALUE
    record::tb($this.a_to) = 'operating_unit';
DEFINE FIELD d3_adjustment ON inventory_movement TYPE decimal VALUE {
    LET $movement_id = $this.id;
    RETURN array::fold(
        (SELECT VALUE a_delta FROM inventory_adjustment_line WHERE a_target = $movement_id),
        0dec,
        |$total, $delta| $total + ($delta ?? 0dec)
    );
};
DEFINE FIELD d4_net_quantity ON inventory_movement TYPE decimal VALUE
    ($this.a_quantity ?? 0dec) + ($this.d3_adjustment ?? 0dec) ASSERT $value > 0dec;
DEFINE FIELD e_guard ON inventory_movement TYPE bool VALUE {
    IF $this.a_from = $this.a_to { THROW 'ACCOUNTS_INVENTORY_SAME_ENDPOINT'; };
    IF !$this.d1_from_is_position AND !$this.d2_to_is_position {
        THROW 'ACCOUNTS_INVENTORY_REQUIRES_UNIT';
    };
    IF ($this.a_unit_value = NONE) != ($this.a_value_currency = NONE) {
        THROW 'ACCOUNTS_INVENTORY_VALUE_PAIR';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_inventory_movement_idempotency ON TABLE inventory_movement
    FIELDS a_idempotency_key UNIQUE;
DEFINE INDEX OVERWRITE idx_accounts_inventory_movement_time ON TABLE inventory_movement
    FIELDS a_effective_at;

DEFINE TABLE OVERWRITE service_capacity SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_operating_unit ON service_capacity TYPE record<operating_unit>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_service ON service_capacity TYPE record<service>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_quantity ON service_capacity TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_effective_at ON service_capacity TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON service_capacity TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE INDEX OVERWRITE idx_accounts_service_capacity_idempotency ON TABLE service_capacity
    FIELDS a_idempotency_key UNIQUE;

DEFINE TABLE OVERWRITE service_delivery SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_operating_unit ON service_delivery TYPE record<operating_unit>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_service ON service_delivery TYPE record<service>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_organization ON service_delivery TYPE option<record<organization>>
    REFERENCE ON DELETE REJECT DEFAULT NONE READONLY;
DEFINE FIELD a_quantity ON service_delivery TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_effective_at ON service_delivery TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON service_delivery TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD a_contexts ON service_delivery TYPE array<record> DEFAULT []
    REFERENCE ON DELETE UNSET COMMENT '@rebase-provenance';
DEFINE INDEX OVERWRITE idx_accounts_service_delivery_idempotency ON TABLE service_delivery
    FIELDS a_idempotency_key UNIQUE;

-- -------------------------------------------------------------------------
-- Claims, tax, settlement, reversals, and adjustments
-- -------------------------------------------------------------------------

DEFINE TABLE OVERWRITE invoice SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_organization ON invoice TYPE record<organization>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_currency ON invoice TYPE record<currency>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_direction ON invoice TYPE string
    ASSERT $value IN ['receivable', 'payable'] READONLY;
DEFINE FIELD a_number ON invoice TYPE option<string> DEFAULT NONE;
DEFINE FIELD a_effective_at ON invoice TYPE datetime READONLY;
DEFINE FIELD a_locked ON invoice TYPE bool DEFAULT false;
DEFINE FIELD a_contexts ON invoice TYPE array<record> DEFAULT []
    REFERENCE ON DELETE UNSET COMMENT '@rebase-provenance';
DEFINE FIELD a_order_context ON invoice TYPE option<record> DEFAULT NONE
    REFERENCE ON DELETE UNSET COMMENT '@rebase-provenance';
DEFINE FIELD e_guard ON invoice TYPE bool VALUE {
    RETURN true;
} ASSERT $value = true;
-- Human invoice numbers are only unique within their issuing organization.
DEFINE INDEX OVERWRITE idx_accounts_invoice_number ON TABLE invoice
    FIELDS a_organization, a_number UNIQUE;

DEFINE TABLE OVERWRITE invoice_line SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_invoice ON invoice_line TYPE record<invoice>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_subject ON invoice_line TYPE record<item | service>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_description ON invoice_line TYPE option<string> DEFAULT NONE;
DEFINE FIELD a_quantity ON invoice_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_unit_price ON invoice_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD d1_organization ON invoice_line TYPE record<organization>
    VALUE $this.a_invoice.a_organization COMMENT '@rebase-derived-reference';
DEFINE FIELD d2_currency ON invoice_line TYPE record<currency>
    VALUE $this.a_invoice.a_currency COMMENT '@rebase-derived-reference';
DEFINE FIELD d3_subject_type ON invoice_line TYPE string VALUE record::tb($this.a_subject);
DEFINE FIELD d4_base_amount ON invoice_line TYPE decimal VALUE
    ($this.a_quantity ?? 0dec) * ($this.a_unit_price ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD d5_tax_amount ON invoice_line TYPE decimal VALUE {
    LET $line_id = $this.id;
    RETURN array::fold(
        (SELECT VALUE d3_amount FROM tax_input WHERE a_invoice_line = $line_id),
        0dec,
        |$total, $amount| $total + ($amount ?? 0dec)
    )
    + array::fold(
        (SELECT VALUE d3_amount FROM tax_output WHERE a_invoice_line = $line_id),
        0dec,
        |$total, $amount| $total + ($amount ?? 0dec)
    );
};
DEFINE FIELD d6_gross_amount ON invoice_line TYPE decimal VALUE
    ($this.d4_base_amount ?? 0dec) + ($this.d5_tax_amount ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD e_guard ON invoice_line TYPE bool VALUE {
    IF $this.a_invoice.a_locked = true AND $before = NONE {
        THROW 'ACCOUNTS_INVOICE_LOCKED';
    };
    IF $before != NONE AND $before.a_invoice.a_locked = true
        AND ($before.a_subject != $after.a_subject
            OR $before.a_quantity != $after.a_quantity
            OR $before.a_unit_price != $after.a_unit_price) {
        THROW 'ACCOUNTS_INVOICE_LOCKED';
    };
    IF ($this.d6_gross_amount ?? 0dec) < 0dec {
        THROW 'ACCOUNTS_INVOICE_NEGATIVE_CLAIM';
    };
    RETURN true;
} ASSERT $value = true;

DEFINE TABLE OVERWRITE tax_input SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_invoice_line ON tax_input TYPE record<invoice_line>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_rule ON tax_input TYPE record<tax_rule>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_rate ON tax_input TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD d1_currency ON tax_input TYPE record<currency>
    VALUE $this.a_invoice_line.d2_currency COMMENT '@rebase-derived-reference';
DEFINE FIELD d2_base_amount ON tax_input TYPE decimal VALUE
    ($this.a_invoice_line.d4_base_amount ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD d3_amount ON tax_input TYPE decimal VALUE {
    LET $tax_id = $this.id;
    RETURN (($this.d2_base_amount ?? 0dec) * (($this.a_rate ?? 0dec) / 100dec))
        + array::fold(
            (SELECT VALUE a_delta FROM tax_adjustment_line WHERE a_target = $tax_id),
            0dec,
            |$total, $delta| $total + ($delta ?? 0dec)
        );
} ASSERT $value >= 0dec;
DEFINE FIELD e_guard ON tax_input TYPE bool VALUE {
    IF $this.a_invoice_line.a_invoice.a_locked = true AND $before = NONE {
        THROW 'ACCOUNTS_INVOICE_LOCKED';
    };
    IF $this.a_invoice_line.a_invoice.a_direction != 'payable' {
        THROW 'ACCOUNTS_TAX_INPUT_DIRECTION';
    };
    IF $before != NONE AND $before.a_invoice_line.a_invoice.a_locked = true
        AND ($before.a_rule != $after.a_rule OR $before.a_rate != $after.a_rate) {
        THROW 'ACCOUNTS_INVOICE_LOCKED';
    };
    RETURN true;
} ASSERT $value = true;

DEFINE TABLE OVERWRITE tax_output SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_invoice_line ON tax_output TYPE record<invoice_line>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_rule ON tax_output TYPE record<tax_rule>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_rate ON tax_output TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD d1_currency ON tax_output TYPE record<currency>
    VALUE $this.a_invoice_line.d2_currency COMMENT '@rebase-derived-reference';
DEFINE FIELD d2_base_amount ON tax_output TYPE decimal VALUE
    ($this.a_invoice_line.d4_base_amount ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD d3_amount ON tax_output TYPE decimal VALUE {
    LET $tax_id = $this.id;
    RETURN (($this.d2_base_amount ?? 0dec) * (($this.a_rate ?? 0dec) / 100dec))
        + array::fold(
            (SELECT VALUE a_delta FROM tax_adjustment_line WHERE a_target = $tax_id),
            0dec,
            |$total, $delta| $total + ($delta ?? 0dec)
        );
} ASSERT $value >= 0dec;
DEFINE FIELD e_guard ON tax_output TYPE bool VALUE {
    IF $this.a_invoice_line.a_invoice.a_locked = true AND $before = NONE {
        THROW 'ACCOUNTS_INVOICE_LOCKED';
    };
    IF $this.a_invoice_line.a_invoice.a_direction != 'receivable' {
        THROW 'ACCOUNTS_TAX_OUTPUT_DIRECTION';
    };
    IF $before != NONE AND $before.a_invoice_line.a_invoice.a_locked = true
        AND ($before.a_rule != $after.a_rule OR $before.a_rate != $after.a_rate) {
        THROW 'ACCOUNTS_INVOICE_LOCKED';
    };
    RETURN true;
} ASSERT $value = true;

DEFINE TABLE OVERWRITE payment_application SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_payment ON payment_application TYPE record<money_movement>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_invoice ON payment_application TYPE record<invoice>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_amount ON payment_application TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_idempotency_key ON payment_application TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD e_guard ON payment_application TYPE bool VALUE {
    LET $payment_from = record::tb($this.a_payment.a_from);
    LET $payment_to = record::tb($this.a_payment.a_to);
    IF $this.a_payment.a_currency != $this.a_invoice.a_currency {
        THROW 'ACCOUNTS_APPLICATION_CURRENCY';
    };
    IF $this.a_invoice.a_direction = 'receivable'
        AND !($payment_from = 'organization'
            AND $this.a_payment.a_from = $this.a_invoice.a_organization
            AND $payment_to IN ['treasury_account', 'misc_account']) {
        THROW 'ACCOUNTS_APPLICATION_DIRECTION';
    };
    IF $this.a_invoice.a_direction = 'payable'
        AND !($payment_to = 'organization'
            AND $this.a_payment.a_to = $this.a_invoice.a_organization
            AND $payment_from IN ['treasury_account', 'misc_account']) {
        THROW 'ACCOUNTS_APPLICATION_DIRECTION';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_application_idempotency ON TABLE payment_application
    FIELDS a_idempotency_key UNIQUE;

DEFINE TABLE OVERWRITE money_refund SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_original_payment ON money_refund TYPE record<money_movement>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_amount ON money_refund TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_effective_at ON money_refund TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON money_refund TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD d1_source_endpoint ON money_refund
    TYPE record<treasury_account | misc_account | organization>
    VALUE $this.a_original_payment.a_from COMMENT '@rebase-derived-reference';
DEFINE FIELD d2_destination_endpoint ON money_refund
    TYPE record<treasury_account | misc_account | organization>
    VALUE $this.a_original_payment.a_to COMMENT '@rebase-derived-reference';
DEFINE FIELD d3_currency ON money_refund TYPE record<currency>
    VALUE $this.a_original_payment.a_currency COMMENT '@rebase-derived-reference';
DEFINE FIELD d4_source_is_position ON money_refund TYPE bool VALUE
    $this.a_original_payment.d1_from_is_position;
DEFINE FIELD d5_destination_is_position ON money_refund TYPE bool VALUE
    $this.a_original_payment.d2_to_is_position;
DEFINE FIELD e_guard ON money_refund TYPE bool VALUE {
    IF record::tb($this.a_original_payment.a_from) != 'organization'
        AND record::tb($this.a_original_payment.a_to) != 'organization' {
        THROW 'ACCOUNTS_REFUND_REQUIRES_ORGANIZATION';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_money_refund_idempotency ON TABLE money_refund
    FIELDS a_idempotency_key UNIQUE;

DEFINE TABLE OVERWRITE inventory_return SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_original_movement ON inventory_return TYPE record<inventory_movement>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_quantity ON inventory_return TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_effective_at ON inventory_return TYPE datetime READONLY;
DEFINE FIELD a_idempotency_key ON inventory_return TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0 READONLY;
DEFINE FIELD d1_source_endpoint ON inventory_return
    TYPE record<operating_unit | organization | misc_inventory_node>
    VALUE $this.a_original_movement.a_from COMMENT '@rebase-derived-reference';
DEFINE FIELD d2_destination_endpoint ON inventory_return
    TYPE record<operating_unit | organization | misc_inventory_node>
    VALUE $this.a_original_movement.a_to COMMENT '@rebase-derived-reference';
DEFINE FIELD d3_item ON inventory_return TYPE record<item>
    VALUE $this.a_original_movement.a_item COMMENT '@rebase-derived-reference';
DEFINE FIELD d4_source_is_position ON inventory_return TYPE bool VALUE
    $this.a_original_movement.d1_from_is_position;
DEFINE FIELD d5_destination_is_position ON inventory_return TYPE bool VALUE
    $this.a_original_movement.d2_to_is_position;
DEFINE FIELD e_guard ON inventory_return TYPE bool VALUE {
    IF !$this.a_original_movement.d1_from_is_position
        OR record::tb($this.a_original_movement.a_to) != 'organization' {
        THROW 'ACCOUNTS_RETURN_REQUIRES_DELIVERY';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_inventory_return_idempotency ON TABLE inventory_return
    FIELDS a_idempotency_key UNIQUE;

DEFINE TABLE OVERWRITE adjustment_note SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_organization ON adjustment_note TYPE option<record<organization>>
    REFERENCE ON DELETE REJECT DEFAULT NONE READONLY;
DEFINE FIELD a_name ON adjustment_note TYPE string VALUE string::trim($value)
    ASSERT string::len($value) > 0;
DEFINE FIELD a_locked ON adjustment_note TYPE bool DEFAULT false;

DEFINE TABLE OVERWRITE money_adjustment_line SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_note ON money_adjustment_line TYPE record<adjustment_note>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_target ON money_adjustment_line TYPE record<money_movement>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_delta ON money_adjustment_line TYPE decimal ASSERT $value != 0dec;
DEFINE FIELD e_guard ON money_adjustment_line TYPE bool VALUE {
    IF $this.a_note.a_locked = true AND $before = NONE {
        THROW 'ACCOUNTS_ADJUSTMENT_LOCKED';
    };
    IF $this.a_note.a_organization != NONE
        AND $this.a_target.a_from != $this.a_note.a_organization
        AND $this.a_target.a_to != $this.a_note.a_organization {
        THROW 'ACCOUNTS_ADJUSTMENT_ORGANIZATION';
    };
    IF $before != NONE AND $before.a_note.a_locked = true AND $before.a_delta != $after.a_delta {
        THROW 'ACCOUNTS_ADJUSTMENT_LOCKED';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_money_adjustment_unique ON TABLE money_adjustment_line
    FIELDS a_note, a_target UNIQUE;

DEFINE TABLE OVERWRITE inventory_adjustment_line SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_note ON inventory_adjustment_line TYPE record<adjustment_note>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_target ON inventory_adjustment_line TYPE record<inventory_movement>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_delta ON inventory_adjustment_line TYPE decimal ASSERT $value != 0dec;
DEFINE FIELD e_guard ON inventory_adjustment_line TYPE bool VALUE {
    IF $this.a_note.a_locked = true AND $before = NONE {
        THROW 'ACCOUNTS_ADJUSTMENT_LOCKED';
    };
    IF $this.a_note.a_organization != NONE
        AND $this.a_target.a_from != $this.a_note.a_organization
        AND $this.a_target.a_to != $this.a_note.a_organization {
        THROW 'ACCOUNTS_ADJUSTMENT_ORGANIZATION';
    };
    IF $before != NONE AND $before.a_note.a_locked = true AND $before.a_delta != $after.a_delta {
        THROW 'ACCOUNTS_ADJUSTMENT_LOCKED';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_inventory_adjustment_unique ON TABLE inventory_adjustment_line
    FIELDS a_note, a_target UNIQUE;

DEFINE TABLE OVERWRITE tax_adjustment_line SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_note ON tax_adjustment_line TYPE record<adjustment_note>
    REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD a_target ON tax_adjustment_line TYPE record<tax_input | tax_output>
    REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD a_delta ON tax_adjustment_line TYPE decimal ASSERT $value != 0dec;
DEFINE FIELD e_guard ON tax_adjustment_line TYPE bool VALUE {
    IF $this.a_note.a_locked = true AND $before = NONE {
        THROW 'ACCOUNTS_ADJUSTMENT_LOCKED';
    };
    IF $this.a_note.a_organization != NONE
        AND $this.a_target.a_invoice_line.d1_organization != $this.a_note.a_organization {
        THROW 'ACCOUNTS_ADJUSTMENT_ORGANIZATION';
    };
    IF $before != NONE AND $before.a_note.a_locked = true AND $before.a_delta != $after.a_delta {
        THROW 'ACCOUNTS_ADJUSTMENT_LOCKED';
    };
    RETURN true;
} ASSERT $value = true;
DEFINE INDEX OVERWRITE idx_accounts_tax_adjustment_unique ON TABLE tax_adjustment_line
    FIELDS a_note, a_target UNIQUE;
