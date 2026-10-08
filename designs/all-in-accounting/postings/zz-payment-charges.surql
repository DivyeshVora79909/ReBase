-- A deterministic charge is part of the payment fact, with independent memberships.
-- All bounds/basis are in the paying treasury currency; explicit rates convert costs/credit.
DEFINE FUNCTION OVERWRITE fn::accounting::fee_validate($row: object) {
    IF $row.fee_account = NONE {
        IF $row.fee_rate != 0dec OR $row.fee_lower_bound != 0dec OR $row.fee_upper_bound != NONE
            OR $row.fee_tax_rate != 0dec OR $row.fee_tax_lower_bound != 0dec OR $row.fee_tax_upper_bound != NONE
            OR $row.fee_tax_creditable OR $row.fee_tax_account != NONE
            OR $row.fee_exchange_rate != 1dec OR $row.fee_tax_exchange_rate != 1dec { THROW 'FEE_ACCOUNT_REQUIRED'; };
        RETURN NONE;
    };
    IF $row.fee_treasury = NONE { THROW 'FEE_CASH_LEG_REQUIRED'; };
    IF $row.fee_account = $row.fee_treasury { THROW 'FEE_ACCOUNT_IS_TREASURY'; };
    fn::accounting::rate_validate($row.fee_currency, $row.fee_account_currency, $row.fee_exchange_rate);
    fn::accounting::precision_validate($row.fee_lower_bound, $row.fee_currency);
    fn::accounting::precision_validate($row.fee_tax_lower_bound, $row.fee_currency);
    IF $row.fee_upper_bound != NONE {
        fn::accounting::precision_validate($row.fee_upper_bound, $row.fee_currency);
        IF $row.fee_upper_bound < $row.fee_lower_bound { THROW 'FEE_BOUNDS'; };
    };
    IF $row.fee_tax_upper_bound != NONE {
        fn::accounting::precision_validate($row.fee_tax_upper_bound, $row.fee_currency);
        IF $row.fee_tax_upper_bound < $row.fee_tax_lower_bound { THROW 'FEE_TAX_BOUNDS'; };
    };
    IF $row.fee_tax_creditable {
        IF $row.fee_tax_account = NONE { THROW 'FEE_TAX_ACCOUNT_REQUIRED'; };
        fn::accounting::rate_validate($row.fee_currency, $row.fee_tax_currency, $row.fee_tax_exchange_rate);
    } ELSE IF $row.fee_tax_account != NONE OR $row.fee_tax_exchange_rate != 1dec { THROW 'FEE_TAX_ACCOUNT_UNUSED'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::fee_members($row: object) {
    fn::accounting::fee_validate($row);
    IF $row.fee_account = NONE { RETURN fn::accounting::payment_analytics($row); };
    LET $cost = $row.fee_amount + $row.fee_tax_amount;
    LET $reserved = record::tb($row.id) = 'production_cost';
    RETURN array::concat([
        fn::accounting::balance_member($row, 'z_fee_cash', $row.fee_treasury, $row.fee_at,
            fn::accounting::effects(-$cost, 0dec, IF $reserved THEN -$cost ELSE 0dec END), false),
        fn::accounting::balance_member($row, 'z_fee_account', $row.fee_account, $row.fee_at,
            fn::accounting::effects($row.fee_account_amount, 0dec, 0dec), false),
        IF $row.fee_tax_creditable THEN fn::accounting::balance_member($row, 'z_fee_tax', $row.fee_tax_account, $row.fee_at,
            fn::accounting::effects($row.fee_credit_amount, $row.fee_credit_amount, 0dec), false) ELSE NONE END,
        IF $reserved THEN fn::accounting::balance_member($row, 'z_fee_reservation', $row.fee_treasury, $row.starts_at,
            fn::accounting::effects(0dec, 0dec, $cost), false) ELSE NONE END], fn::accounting::payment_analytics($row));
} PERMISSIONS NONE;

DEFINE FIELD OVERWRITE fee_account ON invoice_settlement TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON invoice_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON invoice_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON invoice_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON invoice_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON invoice_settlement TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON invoice_settlement TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON invoice_settlement TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON invoice_settlement TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON invoice_settlement TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON invoice_settlement TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON invoice_settlement TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON invoice_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON invoice_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON invoice_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON invoice_settlement TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON invoice_settlement TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON invoice_settlement TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON invoice_settlement TYPE decimal VALUE math::abs(($this.amount)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON invoice_settlement TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON invoice_settlement TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON invoice_settlement TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON invoice_settlement TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON invoice_settlement TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON invoice_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON invoice_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON invoice_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON payment_refund TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON payment_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON payment_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON payment_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON payment_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON payment_refund TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON payment_refund TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON payment_refund TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON payment_refund TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON payment_refund TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON payment_refund TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON payment_refund TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON payment_refund TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON payment_refund TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON payment_refund TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON payment_refund TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON payment_refund TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON payment_refund TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON payment_refund TYPE decimal VALUE math::abs(($this.amount)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON payment_refund TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON payment_refund TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON payment_refund TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON payment_refund TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON payment_refund TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON payment_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON payment_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON payment_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON payment_adjustment TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON payment_adjustment TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON payment_adjustment TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON payment_adjustment TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON payment_adjustment TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON payment_adjustment TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON payment_adjustment TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON payment_adjustment TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON payment_adjustment TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON payment_adjustment TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON payment_adjustment TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON payment_adjustment TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON payment_adjustment TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON payment_adjustment TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON payment_adjustment TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON payment_adjustment TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON payment_adjustment TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON payment_adjustment TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON payment_adjustment TYPE decimal VALUE math::abs(($this.amount_delta)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON payment_adjustment TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON payment_adjustment TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON payment_adjustment TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON payment_adjustment TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON payment_adjustment TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON payment_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON payment_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON payment_adjustment TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON claim_settlement TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON claim_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON claim_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON claim_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON claim_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON claim_settlement TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON claim_settlement TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON claim_settlement TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON claim_settlement TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON claim_settlement TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON claim_settlement TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON claim_settlement TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON claim_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON claim_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON claim_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON claim_settlement TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON claim_settlement TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON claim_settlement TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON claim_settlement TYPE decimal VALUE math::abs(($this.amount)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON claim_settlement TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON claim_settlement TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON claim_settlement TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON claim_settlement TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON claim_settlement TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON claim_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON claim_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON claim_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON tax_settlement TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON tax_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON tax_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON tax_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON tax_settlement TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON tax_settlement TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON tax_settlement TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON tax_settlement TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON tax_settlement TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON tax_settlement TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON tax_settlement TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON tax_settlement TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON tax_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON tax_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON tax_settlement TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON tax_settlement TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON tax_settlement TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON tax_settlement TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON tax_settlement TYPE decimal VALUE math::abs(($this.amount)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON tax_settlement TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON tax_settlement TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON tax_settlement TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON tax_settlement TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON tax_settlement TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON tax_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON tax_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON tax_settlement TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON tax_deposit TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON tax_deposit TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON tax_deposit TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON tax_deposit TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON tax_deposit TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON tax_deposit TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON tax_deposit TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON tax_deposit TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON tax_deposit TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON tax_deposit TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON tax_deposit TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON tax_deposit TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON tax_deposit TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON tax_deposit TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON tax_deposit TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON tax_deposit TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON tax_deposit TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON tax_deposit TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON tax_deposit TYPE decimal VALUE math::abs(($this.amount)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON tax_deposit TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON tax_deposit TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON tax_deposit TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON tax_deposit TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON tax_deposit TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON tax_deposit TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON tax_deposit TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON tax_deposit TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON tax_refund TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON tax_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON tax_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON tax_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON tax_refund TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON tax_refund TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON tax_refund TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON tax_refund TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON tax_refund TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON tax_refund TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON tax_refund TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON tax_refund TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON tax_refund TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON tax_refund TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON tax_refund TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON tax_refund TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON tax_refund TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON tax_refund TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON tax_refund TYPE decimal VALUE math::abs(($this.amount)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON tax_refund TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON tax_refund TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON tax_refund TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON tax_refund TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON tax_refund TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON tax_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON tax_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON tax_refund TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON resource_exchange TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON resource_exchange TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON resource_exchange TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON resource_exchange TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON resource_exchange TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON resource_exchange TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON resource_exchange TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON resource_exchange TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON resource_exchange TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON resource_exchange TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON resource_exchange TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON resource_exchange TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE IF record::tb($this.from_resource) = 'currency' THEN $this.from_account ELSE IF record::tb($this.to_resource) = 'currency' THEN $this.to_account ELSE NONE END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON resource_exchange TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON resource_exchange TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON resource_exchange TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON resource_exchange TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON resource_exchange TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON resource_exchange TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON resource_exchange TYPE decimal VALUE math::abs((IF record::tb($this.from_resource) = 'currency' THEN $this.from_amount ELSE IF record::tb($this.to_resource) = 'currency' THEN $this.to_amount ELSE 0dec END)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON resource_exchange TYPE datetime VALUE $this.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON resource_exchange TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON resource_exchange TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON resource_exchange TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON resource_exchange TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON resource_exchange TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON resource_exchange TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON resource_exchange TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';

DEFINE FIELD OVERWRITE fee_account ON production_cost TYPE option<record<misc_currency_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_rate ON production_cost TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_lower_bound ON production_cost TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_rate ON production_cost TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_lower_bound ON production_cost TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_upper_bound ON production_cost TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_upper_bound ON production_cost TYPE option<decimal> ASSERT $value = NONE OR $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_exchange_rate ON production_cost TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_exchange_rate ON production_cost TYPE decimal DEFAULT 1dec ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_creditable ON production_cost TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_tax_account ON production_cost TYPE option<record<indirect_tax_account>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fee_treasury ON production_cost TYPE option<record<treasury | misc_currency_account>> REFERENCE ON DELETE REJECT VALUE $this.treasury COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_currency ON production_cost TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_currency ON production_cost TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_currency ON production_cost TYPE option<record<currency>> REFERENCE ON DELETE REJECT VALUE $this.fee_tax_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_precision ON production_cost TYPE int VALUE $this.fee_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_precision ON production_cost TYPE int VALUE $this.fee_account_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_precision ON production_cost TYPE int VALUE $this.fee_tax_currency.precision ?? 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_basis ON production_cost TYPE decimal VALUE math::abs(($this.amount)) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_at ON production_cost TYPE datetime VALUE $this.ends_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_amount ON production_cost TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_basis, $this.fee_rate, $this.fee_lower_bound, $this.fee_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_tax_amount ON production_cost TYPE decimal VALUE IF $this.fee_account = NONE THEN 0dec ELSE fn::accounting::tax_rule($this.fee_amount, $this.fee_tax_rate, $this.fee_tax_lower_bound, $this.fee_tax_upper_bound, $this.fee_precision) END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_account_amount ON production_cost TYPE decimal VALUE fn::accounting::round(($this.fee_amount + IF $this.fee_tax_creditable THEN 0dec ELSE $this.fee_tax_amount END) * $this.fee_exchange_rate, $this.fee_account_precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE fee_credit_amount ON production_cost TYPE decimal VALUE IF $this.fee_tax_creditable THEN fn::accounting::round($this.fee_tax_amount * $this.fee_tax_exchange_rate, $this.fee_tax_precision) ELSE 0dec END COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_fee_cash ON production_cost TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_account ON production_cost TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_fee_tax ON production_cost TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner indirect_tax_account.z_history';
DEFINE FIELD OVERWRITE z_fee_reservation ON production_cost TYPE option<object>  COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
