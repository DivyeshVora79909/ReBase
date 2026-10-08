# Worked accounting inputs

Run `node dev-tools/accounting/fixture-example.js` for eleven validated, editable
inputs and native SDK bindings. The fixture creates typed descriptors, accounts,
stock, an invoice, its issue, and an earlier-dated advance. It opens no database
connection. Provision the tenant explicitly before inserting these rows.

## Invoice and advance

```surql
CREATE sales_invoice:sale SET owned_by=rebase_tenant:demo,
    organization=organization:customer, invoice_date=d'2027-01-10';
CREATE sales_issue:line SET owned_by=rebase_tenant:demo,
    invoice=sales_invoice:sale, stock_account=stock_account:goods,
    quantity=10dec, price=10dec, exchange_rate=1dec, effective_at=d'2027-01-05';
CREATE invoice_settlement:advance SET owned_by=rebase_tenant:demo,
    invoice=sales_invoice:sale, treasury=treasury:cash,
    amount=80dec, exchange_rate=1dec, effective_at=d'2027-01-02';
```

The accounts already exist with the same currency, and stock is available.
The payment is effective before the issue. Its invoice-date outstanding
is 20. Changing it to 101 rejects and restores the complete transaction.

## Split, aggregate, calculate again

```surql
CREATE issue_tax:cgst SET owned_by=rebase_tenant:demo,
    source=sales_issue:line, tax_account=indirect_tax_account:cgst,
    rate=9dec, exchange_rate=1dec, effective_at=d'2027-01-06';
CREATE issue_tax:sgst SET owned_by=rebase_tenant:demo,
    source=sales_issue:line, tax_account=indirect_tax_account:sgst,
    rate=9dec, exchange_rate=1dec, effective_at=d'2027-01-06';
CREATE issue_net_tax:surcharge SET owned_by=rebase_tenant:demo,
    source=sales_issue:line, tax_account=indirect_tax_account:surcharge,
    rate=10dec, upper_bound=20dec, exchange_rate=1dec,
    effective_at=d'2027-01-07';
```

The surcharge sees 118 and contributes 11.80. Inserting an earlier base tax or
changing an earlier rate recalculates it. The account names are example labels,
not a jurisdiction or a predefined tax workflow.

## Explicit corrections

```surql
CREATE issue_adjustment:quantity SET owned_by=rebase_tenant:demo,
    source=sales_issue:line, quantity_delta=-2dec, effective_at=d'2027-01-11';
CREATE adjustment_tax:cgst SET owned_by=rebase_tenant:demo,
    adjustment=issue_adjustment:quantity, source_tax=issue_tax:cgst,
    effective_at=d'2027-01-11T00:00:01Z';
CREATE adjustment_tax:sgst SET owned_by=rebase_tenant:demo,
    adjustment=issue_adjustment:quantity, source_tax=issue_tax:sgst,
    effective_at=d'2027-01-11T00:00:01Z';
CREATE adjustment_tax:surcharge SET owned_by=rebase_tenant:demo,
    adjustment=issue_adjustment:quantity, source_tax=issue_net_tax:surcharge,
    effective_at=d'2027-01-11T00:00:02Z';
```

Two units return to stock; value changes by -20. Base-tax reversals are -1.80
each. The surcharge reversal sees -23.60 and is -2.36. Editing the original
rates updates both the original tax and these linked changes. For a price or FX
correction, use `price_delta` or `exchange_rate_delta` instead, one per record.

Use `issue_return` and `payment_refund` on/before the invoice date. After that
date use `issue_adjustment` and a negative `payment_adjustment.amount_delta`.
When a correction would overpay the invoice, enter its cash reversal first.
All affected sources can still be in one explicit database transaction.

## Future production

```surql
CREATE production:run SET owned_by=rebase_tenant:demo, name='Run',
    starts_at=d'2027-01-20', ends_at=d'2027-01-21';
CREATE production_input:material SET owned_by=rebase_tenant:demo,
    production=production:run, stock_account=stock_account:material, quantity=5dec;
CREATE production_input:labor SET owned_by=rebase_tenant:demo,
    production=production:run, stock_account=stock_account:labor, quantity=2dec;
CREATE production_output:goods SET owned_by=rebase_tenant:demo,
    production=production:run, stock_account=stock_account:goods, quantity=3dec;
CREATE production_cost:cash SET owned_by=rebase_tenant:demo,
    production=production:run, treasury=treasury:cash, amount=10dec;
CREATE production_capacity:machine SET owned_by=rebase_tenant:demo,
    production=production:run, operating_unit=operating_unit:workshop,
    service=service:machine_time, quantity=1dec;
```

Each row contributes at two times. Stock/cash is reserved at the start; inputs
are consumed and outputs become real at the end. Capacity is occupied for the
half-open interval. References and availability must already exist; outputs do
not manufacture their own input supply.

```surql
-- Strictly before the finish: the output is still receivable, not real stock.
RETURN fn::tree::read(stock_account:goods, 'z_history', 'before', [d'2027-01-21']);
-- Through the finish timestamp, including every equal-time contribution.
RETURN fn::tree::read(stock_account:goods, 'z_history', 'before', [d'2027-01-21' + 1ns]);
```

## Extending the model

`postings/entries.surql` is the smallest native example: strict scalar inputs,
one typed account reference, one declared node slot and one member function.
Add another table with explicit units, memberships and validators. A foreign
key alone neither changes a balance nor discovers all ancestors automatically.
The source oracle and acceptance probe illustrate backdating, rollback and
reparenting checks for a new composition.

## Adjustment document and inline payment charge

Starting from the `issue_adjustment:quantity` above, group the correction and its
linked tax rows in one sales note, then finalize it:

```surql
CREATE sales_adjustment_note:correction SET owned_by=rebase_tenant:demo,
    organization=organization:customer, number='A-001';
UPDATE issue_adjustment:quantity SET adjustment_note=sales_adjustment_note:correction;
UPDATE sales_adjustment_note:correction SET draft=false;
```

Every nonzero line must have the same sign and organization. Linked tax rows
inherit the grouping. Zero tax changes are neutral. A payment correction can be
included explicitly; its settlement total remains separate from commercial value.

```surql
-- Independent example: use an invoice with at least 10 outstanding.
-- The selected charge/tax accounts already exist in this tenant.
CREATE invoice_settlement:charged SET owned_by=rebase_tenant:demo,
    invoice=sales_invoice:sale, treasury=treasury:cash, amount=10dec,
    exchange_rate=1dec, effective_at=d'2027-01-12',
    fee_account=misc_currency_account:charges, fee_rate=1dec,
    fee_tax_rate=18dec, fee_tax_creditable=true,
    fee_tax_account=indirect_tax_account:input_credit, include_analytics=true;
```

The example rule charges 0.10, its tax rounds to 0.02, and treasury receives
9.88 while invoice settlement stays 10. The charge account receives 0.10 real;
the tax account receives 0.02 real and 0.02 receivable. These are authored example
rates and an explicit creditability choice, not a legal schedule. Use the
[extension contract](extension-contract.md) for tax cash, transfers and analytics
queries, including currency and resource boundaries.
