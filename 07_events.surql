USE NS main DB main;

-- 1. THE GATEKEEPERS (Validation Rules via CQRS)
-- Prevent tampering with lines if the parent document is posted/locked
DEFINE EVENT OVERWRITE enforce_document_locks ON TABLE document_line WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
    LET $doc = $after.document_ref OR $before.document_ref;
    IF $doc.status = 'posted' { 
        THROW "DOCUMENT_LOCKED: Cannot modify lines of a posted document."; 
    };
};

-- Prevent over-allocating cash or over-paying an invoice
DEFINE EVENT OVERWRITE assert_payment_limits ON TABLE payment_allocation WHEN $event IN ['CREATE', 'UPDATE'] THEN {
    LET $doc_id = $after.document_ref;
    LET $pay_id = $after.payment_ref;

    -- 1. Check if Document is overpaid
    LET $paid = (SELECT VALUE total_paid FROM v_payment_allocations WHERE document_ref = $doc_id LIMIT 1)[0] ?? 0dec;
    LET $billed = (SELECT VALUE total_amount FROM v_document_totals WHERE document_ref = $doc_id LIMIT 1)[0] ?? 0dec; 
    IF $paid > $billed { 
        THROW "OVERPAYMENT: Allocated cash exceeds the Document's total amount."; 
    };

    -- 2. Check if Payment is over-allocated
    LET $allocated = (SELECT VALUE total_allocated FROM v_payment_outbound WHERE payment_ref = $pay_id LIMIT 1)[0] ?? 0dec;
    IF $allocated > $pay_id.amount {
        THROW "OVER_ALLOCATION: You cannot allocate more cash than the Payment contains.";
    };
};


-- 2. THE TRANSLATORS (Polymorphic Routing to Immutable Ledger)
DEFINE EVENT OVERWRITE translate_document ON TABLE document WHEN $event = 'UPDATE' THEN {
    
    -- [A] POSTING A DOCUMENT
    IF $before.status != 'posted' AND $after.status = 'posted' {
        
        LET $totals = (SELECT total_base, total_tax, total_amount FROM v_document_totals WHERE document_ref = $after.id LIMIT 1)[0] OR { total_base: 0dec, total_tax: 0dec, total_amount: 0dec };
        
        -- Create the Journal Header
        LET $je_id = type::record('journal_entry', rand::ulid());
        CREATE $je_id SET 
            status = 'posted', 
            posting_date = $after.issue_date, 
            description = "Auto-generated for " + $after.document_number,
            source_doc = $after.id,
            owned_by = $after.owned_by;

        -- SALES INVOICE (AR = Debit/Positive, Revenue & Tax = Credit/Negative)
        IF $after.type = 'sales_invoice' {
            LET $ar_account = (SELECT id FROM account WHERE category = 'asset' LIMIT 1)[0]; -- Fallback AR Account resolution
            
            -- AR Line
            CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $ar_account, contact_ref = $after.contact_ref, amount_currency = $totals.total_amount, currency = $after.currency, fx_rate = $after.fx_rate;
            
            -- Revenue Lines (Dynamic map from lines)
            INSERT INTO journal_line (
                SELECT 
                    $je_id AS journal_entry_ref,
                    item_ref.income_account_ref AS account_ref,
                    tracking_tag_ref,
                    (z_base_amount * -1dec) AS amount_currency, 
                    $after.currency AS currency, 
                    $after.fx_rate AS fx_rate 
                FROM document_line WHERE document_ref = $after.id
            );

            -- Tax Lines
            LET $lines = SELECT z_base_amount, taxes FROM document_line WHERE document_ref = $after.id;
            FOR $line IN $lines {
                FOR $tax IN $line.taxes {
                    LET $tax_acc = (SELECT VALUE liability_account_ref FROM $tax.tax_ref LIMIT 1)[0];
                    LET $tax_amt = type::decimal(math::round(($line.z_base_amount * ($tax.rate / 100dec)) * 100dec) / 100dec);
                    CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $tax_acc, amount_currency = ($tax_amt * -1dec), currency = $after.currency, fx_rate = $after.fx_rate;
                };
            };
        };

        -- VENDOR BILL (AP = Credit/Negative, Expense & Tax = Debit/Positive)
        IF $after.type = 'vendor_bill' {
            LET $ap_account = (SELECT id FROM account WHERE category = 'liability' LIMIT 1)[0]; -- Fallback AP Account resolution
            
            -- AP Line
            CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $ap_account, contact_ref = $after.contact_ref, amount_currency = ($totals.total_amount * -1dec), currency = $after.currency, fx_rate = $after.fx_rate;
            
            -- Expense Lines
            INSERT INTO journal_line (
                SELECT 
                    $je_id AS journal_entry_ref,
                    item_ref.expense_account_ref AS account_ref,
                    tracking_tag_ref,
                    z_base_amount AS amount_currency, 
                    $after.currency AS currency, 
                    $after.fx_rate AS fx_rate 
                FROM document_line WHERE document_ref = $after.id
            );

            -- Tax Lines (Assume recoverable taxes, acting as debits)
            LET $lines = SELECT z_base_amount, taxes FROM document_line WHERE document_ref = $after.id;
            FOR $line IN $lines {
                FOR $tax IN $line.taxes {
                    LET $tax_acc = (SELECT VALUE liability_account_ref FROM $tax.tax_ref LIMIT 1)[0];
                    LET $tax_amt = type::decimal(math::round(($line.z_base_amount * ($tax.rate / 100dec)) * 100dec) / 100dec);
                    CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $tax_acc, amount_currency = $tax_amt, currency = $after.currency, fx_rate = $after.fx_rate;
                };
            };
        };
    };

    -- [B] VOIDING A DOCUMENT (Reversing Entries natively)
    IF $before.status = 'posted' AND $after.status = 'void' {
        LET $paid = (SELECT VALUE total_paid FROM v_payment_allocations WHERE document_ref = $after.id LIMIT 1)[0] ?? 0dec;
        IF $paid > 0dec { THROW "CANNOT_VOID_PAID: Document has active payment allocations. Void the payment first."; };

        -- Clone the old journal entry lines but multiply amount_currency by -1 to reverse it
        LET $old_je = (SELECT id FROM journal_entry WHERE source_doc = $after.id LIMIT 1)[0];
        LET $reversal_je_id = type::record('journal_entry', rand::ulid());
        
        CREATE $reversal_je_id SET status = 'posted', posting_date = time::now(), description = "Reversal for " + $after.document_number, source_doc = $after.id, owned_by = $after.owned_by;
        
        INSERT INTO journal_line (
            SELECT 
                $reversal_je_id AS journal_entry_ref, 
                account_ref, 
                contact_ref,
                tracking_tag_ref,
                (amount_currency * -1dec) AS amount_currency, 
                currency, 
                fx_rate 
            FROM journal_line WHERE journal_entry_ref = $old_je.id
        );
    };
};

-- PAYMENT TO LEDGER ROUTING
DEFINE EVENT OVERWRITE translate_payment ON TABLE payment WHEN $event = 'UPDATE' THEN {
    
    IF $before.status != 'posted' AND $after.status = 'posted' {
        LET $je_id = type::record('journal_entry', rand::ulid());
        CREATE $je_id SET status = 'posted', posting_date = $after.payment_date, description = "Payment " + $after.reference, source_doc = $after.id, owned_by = $after.owned_by;

        LET $bank_gl = $after.bank_account_ref.asset_account_ref;
        LET $contact_gl = (SELECT id FROM account WHERE category = IF $after.type = 'receive_money' THEN 'asset' ELSE 'liability' END LIMIT 1)[0];

        IF $after.type = 'receive_money' {
            -- Bank goes UP (Debit), AR goes DOWN (Credit)
            CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $bank_gl, amount_currency = $after.amount, currency = $after.currency, fx_rate = $after.fx_rate;
            CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $contact_gl, contact_ref = $after.contact_ref, amount_currency = ($after.amount * -1dec), currency = $after.currency, fx_rate = $after.fx_rate;
        } ELSE {
            -- Bank goes DOWN (Credit), AP goes DOWN (Debit)
            CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $bank_gl, amount_currency = ($after.amount * -1dec), currency = $after.currency, fx_rate = $after.fx_rate;
            CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $contact_gl, contact_ref = $after.contact_ref, amount_currency = $after.amount, currency = $after.currency, fx_rate = $after.fx_rate;
        };
    };

    IF $before.status = 'posted' AND $after.status = 'void' {
        LET $old_je = (SELECT id FROM journal_entry WHERE source_doc = $after.id LIMIT 1)[0];
        LET $reversal_je_id = type::record('journal_entry', rand::ulid());
        CREATE $reversal_je_id SET status = 'posted', posting_date = time::now(), description = "Reversal of Payment " + $after.reference, source_doc = $after.id, owned_by = $after.owned_by;
        
        INSERT INTO journal_line (SELECT $reversal_je_id AS journal_entry_ref, account_ref, contact_ref, tracking_tag_ref, (amount_currency * -1dec) AS amount_currency, currency, fx_rate FROM journal_line WHERE journal_entry_ref = $old_je.id);
    };
};

-- AUTOMATIC FX GAIN/LOSS (Triggers when a cross-currency allocation occurs)
DEFINE EVENT OVERWRITE auto_fx_gain_loss ON TABLE payment_allocation WHEN $event IN ['CREATE', 'UPDATE'] THEN {
    LET $pay = $after.payment_ref;
    LET $doc = $after.document_ref;
    
    LET $doc_base = $after.doc_currency_amount * ($doc.fx_rate ?? 1dec);
    LET $pay_base = $after.pay_currency_amount * ($pay.fx_rate ?? 1dec);
    LET $diff = $pay_base - $doc_base;
    
    IF $diff != 0dec {
        LET $je_id = type::record('journal_entry', rand::ulid());
        CREATE $je_id SET status = 'posted', posting_date = time::now(), description = "FX Gain/Loss Auto-Correction", source_doc = $after.id, owned_by = $pay.owned_by;
        
        LET $fx_expense_acc = (SELECT id FROM account WHERE category = 'expense' AND name CONTAINS 'FX' LIMIT 1)[0];
        LET $contact_acc = (SELECT id FROM account WHERE category = IF $doc.type = 'sales_invoice' THEN 'asset' ELSE 'liability' END LIMIT 1)[0];

        -- Book the FX Gain/Loss difference directly to the ledger
        CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $fx_expense_acc, amount_currency = math::abs($diff), currency = 'USD', fx_rate = 1dec;
        CREATE journal_line SET journal_entry_ref = $je_id, account_ref = $contact_acc, contact_ref = $doc.contact_ref, amount_currency = (math::abs($diff) * -1dec), currency = 'USD', fx_rate = 1dec;
    };
};