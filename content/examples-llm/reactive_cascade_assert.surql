REMOVE TABLE IF EXISTS account;
REMOVE TABLE IF EXISTS transaction;
REMOVE TABLE IF EXISTS v_account_balance;

DEFINE TABLE account SCHEMAFULL;
    DEFINE FIELD name ON account TYPE string;
    DEFINE FIELD overdraft_limit ON account TYPE decimal DEFAULT 0dec;
    -- PARENT ASSERT: Safely handles decimal subtraction
    DEFINE FIELD balance ON account TYPE decimal DEFAULT 0dec
        ASSERT $value >= (0dec - overdraft_limit);
    DEFINE FIELD available_balance ON account TYPE decimal COMPUTED balance + overdraft_limit;

DEFINE TABLE transaction SCHEMAFULL;
    DEFINE FIELD account ON transaction TYPE record<account> REFERENCE ON DELETE REJECT;
    DEFINE FIELD amount ON transaction TYPE decimal;
    DEFINE FIELD description ON transaction TYPE string;
    DEFINE FIELD status ON transaction TYPE string DEFAULT 'draft'
        ASSERT $value IN ['draft', 'posted', 'void'];
    DEFINE FIELD z_posted_amount ON transaction TYPE decimal
        VALUE IF status = 'posted' THEN (amount ?? 0dec) ELSE 0dec END;

DEFINE TABLE v_account_balance AS
    SELECT account, math::sum(z_posted_amount) AS total_balance
    FROM transaction GROUP BY account;

DEFINE EVENT sync_balance ON v_account_balance WHEN $event != 'NONE' THEN {
    LET $tgt = $after.account ?? $before.account;
    UPDATE $tgt SET balance = ($after.total_balance ?? 0dec);
};

-- TEST 1: Normal operations
CREATE account:1 SET name = "Main Account", overdraft_limit = 500dec;
CREATE transaction:1 SET account = account:1, amount = 1000dec, description = "Deposit", status = 'posted';
CREATE transaction:2 SET account = account:1, amount = -200dec, description = "Withdrawal", status = 'posted';

-- Expected: balance 800, available_balance 1300
SELECT balance, available_balance FROM account:1; 


-- TEST 2: ASSERT blocks overdraft beyond limit (posted withdrawal)
-- This will successfully THROW the assertion error and rollback the transaction!
CREATE transaction:3 SET account = account:1, amount = -1500dec, description = "Large withdrawal", status = 'posted';


-- TEST 3: Referential integrity blocks deletion
-- This will successfully THROW a rejection error!
DELETE account:1;


-- TEST 4: Cleanup works after removing children
DELETE transaction;
DELETE account:1;


-- TEST 5: Another account with stricter limit (overdraft_limit = 0)
CREATE account:2 SET name = "Savings", overdraft_limit = 0dec;
CREATE transaction:4 SET account = account:2, amount = 500dec, description = "Deposit", status = 'posted';

-- This will THROW an assertion error (balance would be -100)
CREATE transaction:5 SET account = account:2, amount = -600dec, description = "Overdraft attempt", status = 'posted';


-- TEST 6: Cascading validation through amount update on a posted record
CREATE account:3 SET name = "Joint Account", overdraft_limit = 1000dec;
CREATE transaction:6 SET account = account:3, amount = 2000dec, description = "Initial deposit", status = 'posted';

-- Expected: 2000
SELECT balance FROM account:3; 

-- This will THROW an assertion error: changing amount to -1500 makes balance -1500 < -1000
UPDATE transaction:6 SET amount = -1500dec;


-- TEST 7: Status transitions (draft/void do NOT count)
CREATE account:4 SET name = "Flex Account", overdraft_limit = 200dec;
CREATE transaction:7 SET account = account:4, amount = 300dec, description = "Draft deposit";

SELECT balance FROM account:4; -- Expected: 0
UPDATE transaction:7 SET status = 'posted';
SELECT balance FROM account:4; -- Expected: 300
UPDATE transaction:7 SET status = 'void';
SELECT balance FROM account:4; -- Expected: 0


-- TEST 8: Mixed statuses and bulk updates (FIXED IDs)
CREATE account:5 SET name = "Mixed Account", overdraft_limit = 1000dec;

-- FIXED: Provide explicit IDs so we can target them with UPDATE commands below
INSERT INTO transaction [
    { id: transaction:8_1, account: account:5, amount: 500dec,  status: 'posted', description: "Draft deposit" },
    { id: transaction:8_2, account: account:5, amount: 300dec,  status: 'draft', description: "Draft deposit" },
    { id: transaction:8_3, account: account:5, amount: -100dec, status: 'posted', description: "Draft deposit" },
    { id: transaction:8_4, account: account:5, amount: -200dec, status: 'void', description: "Draft deposit" }
];

SELECT balance FROM account:5; -- Expected: 400

-- Post the draft
UPDATE transaction:8_2 SET status = 'posted'; 
SELECT balance FROM account:5; -- Expected: 700

-- Void the posted -100
UPDATE transaction:8_3 SET status = 'void'; 
SELECT balance FROM account:5; -- Expected: 800