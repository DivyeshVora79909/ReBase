CREATE groups:finance SET name = 'Finance Dept', role = ['node_create', 'node_select', 'node_update', 'node_delete', 'finance_create', 'finance_select', 'finance_update', 'finance_delete', 'order_select', 'link_create'];
CREATE groups:sales SET name = 'Sales Dept', role = ['node_create', 'node_select', 'node_update', 'order_create', 'order_select', 'order_update', 'order_delete', 'inventory_select'];

CREATE user:alice SET name = 'Alice Manager', email = 'alice@company.com';
CREATE user:bob SET name = 'Bob Sales Rep', email = 'bob@company.com';

UPDATE user:root SET last_refreshed_at = time::now();

RELATE groups:finance -> link -> user:alice;
RELATE groups:sales -> link -> user:bob;
RELATE user:alice -> link -> groups:sales;

UPDATE user:alice SET last_refreshed_at = time::now();
UPDATE user:bob SET last_refreshed_at = time::now();

SELECT id, name, parents, dominates, permissions FROM user:alice;
SELECT id, name, parents, dominates, permissions FROM user:bob;

