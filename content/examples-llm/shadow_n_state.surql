DEFINE TABLE order_line SCHEMAFULL;
    DEFINE FIELD status ON order_line TYPE string
        ASSERT $value IN ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled']
        AND (
            $before = NONE
            OR ($before = 'pending' AND $value IN ['confirmed', 'cancelled'])
            OR ($before = 'confirmed' AND $value IN ['shipped', 'cancelled'])
            OR ($before = 'shipped' AND $value = 'delivered')
            OR ($before = 'cancelled' AND $value = 'cancelled')
            OR ($before = 'delivered' AND $value = 'delivered')
        );

    DEFINE FIELD item_name ON order_line TYPE string;
    DEFINE FIELD amount ON order_line TYPE decimal;
    DEFINE FIELD z_active_amount ON order_line TYPE decimal COMPUTED
        IF status IN ['cancelled', 'delivered'] THEN 0dec ELSE (amount ?? 0dec) END;

CREATE order_line:1 SET item_name = "Widget", amount = 100.00dec, status = 'pending'; -- 100
UPDATE order_line:1 SET status = 'confirmed'; -- 100
UPDATE order_line:1 SET status = 'cancelled'; -- 0
UPDATE order_line:1 SET status = 'shipped'; -- ERROR

CREATE order_line:2 SET item_name = "Gadget", amount = 250.00dec, status = 'pending'; --250
UPDATE order_line:2 SET status = 'confirmed'; -- 250
UPDATE order_line:2 SET status = 'shipped'; -- 250
UPDATE order_line:2 SET status = 'delivered'; -- 0
