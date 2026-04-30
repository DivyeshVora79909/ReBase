REMOVE TABLE IF EXISTS product;
REMOVE TABLE IF EXISTS order;

DEFINE TABLE product SCHEMAFULL;
    DEFINE FIELD name ON product TYPE string;
    DEFINE FIELD price ON product TYPE decimal;

DEFINE TABLE order SCHEMAFULL;
    DEFINE FIELD customer ON order TYPE string;
    DEFINE FIELD items ON order TYPE array<object> DEFAULT[];
    DEFINE FIELD items.*.product_link ON order TYPE record<product>;
    DEFINE FIELD items.*.quantity ON order TYPE int;
    DEFINE FIELD computed_prices ON order TYPE array<decimal> DEFAULT[]
        VALUE $this.items.product_link.price ??[];
    DEFINE FIELD computed_total_value ON order TYPE decimal VALUE {
        RETURN (
            SELECT VALUE math::sum( quantity * product_link.price )
            FROM $this.items
            GROUP ALL
        )[0] ?? 0dec;
    };
    DEFINE FIELD computed_total_value_map_method ON order TYPE decimal
        VALUE math::sum(
            ($this.items ??[]).map(|$item| 
                $item.quantity * ($item.product_link.price ?? 0dec)
            )
        ) ?? 0dec;
    DEFINE FIELD computed_max_item_price ON order TYPE decimal
        VALUE array::max($this.items.product_link.price) ?? 0dec;
    DEFINE FIELD computed_receipt ON order TYPE array<object> DEFAULT[] VALUE {
        RETURN (
            SELECT 
                product_link.name AS item_name,
                (quantity * product_link.price) AS total_cost
            FROM $this.items
        );
    };
    DEFINE FIELD computed_receipt.*.item_name ON order TYPE string;
    DEFINE FIELD computed_receipt.*.total_cost ON order TYPE decimal;


CREATE product:laptop SET name = "ProBook", price = 1500.00dec;
CREATE product:mouse SET name = "Wireless Mouse", price = 50.00dec;
CREATE product:cable SET name = "USB-C Cable", price = 20.00dec;

CREATE order:web_sale SET 
    customer = "Alice",
    items =[
        { product_link: product:laptop, quantity: 1 },
        { product_link: product:mouse, quantity: 2 },  -- 2 * 50 = 100
        { product_link: product:cable, quantity: 3 }   -- 3 * 20 = 60
    ];

-- RESULT
SELECT 
    computed_prices,                     -- Expected: [1500.0, 50.0, 20.0]
    computed_total_value,                -- Expected: 1660.0 
    computed_total_value_map_method,     -- Expected: 1660.0
    computed_max_item_price,             -- Expected: 1500.0
    computed_receipt                     -- Expected: Array of named line-items
FROM order:web_sale;