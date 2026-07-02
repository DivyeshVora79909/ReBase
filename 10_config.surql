-- ==============================================================================
-- FILE 10: CONFIGURATION & ALGORITHMIC EXCEPTIONS
-- ==============================================================================
USE NS main DB main;

DEFINE TABLE company SCHEMAFULL;
DEFINE FIELD default_currency ON company TYPE string ASSERT $value != NONE;
DEFINE FIELD updated_at ON company TYPE datetime VALUE time::now();
CREATE company:settings SET default_currency = 'USD';

-- ==============================================================================
-- THE ABSOLUTE MATRIX GUARD (O(1) Memory Cross-Checking)
-- ==============================================================================

DEFINE EVENT enforce_matrix_stock_in ON TABLE v_sl_matrix_in WHEN $event != 'NONE' THEN {
    IF record::tb($after.node) = 'warehouse' {
        LET $node = $after.node ?? $before.node;
        LET $item = $after.item ?? $before.item;
        LET $in = $after.qty ?? 0dec;
        LET $out = (type::record('v_sl_matrix_out', [$node, $item])).qty ?? 0dec;
        
        IF ($in - $out) < 0dec {
            THROW "PHYSICS_ERR: Action reverted. This causes Warehouse [" + <string>$node + "] to have negative stock (" + <string>($in - $out) + ") for Item [" + <string>$item + "].";
        };
    };
};

DEFINE EVENT enforce_matrix_stock_out ON TABLE v_sl_matrix_out WHEN $event != 'NONE' THEN {
    IF record::tb($after.node) = 'warehouse' {
        LET $node = $after.node ?? $before.node;
        LET $item = $after.item ?? $before.item;
        LET $out = $after.qty ?? 0dec;
        LET $in = (type::record('v_sl_matrix_in', [$node, $item])).qty ?? 0dec;
        
        IF ($in - $out) < 0dec {
            THROW "PHYSICS_ERR: Action reverted. This causes Warehouse [" + <string>$node + "] to have negative stock (" + <string>($in - $out) + ") for Item [" + <string>$item + "].";
        };
    };
};