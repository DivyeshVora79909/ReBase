REMOVE TABLE IF EXISTS gold_mine;
REMOVE TABLE IF EXISTS mana_crystal;
REMOVE TABLE IF EXISTS player;
REMOVE TABLE IF EXISTS resource_ledger;
REMOVE TABLE IF EXISTS action_intent;
REMOVE TABLE IF EXISTS v_player_resources;

DEFINE TABLE OVERWRITE gold_mine SCHEMAFULL;
    DEFINE FIELD OVERWRITE yield_rate ON gold_mine TYPE decimal DEFAULT 100dec;

DEFINE TABLE OVERWRITE mana_crystal SCHEMAFULL;
    DEFINE FIELD OVERWRITE yield_rate ON mana_crystal TYPE decimal DEFAULT 50dec;

DEFINE TABLE OVERWRITE player SCHEMAFULL;
    DEFINE FIELD OVERWRITE name ON player TYPE string;

DEFINE TABLE OVERWRITE resource_ledger SCHEMAFULL;
    DEFINE FIELD OVERWRITE player_ref ON resource_ledger TYPE record<player>;
    DEFINE FIELD OVERWRITE resource_type ON resource_ledger TYPE string ASSERT $value IN ['gold', 'mana'];
    DEFINE FIELD OVERWRITE amount ON resource_ledger TYPE decimal;

DEFINE TABLE OVERWRITE action_intent SCHEMAFULL;
    DEFINE FIELD OVERWRITE status ON action_intent TYPE string DEFAULT 'pending';
    DEFINE FIELD OVERWRITE player_ref ON action_intent TYPE record<player>;
    DEFINE FIELD OVERWRITE target_node ON action_intent TYPE record<gold_mine | mana_crystal>;

DEFINE TABLE OVERWRITE v_player_resources AS 
    SELECT 
        player_ref, 
        resource_type, 
        math::sum(amount) AS total_amount 
    FROM resource_ledger 
    GROUP BY player_ref, resource_type;

DEFINE EVENT OVERWRITE enforce_resource_limits ON TABLE resource_ledger WHEN $event IN['CREATE', 'UPDATE'] THEN {
    IF $after.amount < 0dec {
        LET $current_balance = (
            SELECT VALUE total_amount 
            FROM v_player_resources 
            WHERE player_ref = $after.player_ref AND resource_type = $after.resource_type 
            LIMIT 1
        )[0] ?? 0dec;

        IF $current_balance < 0dec {
            THROW "INSUFFICIENT_RESOURCES: Action aborted. You do not have enough " + $after.resource_type;
        };
    };
};

DEFINE EVENT OVERWRITE translate_action ON TABLE action_intent WHEN $event = 'UPDATE' THEN {
    
    IF $before.status != 'executed' AND $after.status = 'executed' {
        LET $res_type = IF record::tb($after.target_node) = 'gold_mine' THEN 'gold' ELSE 'mana' END;
        LET $yield = (SELECT VALUE yield_rate FROM $after.target_node LIMIT 1)[0] ?? 0dec;

        CREATE resource_ledger SET 
            player_ref = $after.player_ref,
            resource_type = $res_type,
            amount = $yield;
    };

    IF $before.status = 'executed' AND $after.status = 'reverted' {
        LET $res_type = IF record::tb($after.target_node) = 'gold_mine' THEN 'gold' ELSE 'mana' END;
        LET $yield = (SELECT VALUE yield_rate FROM $after.target_node LIMIT 1)[0] ?? 0dec;

        CREATE resource_ledger SET 
            player_ref = $after.player_ref,
            resource_type = $res_type,
            amount = $yield * -1dec;
    };
};


-- RESULT
CREATE player:hero SET name = "Arthur";
CREATE gold_mine:cave_1 SET yield_rate = 100dec;
CREATE mana_crystal:shard_1 SET yield_rate = 50dec;

CREATE resource_ledger SET player_ref = player:hero, resource_type = 'mana', amount = 10dec;

CREATE action_intent:mine_gold SET player_ref = player:hero, target_node = gold_mine:cave_1;
UPDATE action_intent:mine_gold SET status = 'executed'; 

SELECT * FROM v_player_resources;

-- INSUFFICIENT_RESOURCES
CREATE resource_ledger SET player_ref = player:hero, resource_type = 'mana', amount = -20dec; 


"
-- VIEWS EXECUTE BEFORE EVENTS: Use enforcer events to enforce rules based on view state for data integrity and very fast O(1) lookups.
-- ENFORCER EVENT FOR CROSS TABLE ASSERTION: Query the view via `SELECT VALUE ... LIMIT 1` ensures synchronous O(1) reads.
-- POLYMORPHISM IN EVENTS: Use `record::tb()` to check which table the reference points to, adapting logic dynamically.
-- POLYMORPHIC ROUTING: Use `record::tb($pointer)` inside events to write declarative logic that effortlessly spans multiple distinct domains.
"