-- FILE 10: CONFIGURATION & SYSTEM EXCEPTIONS
USE NS main DB main;

-- 1. GLOBAL COMPANY CONFIGURATION
DEFINE TABLE company SCHEMAFULL;
DEFINE FIELD currency ON company TYPE string;
DEFINE FIELD updated_at ON company TYPE datetime VALUE time::now();
CREATE company:settings SET currency = 'USD';

-- 2. EXCEPTION: THE DELTA REBALANCER
DEFINE EVENT ripple_chronological_deltas ON TABLE adjustment_line 
WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
    LET $target_org = $after.b_ctx_note_org ?? $before.b_ctx_note_org;
    LET $pivot_time = $after.created_at ?? $before.created_at;
    
    LET $notes = (
        SELECT VALUE id FROM adjustment_note 
        WHERE a_in_org = $target_org AND created_at >= $pivot_time
    );
    UPDATE $notes SET system_ping = time::now();
};