-- FILE 10: CONFIGURATION & ALGORITHMIC EXCEPTIONS
USE NS main DB main;

DEFINE TABLE company SCHEMAFULL;
DEFINE FIELD default_currency ON company TYPE string ASSERT $value != NONE;
DEFINE FIELD updated_at ON company TYPE datetime VALUE time::now();
CREATE company:settings SET default_currency = 'USD';

DEFINE EVENT ripple_chronological_notes ON TABLE adjustment_line 
WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
    LET $target_org = $after.b_ctx_note_org ?? $before.b_ctx_note_org;
    LET $pivot_time = $after.created_at ?? $before.created_at;
    LET $impacted_notes = (SELECT VALUE id FROM adjustment_note WHERE a_in_org = $target_org AND created_at >= $pivot_time);
    UPDATE adjustment_note SET system_ping = time::now() WHERE id IN $impacted_notes;
};

DEFINE EVENT ripple_base_reality ON TABLE invoice_line
WHEN $event = 'UPDATE' AND $before.d_c2_base_val != $after.d_c2_base_val THEN {
    LET $impacted_notes = (SELECT VALUE a_in_note FROM adjustment_line WHERE a_in_invl = $after.id);
    UPDATE adjustment_note SET system_ping = time::now() WHERE id IN $impacted_notes;
};