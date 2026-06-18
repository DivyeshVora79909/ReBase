USE NS main DB main;

LET $flag_tables = ['payment', 'invoice', 'adjustment_note', 'sl'];

FOR $tb IN $flag_tables {
    DEFINE FIELD OVERWRITE suspended ON TABLE $tb TYPE bool DEFAULT false;
    DEFINE FIELD OVERWRITE locked ON TABLE $tb TYPE bool DEFAULT false;
};