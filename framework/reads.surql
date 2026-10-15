-- Compiler-owned logical subscriptions. Record users cannot forge or invoke them.
DEFINE TABLE OVERWRITE rebase_read SCHEMAFULL PERMISSIONS NONE COMMENT '@rebase-members fn::reads::span_members';
DEFINE FIELD OVERWRITE tenant ON rebase_read TYPE record;
DEFINE FIELD OVERWRITE reader ON rebase_read TYPE record;
DEFINE FIELD OVERWRITE reader_identity ON rebase_read TYPE string;
DEFINE FIELD OVERWRITE phase ON rebase_read TYPE string;
DEFINE FIELD OVERWRITE version ON rebase_read TYPE int;
DEFINE FIELD OVERWRITE source_root ON rebase_read TYPE record;
DEFINE FIELD OVERWRITE source_slot ON rebase_read TYPE string;
DEFINE FIELD OVERWRITE kind ON rebase_read TYPE string;
DEFINE FIELD OVERWRITE channel ON rebase_read TYPE string;
DEFINE FIELD OVERWRITE arguments ON rebase_read TYPE array;
DEFINE FIELD OVERWRITE path ON rebase_read TYPE string;
DEFINE FIELD OVERWRITE fallback ON rebase_read TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE observed ON rebase_read TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE group ON rebase_read TYPE record<rebase_read_group>;
DEFINE FIELD OVERWRITE position ON rebase_read TYPE array;
DEFINE FIELD OVERWRITE z_position ON rebase_read TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key tuple @rebase-tree-owner rebase_read_group.z_positions @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_interval ON rebase_read TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key tuple @rebase-tree-owner rebase_read_group.z_intervals @rebase-tree-no-reader';
DEFINE INDEX OVERWRITE reader_identity ON rebase_read FIELDS reader_identity;
DEFINE INDEX OVERWRITE reader_phase ON rebase_read FIELDS reader, phase;

DEFINE TABLE OVERWRITE rebase_read_group SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE tenant ON rebase_read_group TYPE record;
DEFINE FIELD OVERWRITE source_root ON rebase_read_group TYPE record;
DEFINE FIELD OVERWRITE source_slot ON rebase_read_group TYPE string;
DEFINE FIELD OVERWRITE kind ON rebase_read_group TYPE string;
DEFINE FIELD OVERWRITE channel ON rebase_read_group TYPE string;
DEFINE FIELD OVERWRITE z_positions ON rebase_read_group TYPE object COMMENT '@rebase-tree-root @rebase-tree-key tuple @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_intervals ON rebase_read_group TYPE object COMMENT '@rebase-tree-root @rebase-tree-key tuple @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE rebase_read_frame SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE version ON rebase_read_frame TYPE int;

DEFINE TABLE OVERWRITE rebase_read_lock SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE tenant ON rebase_read_lock TYPE record;
DEFINE FIELD OVERWRITE revision ON rebase_read_lock TYPE int;

-- Logical reads are first collected here while a formula is being evaluated.
-- The compiler flushes one scope's rows in stable order at an explicit
-- evaluation boundary, before publishing the source or its managed outputs.
DEFINE TABLE OVERWRITE rebase_read_stage SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE scope ON rebase_read_stage TYPE string;
DEFINE FIELD OVERWRITE reader ON rebase_read_stage TYPE record;
DEFINE FIELD OVERWRITE phase ON rebase_read_stage TYPE string;
DEFINE FIELD OVERWRITE version ON rebase_read_stage TYPE int;
DEFINE FIELD OVERWRITE read_id ON rebase_read_stage TYPE record<rebase_read>;
DEFINE FIELD OVERWRITE tenant ON rebase_read_stage TYPE record;
DEFINE FIELD OVERWRITE source_root ON rebase_read_stage TYPE record;
DEFINE FIELD OVERWRITE source_slot ON rebase_read_stage TYPE string;
DEFINE FIELD OVERWRITE kind ON rebase_read_stage TYPE string;
DEFINE FIELD OVERWRITE channel ON rebase_read_stage TYPE string;
DEFINE FIELD OVERWRITE arguments ON rebase_read_stage TYPE array;
DEFINE FIELD OVERWRITE path ON rebase_read_stage TYPE string;
DEFINE FIELD OVERWRITE fallback ON rebase_read_stage TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE observed ON rebase_read_stage TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE group ON rebase_read_stage TYPE record<rebase_read_group>;
DEFINE FIELD OVERWRITE position ON rebase_read_stage TYPE array;
DEFINE INDEX OVERWRITE scope ON rebase_read_stage FIELDS scope;
