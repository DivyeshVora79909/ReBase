-- The all-in-one profile owns one principal pair.  The framework binds the
-- complete authentication/authorization implementation onto these markers.
DEFINE TABLE OVERWRITE user SCHEMAFULL COMMENT '@rebase-principal user';
DEFINE TABLE OVERWRITE groups SCHEMAFULL COMMENT '@rebase-principal group';
