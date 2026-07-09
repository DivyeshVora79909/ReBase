-- ==============================================================================
-- FILE 10: CONFIGURATION & ALGORITHMIC EXCEPTIONS
-- ==============================================================================
USE NS main DB main;

DEFINE TABLE OVERWRITE company SCHEMAFULL;
DEFINE FIELD OVERWRITE default_currency ON company TYPE string ASSERT $value != NONE;
DEFINE FIELD OVERWRITE updated_at ON company TYPE datetime VALUE time::now();
CREATE company:settings SET default_currency = 'USD';