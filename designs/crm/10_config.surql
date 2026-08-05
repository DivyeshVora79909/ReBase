-- ==============================================================================
-- FILE 10: CONFIGURATION & ALGORITHMIC EXCEPTIONS
-- ==============================================================================
USE NS main DB main;

CREATE user:root SET name = 'Super Admin', email = 'divy.r.vora14@gmail.com';
UPDATE user:root SET password = crypto::argon2::generate("password");
RELATE groups:root -> link -> user:root;
UPDATE user:root SET refreshed_at = time::now();

DEFINE TABLE OVERWRITE company SCHEMAFULL;
DEFINE FIELD OVERWRITE default_currency ON company TYPE string ASSERT $value != NONE;
DEFINE FIELD OVERWRITE updated_at ON company TYPE datetime VALUE time::now();
CREATE company:settings SET default_currency = 'USD';