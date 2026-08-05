USE NS main DB main;

CREATE user:root SET name = 'Super Admin', email = 'divy.r.vora14@gmail.com';
UPDATE user:root SET password = crypto::argon2::generate("password");
RELATE groups:root -> link -> user:root;
UPDATE user:root SET refreshed_at = time::now();