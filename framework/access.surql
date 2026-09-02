-- Password is one optional credential. Authentication is established by a
-- successful access method, not by the presence of the password field.

DEFINE ACCESS OVERWRITE account_password ON DATABASE TYPE RECORD
    SIGNIN {
        LET $identifier_value = string::lowercase(string::trim($identifier ?? ""));
        LET $email_principal = (SELECT VALUE principal FROM authentication_email
            WHERE address = $identifier_value
              AND verified_revision = revision
              AND principal.login_access = true)[0];
        LET $phone_principal = (SELECT VALUE principal FROM authentication_phone
            WHERE number = $identifier_value
              AND verified_revision = revision
              AND principal.login_access = true)[0];
        LET $username_principal = (SELECT VALUE id FROM user
            WHERE username = $identifier_value AND login_access = true)[0];
        LET $principal = IF $email_principal != NONE THEN $email_principal
            ELSE IF $phone_principal != NONE THEN $phone_principal
            ELSE $username_principal END;
        IF $principal = NONE { RETURN NONE; };

        -- A username is usable only after at least one identity has been
        -- verified. Email and phone candidates already carry that condition.
        IF $email_principal = NONE AND $phone_principal = NONE {
            LET $verified_count = (SELECT VALUE id FROM authentication_email
                WHERE principal = $principal AND verified_revision = revision).len()
                + (SELECT VALUE id FROM authentication_phone
                WHERE principal = $principal AND verified_revision = revision).len();
            IF $verified_count = 0 { RETURN NONE; };
        };

        LET $account = (SELECT * FROM type::record($principal))[0];
        IF $account = NONE OR $account.password = NONE OR $password = NONE
            OR !crypto::argon2::compare($account.password, $password) { RETURN NONE; };
        RETURN $principal;
    }
    AUTHENTICATE {
        IF !$auth OR !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;

DEFINE ACCESS OVERWRITE account_code ON DATABASE TYPE RECORD
    SIGNIN {
        LET $identifier_value = string::lowercase(string::trim($identifier ?? ""));
        LET $code_value = string::trim($code ?? "");
        LET $password_action_value = string::lowercase(string::trim($password_action ?? "keep"));
        LET $password_value = $new_password ?? "";
        IF $password_action_value NOT IN ["keep", "set", "clear"] { RETURN NONE; };
        IF $password_action_value = "set" AND $password_value.len() < 8 { RETURN NONE; };
        IF !string::matches($code_value, /^[0-9]{6}$/) { RETURN NONE; };

        LET $email_identity = (SELECT * FROM authentication_email
            WHERE address = $identifier_value)[0];
        LET $phone_identity = (SELECT * FROM authentication_phone
            WHERE number = $identifier_value)[0];
        LET $username_principal = (SELECT VALUE id FROM user
            WHERE username = $identifier_value AND login_access = true)[0];
        LET $username_challenge = (SELECT * FROM authentication_challenge
            WHERE principal = $username_principal
              AND consumed_at = NONE
              AND expires_at >= time::now()
            ORDER BY expires_at DESC)[0];
        LET $username_identity = IF $username_challenge = NONE THEN NONE
            ELSE (SELECT * FROM type::record($username_challenge.target))[0] END;
        LET $identity = IF $email_identity != NONE THEN $email_identity
            ELSE IF $phone_identity != NONE THEN $phone_identity
            ELSE $username_identity END;
        IF $identity = NONE { RETURN NONE; };
        LET $account = (SELECT * FROM type::record($identity.principal))[0];
        LET $challenge = (SELECT * FROM authentication_challenge
            WHERE target = $identity.id)[0];
        IF $account = NONE OR $challenge = NONE OR $account.login_access != true
            OR $challenge.consumed_at != NONE
            OR $challenge.expires_at < time::now()
            OR $challenge.principal_revision != $account.authentication_revision
            OR $challenge.target_revision != $identity.revision { RETURN NONE; };

        -- Incrementing attempts is the first atomic claim. A later conditional
        -- consume means concurrent correct submissions have exactly one winner.
        LET $attempt = (UPDATE $challenge.id SET attempts = attempts + 1
            WHERE consumed_at = NONE
              AND expires_at >= time::now()
              AND attempts < 5
            RETURN AFTER)[0];
        IF $attempt = NONE OR $code_value.len() = 0
            OR !crypto::argon2::compare($attempt.code_hash, $code_value) { RETURN NONE; };
        LET $consumed = (UPDATE $attempt.id SET consumed_at = time::now()
            WHERE consumed_at = NONE RETURN AFTER)[0];
        IF $consumed = NONE { RETURN NONE; };

        UPDATE $identity.id SET verified_revision = revision, verified_at = time::now();
        IF $password_action_value = "set" {
            UPDATE $account.id SET password = crypto::argon2::generate($password_value);
        } ELSE IF $password_action_value = "clear" {
            UPDATE $account.id SET password = NONE;
        };
        RETURN $account.id;
    }
    AUTHENTICATE {
        IF !$auth OR !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;
