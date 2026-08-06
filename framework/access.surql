USE NS main DB main;

DEFINE ACCESS OVERWRITE account ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET 
            password = crypto::argon2::generate($password),
            invite_token = rand::uuid(),
            invite_expires_at = time::now()
        WHERE email = string::lowercase($email) 
          AND invite_token = type::uuid($invite)
          AND invite_expires_at >= time::now()
          AND $password.len() >= 8
    )
    SIGNIN (
        SELECT id from user 
        WHERE email = string::lowercase($email) 
          AND crypto::argon2::compare(password ?? "", $password)
    )
    AUTHENTICATE {
        IF !$auth.password OR !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;
