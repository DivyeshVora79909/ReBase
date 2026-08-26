DEFINE ACCESS OVERWRITE account ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET 
            password = crypto::argon2::generate($password)
        WHERE email = string::lowercase($email) 
          AND password = NONE
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

DEFINE ACCESS OVERWRITE manage_password ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET
            password = NONE
        WHERE email = string::lowercase($email)
          AND crypto::argon2::compare(password ?? "", $password)
    )
    SIGNIN (
        UPDATE user SET
            password = crypto::argon2::generate($new_password)
        WHERE email = string::lowercase($email)
          AND crypto::argon2::compare(password ?? "", $password)
          AND $new_password.len() >= 8
    )
    AUTHENTICATE {
        IF !$auth.password OR !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 1ms, FOR TOKEN 1ms;
