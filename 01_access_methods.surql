USE NS main DB main;

DEFINE ACCESS OVERWRITE account ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET 
            password = crypto::argon2::generate($password), 
            refreshed_at = time::now()
        WHERE email = string::lowercase($email) 
          AND invite_token = type::uuid($invite)
          AND time::unix(time::now()) - time::unix(last_email_sent_at ?? '1970-01-01T00:00:00Z') <= 9000
          AND $password.len() > 6
    )
    SIGNIN (
        UPDATE user SET refreshed_at = time::now()
        WHERE email = string::lowercase($email) 
          AND crypto::argon2::compare(password ?? "", $password)
    )
    AUTHENTICATE {
        IF !$auth.password OR !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;

DEFINE ACCESS OVERWRITE password_management ON DATABASE TYPE RECORD
    SIGNUP (
        fn::send_reset_email(
            (
                UPDATE user SET 
                    last_email_sent_at = time::now(),
                    total_times_email_sent = (total_times_email_sent ?? 0) + 1
                WHERE email = string::lowercase($email) 
                    AND (time::unix(time::now()) - time::unix(last_email_sent_at ?? '1970-01-01T00:00:00Z') >= 60)
            )
        )
    )
    SIGNIN (
        UPDATE user SET 
            password = crypto::argon2::generate($new_password), 
            refreshed_at = time::now()
        WHERE email = string::lowercase($email) 
          AND password != NONE 
          AND crypto::argon2::compare(password ?? "", $password)
          AND $new_password.len() > 6
    )
    AUTHENTICATE {
        IF !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 1ms, FOR TOKEN 1ms;