USE NS main DB main;

DEFINE FUNCTION OVERWRITE fn::send_reset_email($users: array) {

    IF !$users {
        RETURN NONE;
    };

    LET $user = $users[0];
    LET $BREVO_API_URL = "https://api.brevo.com/v3/smtp/email";
    LET $APP_URL = "http://localhost:5173";
    LET $BREVO_API_KEY = "xkeysib-xxx";
    LET $RESET_URL = $APP_URL + "/auth/verify?token=" + <string>$user.invite_token + "&email=" + $user.email;
    LET $EMAIL_SENDER = {
        "name": "ReBase CRM",
        "email": "divy.r.vora14@gmail.com"
    };

    LET $EMAIL_TEMPLATE = "
    <div style='font-family: sans-serif; padding: 20px; max-width: 600px; margin: auto;'>
        <h2 style='color: #2c3e50;'>Reset Your ReBase Password</h2>

        <p>Hello <strong>{{name}}</strong>,</p>

        <p>
            We received a request to reset the password for your ReBase account.
        </p>

        <p>
            If you made this request, click the button below to choose a new password:
        </p>

        <p style='margin:30px 0;text-align:center;'>
            <a
                href='{{reset_url}}'
                style='display:inline-block;padding:14px 28px;background:#3498db;color:#fff;text-decoration:none;border-radius:6px;font-weight:bold;font-size:16px;'>
                Reset Password
            </a>
        </p>

        <p style='color:#555;'>
            Or copy and paste this token manually:
        </p>

        <div style='background:#f4f4f4;padding:15px;text-align:center;font-size:24px;letter-spacing:2px;border-radius:8px;border:1px solid #ddd;'>
            <strong>{{token}}</strong>
        </div>

        <p style='margin-top:30px;font-size:14px;color:#888;'>
            If you did not request a password reset, simply ignore this email.
        </p>
    </div>
    ";

    LET $html = string::replace(
        string::replace(
            string::replace(
                string::replace(
                    $EMAIL_TEMPLATE,
                    "{{name}}",
                    $user.name
                ),
                "{{token}}",
                <string>$user.invite_token
            ),
            "{{email}}",
            $user.email
        ),
        "{{reset_url}}",
        $RESET_URL
    );

    LET $headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "api-key": $BREVO_API_KEY
    };

    LET $payload = {
        "sender": $EMAIL_SENDER,
        "to": [{
            "email": $user.email,
            "name": $user.name
        }],
        "subject": "Your Secure Access Token",
        "htmlContent": $html
    };

    RETURN http::post($BREVO_API_URL, $payload, $headers);
};