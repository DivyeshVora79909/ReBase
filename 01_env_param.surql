-- GLOBAL PARAMETERS (Environment Variables)
DEFINE PARAM OVERWRITE $BREVO_API_URL 
    VALUE "https://api.brevo.com/v3/smtp/email" PERMISSIONS NONE;

DEFINE PARAM OVERWRITE $BREVO_API_KEY 
    VALUE "xkeysib-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX-XXXXXXXXXX" PERMISSIONS NONE;

DEFINE PARAM OVERWRITE $EMAIL_SENDER 
    VALUE { "name": "ReBase CRM", "email": "divy.r.vora14@gmail.com" } PERMISSIONS NONE;

DEFINE PARAM OVERWRITE $EMAIL_TEMPLATE_RESET 
    VALUE "
    <div style='font-family: sans-serif; padding: 20px; max-width: 600px; margin: auto;'>
        <h2 style='color: #2c3e50;'>ReBase Authentication</h2>
        <p>Hello <strong>{{name}}</strong>,</p>
        <p>You recently requested a new access token or updated your credentials.</p>
        <p>Your secure access token is:</p>
        <div style='background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 2px; border-radius: 8px; border: 1px solid #ddd;'>
            <strong>{{token}}</strong>
        </div>
        <p style='margin-top: 20px;'>Copy and paste this token into the login screen to authenticate. It will expire shortly.</p>
        <hr style='border: none; border-top: 1px solid #eee; margin-top: 30px;' />
        <small style='color: #888;'>If you did not request this, please contact your System Administrator immediately.</small>
    </div>
    " PERMISSIONS NONE;