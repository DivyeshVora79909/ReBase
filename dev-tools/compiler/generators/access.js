function quote(value) {
  return `'${String(value).replaceAll("\\", "\\\\").replaceAll("'", "\\'")}'`;
}

function identifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) {
    throw new Error(`Invalid principal table identifier: ${value}`);
  }
  return value;
}

function generateOAuthAccess(principals, options = {}) {
  if (!options.runtimeUrl || !options.runtimeSecret) return "";
  const user = identifier(principals?.user);
  const runtimeUrl = String(options.runtimeUrl).replace(/\/+$/, "");
  const authorization = quote(`Bearer ${options.runtimeSecret}`);
  return `DEFINE ACCESS OVERWRITE oauth ON DATABASE TYPE RECORD
    SIGNIN {
        LET $verification = http::post(${quote(`${runtimeUrl}/internal/oauth`)}, {
            provider: string::lowercase(string::trim($provider ?? "")),
            token: $oauth_token
        }, { authorization: ${authorization} });
        IF $verification.verified != true OR !string::is_email($verification.email ?? "") {
            RETURN NONE;
        };
        LET $identity = (SELECT VALUE principal FROM authentication_email
            WHERE address = string::lowercase(string::trim($verification.email))
              AND principal.login_access = true)[0];
        IF $identity = NONE { RETURN NONE; };
        RETURN (SELECT VALUE id FROM ${user} WHERE id = $identity AND login_access = true)[0];
    }
    AUTHENTICATE {
        IF !$auth OR !$auth.login_access { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;`;
}

module.exports = { generateOAuthAccess };
