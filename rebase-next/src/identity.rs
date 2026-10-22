//! A narrow standard JWT profile. Keys and cryptographic verification come from
//! jsonwebtoken; mutable permissions never come from token claims.
use crate::{
    json,
    native_codec::uuid_text,
    native_slice::{Error, Result},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const MAX_TOKEN_BYTES: usize = 4096;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub issuer: String,
    pub audience: String,
    /// Public Ed25519 PEM keys indexed by a bounded, explicit rotation key ID.
    pub public_keys: BTreeMap<String, String>,
    pub max_token_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    #[serde(with = "uuid_text")]
    pub sub: Uuid,
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    pub epoch: u64,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    #[serde(with = "uuid_text")]
    pub actor: Uuid,
    pub epoch: u64,
    pub ttl: u64,
    pub key_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenHeader {
    alg: String,
    typ: String,
    kid: String,
}

pub struct Verifier {
    config: IdentityConfig,
    keys: BTreeMap<String, DecodingKey>,
    validation: Validation,
}
fn invalid() -> Error {
    Error::new("unauthenticated", "valid service credential required")
}
fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 64
        && kid
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}
pub fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| invalid())
}
impl Verifier {
    pub fn new(config: IdentityConfig) -> Result<Self> {
        if config.issuer.is_empty()
            || config.audience.is_empty()
            || config.issuer.len() > 256
            || config.audience.len() > 256
            || !(1..=3600).contains(&config.max_token_seconds)
            || config.public_keys.is_empty()
            || config.public_keys.len() > 16
        {
            return Err(Error::new("invalid_input", "identity configuration limits"));
        }
        let mut keys = BTreeMap::new();
        for (kid, pem) in &config.public_keys {
            if !valid_kid(kid) || pem.len() > 4096 {
                return Err(Error::new(
                    "invalid_input",
                    "verification key configuration",
                ));
            }
            keys.insert(
                kid.clone(),
                DecodingKey::from_ed_pem(pem.as_bytes())
                    .map_err(|_| Error::new("invalid_input", "Ed25519 public PEM required"))?,
            );
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "exp", "nbf"]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        Ok(Self {
            config,
            keys,
            validation,
        })
    }
    pub fn verify(&self, token: &str, tenant: Uuid) -> Result<Claims> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(invalid());
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(invalid());
        }
        // Reject duplicate/unknown claims and headers before trusting any value.
        let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|_| invalid());
        let header: TokenHeader =
            serde_json::from_value(json::parse(&decode(parts[0])?).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        if header.alg != "EdDSA" || header.typ != "JWT" || !valid_kid(&header.kid) {
            return Err(invalid());
        }
        let _: Claims =
            serde_json::from_value(json::parse(&decode(parts[1])?).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let key = self.keys.get(&header.kid).ok_or_else(invalid)?;
        let claims = jsonwebtoken::decode::<Claims>(token, key, &self.validation)
            .map_err(|_| invalid())?
            .claims;
        let now = now()?;
        if claims.tenant != tenant
            || claims.iat > now
            || claims.nbf > now
            || claims.nbf < claims.iat
            || claims.exp <= now
            || claims
                .exp
                .checked_sub(claims.iat)
                .is_none_or(|life| life == 0 || life > self.config.max_token_seconds)
        {
            return Err(invalid());
        }
        Ok(claims)
    }
}

/// Offline trusted issuer utility. This has no public RPC endpoint. A real
/// identity provider can issue the same profile; principal epochs stay in store.
pub fn issue(
    config: &IdentityConfig,
    request: &TokenRequest,
    private_pem: &[u8],
) -> Result<String> {
    let TokenRequest {
        tenant,
        actor,
        epoch,
        ttl,
        key_id: kid,
    } = request;
    let verifier = Verifier::new(config.clone())?;
    if !config.public_keys.contains_key(kid) || *ttl == 0 || *ttl > config.max_token_seconds {
        return Err(Error::new("invalid_input", "credential key/lifetime"));
    }
    let at = now()?;
    let claims = Claims {
        iss: config.issuer.clone(),
        aud: config.audience.clone(),
        sub: *actor,
        tenant: *tenant,
        epoch: *epoch,
        iat: at,
        nbf: at,
        exp: at.checked_add(*ttl).ok_or_else(invalid)?,
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.into());
    let key = EncodingKey::from_ed_pem(private_pem)
        .map_err(|_| Error::new("invalid_input", "Ed25519 private PEM required"))?;
    let token = jsonwebtoken::encode(&header, &claims, &key).map_err(|_| invalid())?;
    verifier.verify(&token, *tenant)?; // catch mismatched public/private keys offline
    Ok(token)
}
