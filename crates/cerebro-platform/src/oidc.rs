use std::{
    collections::BTreeSet,
    env,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, errors::ErrorKind, jwk::JwkSet,
};
use reqwest::{Client, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use cerebro_organizational_model::TenantId;

const MAX_BEARER_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_JWKS_KEYS: usize = 64;
const MAX_IDENTITY_VALUE_BYTES: usize = 256;
const MAX_ENTITLEMENTS: usize = 64;
const MIN_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub(crate) struct OidcAuthenticator {
    audience: Arc<str>,
    issuer: Arc<str>,
    jwks_url: Url,
    client: Client,
    keys: Arc<RwLock<JwkSet>>,
    last_refresh: Arc<Mutex<Instant>>,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedIdentity {
    pub(crate) tenant: TenantId,
    pub(crate) actor_id: String,
    pub(crate) actor_label: String,
    pub(crate) display_name: String,
    pub(crate) initials: String,
    pub(crate) email: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) subject: String,
    pub(crate) groups: Vec<String>,
    pub(crate) roles: Vec<String>,
    pub(crate) scopes: BTreeSet<String>,
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) key_id: String,
}

#[derive(Debug)]
pub(crate) enum OidcConfiguration {
    Disabled,
    Configured(OidcAuthenticator),
}

#[derive(Debug)]
pub(crate) enum AuthenticationError {
    Invalid,
    Unavailable(String),
}

#[derive(Debug, Deserialize)]
struct Claims {
    aud: Audience,
    email: Option<String>,
    #[serde(rename = "exp")]
    _expires_at: u64,
    groups: Option<Vec<String>>,
    iss: String,
    name: Option<String>,
    preferred_username: Option<String>,
    roles: Option<Vec<String>>,
    scope: Option<String>,
    sub: String,
    tenant_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Serialize)]
pub(crate) struct CurrentUserResponse {
    authenticated: bool,
    fallback: bool,
    user: CurrentUser,
}

#[derive(Serialize)]
struct CurrentUser {
    #[serde(rename = "actorId")]
    actor_id: String,
    #[serde(rename = "actorLabel")]
    actor_label: String,
    confidence: &'static str,
    #[serde(rename = "displayName")]
    display_name: String,
    initials: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    subject: String,
    provider: &'static str,
    source: &'static str,
    entitlements: IdentityEntitlements,
    evidence: IdentityEvidence,
}

#[derive(Serialize)]
struct IdentityEntitlements {
    groups: Vec<String>,
    roles: Vec<String>,
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct IdentityEvidence {
    claims: Vec<&'static str>,
    jwt: JwtEvidence,
}

#[derive(Serialize)]
struct JwtEvidence {
    algorithm: &'static str,
    audience: String,
    issuer: String,
    #[serde(rename = "keyId")]
    key_id: String,
    signature: &'static str,
}

impl OidcAuthenticator {
    pub(crate) async fn from_env() -> Result<OidcConfiguration, String> {
        let issuer = env::var("CEREBRO_IDENTITY_ISSUER").ok();
        let audience = env::var("CEREBRO_IDENTITY_AUDIENCE").ok();
        let jwks_url = env::var("CEREBRO_IDENTITY_JWKS_URL").ok();
        match (issuer, audience, jwks_url) {
            (None, None, None) => Ok(OidcConfiguration::Disabled),
            (Some(issuer), Some(audience), Some(jwks_url)) => Self::new(issuer, audience, jwks_url)
                .await
                .map(OidcConfiguration::Configured),
            _ => Err("CEREBRO_IDENTITY_ISSUER, CEREBRO_IDENTITY_AUDIENCE, and \
                 CEREBRO_IDENTITY_JWKS_URL must be configured together"
                .to_owned()),
        }
    }

    async fn new(issuer: String, audience: String, jwks_url: String) -> Result<Self, String> {
        validate_identity_value("issuer", &issuer)?;
        validate_identity_value("audience", &audience)?;
        let jwks_url = Url::parse(&jwks_url)
            .map_err(|error| format!("CEREBRO_IDENTITY_JWKS_URL is invalid: {error}"))?;
        validate_jwks_url(&jwks_url)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .build()
            .map_err(|error| format!("failed to build the OIDC HTTP client: {error}"))?;
        let keys = fetch_keys(&client, &jwks_url).await?;
        Ok(Self {
            audience: Arc::from(audience),
            issuer: Arc::from(issuer),
            jwks_url,
            client,
            keys: Arc::new(RwLock::new(keys)),
            last_refresh: Arc::new(Mutex::new(Instant::now())),
        })
    }

    pub(crate) async fn authenticate(
        &self,
        bearer: &str,
    ) -> Result<AuthenticatedIdentity, AuthenticationError> {
        if bearer.is_empty() || bearer.len() > MAX_BEARER_BYTES {
            return Err(AuthenticationError::Invalid);
        }
        let header = decode_header(bearer).map_err(|_| AuthenticationError::Invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthenticationError::Invalid);
        }
        let key_id = header
            .kid
            .filter(|value| validate_identity_value("key id", value).is_ok())
            .ok_or(AuthenticationError::Invalid)?;

        match self.decode_with_cached_key(bearer, &key_id).await {
            Ok(identity) => Ok(identity),
            Err(DecodeFailure::Refreshable) => {
                self.refresh().await?;
                self.decode_with_cached_key(bearer, &key_id)
                    .await
                    .map_err(|_| AuthenticationError::Invalid)
            }
            Err(DecodeFailure::Invalid) => Err(AuthenticationError::Invalid),
        }
    }

    async fn decode_with_cached_key(
        &self,
        bearer: &str,
        key_id: &str,
    ) -> Result<AuthenticatedIdentity, DecodeFailure> {
        let jwk = self
            .keys
            .read()
            .await
            .find(key_id)
            .cloned()
            .ok_or(DecodeFailure::Refreshable)?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| DecodeFailure::Invalid)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 30;
        validation.validate_nbf = true;
        validation.set_audience(&[self.audience.as_ref()]);
        validation.set_issuer(&[self.issuer.as_ref()]);
        validation.set_required_spec_claims(&["aud", "exp", "iss", "sub"]);
        let token = decode::<Claims>(bearer, &key, &validation).map_err(|error| {
            if matches!(error.kind(), ErrorKind::InvalidSignature) {
                DecodeFailure::Refreshable
            } else {
                DecodeFailure::Invalid
            }
        })?;
        self.identity_from_claims(token.claims, key_id)
            .map_err(|_| DecodeFailure::Invalid)
    }

    async fn refresh(&self) -> Result<(), AuthenticationError> {
        let mut last_refresh = self.last_refresh.lock().await;
        if last_refresh.elapsed() < MIN_JWKS_REFRESH_INTERVAL {
            return Ok(());
        }
        *last_refresh = Instant::now();
        let keys = fetch_keys(&self.client, &self.jwks_url)
            .await
            .map_err(AuthenticationError::Unavailable)?;
        *self.keys.write().await = keys;
        Ok(())
    }

    fn identity_from_claims(
        &self,
        claims: Claims,
        key_id: &str,
    ) -> Result<AuthenticatedIdentity, String> {
        validate_identity_value("subject", &claims.sub)?;
        validate_identity_value("tenant", &claims.tenant_id)?;
        validate_identity_value("issuer", &claims.iss)?;
        let tenant = TenantId::parse(claims.tenant_id).map_err(|error| error.to_string())?;
        let email = validate_optional("email", claims.email)?;
        let username = validate_optional("preferred username", claims.preferred_username)?;
        let name = validate_optional("name", claims.name)?;
        let groups = validate_list("groups", claims.groups.unwrap_or_default())?;
        let roles = validate_list("roles", claims.roles.unwrap_or_default())?;
        let scopes = validate_scopes(claims.scope.as_deref().unwrap_or_default())?;
        let audience = claims.aud.display_value(&self.audience)?;
        let actor_label = email
            .clone()
            .or_else(|| username.clone())
            .unwrap_or_else(|| claims.sub.clone());
        let display_name = name.unwrap_or_else(|| actor_label.clone());
        Ok(AuthenticatedIdentity {
            tenant,
            actor_id: claims.sub.clone(),
            actor_label,
            initials: initials(&display_name),
            display_name,
            email,
            username,
            subject: claims.sub,
            groups,
            roles,
            scopes,
            issuer: claims.iss,
            audience,
            key_id: key_id.to_owned(),
        })
    }
}

impl Audience {
    fn display_value(self, expected: &str) -> Result<String, String> {
        let values = match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        };
        let values = validate_list("audience", values)?;
        if !values.iter().any(|value| value == expected) {
            return Err("audience does not contain the configured value".to_owned());
        }
        Ok(expected.to_owned())
    }
}

impl AuthenticatedIdentity {
    pub(crate) fn has_scope(&self, required: &str) -> bool {
        self.scopes.contains(required)
    }

    pub(crate) fn current_user_response(&self) -> CurrentUserResponse {
        CurrentUserResponse {
            authenticated: true,
            fallback: false,
            user: CurrentUser {
                actor_id: self.actor_id.clone(),
                actor_label: self.actor_label.clone(),
                confidence: "signature-verified",
                display_name: self.display_name.clone(),
                initials: self.initials.clone(),
                email: self.email.clone(),
                username: self.username.clone(),
                subject: self.subject.clone(),
                provider: "bearer-jwt",
                source: "jwt",
                entitlements: IdentityEntitlements {
                    groups: self.groups.clone(),
                    roles: self.roles.clone(),
                    scopes: self.scopes.iter().cloned().collect(),
                },
                evidence: IdentityEvidence {
                    claims: vec!["aud", "exp", "iss", "sub", "tenant_id"],
                    jwt: JwtEvidence {
                        algorithm: "RS256",
                        audience: self.audience.clone(),
                        issuer: self.issuer.clone(),
                        key_id: self.key_id.clone(),
                        signature: "verified",
                    },
                },
            },
        }
    }
}

#[derive(Debug)]
enum DecodeFailure {
    Invalid,
    Refreshable,
}

async fn fetch_keys(client: &Client, url: &Url) -> Result<JwkSet, String> {
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|error| format!("failed to fetch OIDC JWKS: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "OIDC JWKS endpoint returned HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
    {
        return Err("OIDC JWKS exceeds the response limit".to_owned());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("failed to read OIDC JWKS: {error}"))?;
        if body.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
            return Err("OIDC JWKS exceeds the response limit".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    let keys: JwkSet =
        serde_json::from_slice(&body).map_err(|error| format!("OIDC JWKS is invalid: {error}"))?;
    if keys.keys.is_empty() || keys.keys.len() > MAX_JWKS_KEYS {
        return Err(format!(
            "OIDC JWKS must contain between 1 and {MAX_JWKS_KEYS} keys"
        ));
    }
    Ok(keys)
}

fn validate_jwks_url(url: &Url) -> Result<(), String> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if url.scheme() == "http" && loopback {
        return Ok(());
    }
    Err(
        "CEREBRO_IDENTITY_JWKS_URL must use HTTPS, except for a loopback development issuer"
            .to_owned(),
    )
}

fn validate_optional(name: &str, value: Option<String>) -> Result<Option<String>, String> {
    value
        .map(|value| {
            validate_identity_value(name, &value)?;
            Ok(value)
        })
        .transpose()
}

fn validate_list(name: &str, values: Vec<String>) -> Result<Vec<String>, String> {
    if values.len() > MAX_ENTITLEMENTS {
        return Err(format!("{name} exceeds the item limit"));
    }
    values
        .into_iter()
        .map(|value| {
            validate_identity_value(name, &value)?;
            Ok(value)
        })
        .collect()
}

fn validate_scopes(value: &str) -> Result<BTreeSet<String>, String> {
    if value.len() > MAX_IDENTITY_VALUE_BYTES * MAX_ENTITLEMENTS {
        return Err("scope exceeds the byte limit".to_owned());
    }
    let scopes = value
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    Ok(validate_list("scope", scopes)?.into_iter().collect())
}

fn validate_identity_value(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{name} is empty, too long, or contains control characters"
        ));
    }
    Ok(())
}

fn initials(display_name: &str) -> String {
    let mut words = display_name
        .split_whitespace()
        .filter_map(|word| word.chars().next())
        .take(2)
        .flat_map(char::to_uppercase)
        .collect::<String>();
    if words.is_empty() {
        words.push('?');
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_url_requires_https_outside_loopback() {
        assert!(validate_jwks_url(&Url::parse("https://issuer.example/jwks").unwrap()).is_ok());
        assert!(validate_jwks_url(&Url::parse("http://127.0.0.1:3000/jwks").unwrap()).is_ok());
        assert!(validate_jwks_url(&Url::parse("http://issuer.example/jwks").unwrap()).is_err());
    }

    #[test]
    fn scope_and_entitlement_bounds_fail_closed() {
        assert!(
            validate_scopes("cerebro:read identity:read")
                .unwrap()
                .contains("cerebro:read")
        );
        assert!(validate_scopes(&"scope ".repeat(MAX_ENTITLEMENTS + 1)).is_err());
        assert!(validate_list("roles", vec!["role\nadmin".to_owned()]).is_err());
    }

    #[test]
    fn initials_are_bounded_to_two_words() {
        assert_eq!(initials("Rust End To End"), "RE");
        assert_eq!(initials(""), "?");
    }
}
