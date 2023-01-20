use jwks_client::error::Error as JwksError;
pub use jwks_client::keyset::KeyStore;
use log::*;
use reqwest::Client;
#[cfg(feature = "rocket")]
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
};
#[cfg(feature = "openapi")]
use rocket_okapi::request::OpenApiFromRequest;
use serde::{Deserialize, Serialize};
#[cfg(feature = "static-tokens")]
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[cfg(feature = "axum")]
mod axum;
#[cfg(test)]
mod tests;

/// Expected size for auth tokens.
const AUTH_TOKEN_LENGTH: usize = 40;
/// Warn about expiring System scope JWTs when valid for less than one week.
const SYSTEM_CONTEXT_WARNING_THRESHOLD: u64 = 60 * 60 * 24 * 7;

pub async fn key_store(url: &str) -> Result<KeyStore, JwksError> {
    KeyStore::new_from(url.to_string()).await
}

/// Errors that can happen when validating authentication
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Error")]
    DecodeError(#[from] JwksError),
    #[error("Error parsing UUID")]
    UuidDecodeError(#[from] uuid::Error),
    #[error("Error in JWT payload")]
    PayloadError,
    #[error("JWT is wrong")]
    TokenInvalid,
    #[error("JWT is missing")]
    TokenMissing,
    #[error("JWT is expired")]
    TokenExpired,
    #[error("JWT missing scope")]
    Unauthorized,
    #[error("Config missing")]
    MissingConfig,
    #[error("Error making request: {0:}")]
    RequestError(#[from] reqwest::Error),
    #[error("Auth token invalid")]
    InvalidAuthToken,
    #[error("Scope is wrong")]
    ScopeError,
    #[error("Missing KeyStore")]
    MissingKeyStore,
    #[error("Invalid Override-Account-UUID header")]
    InvalidOverrideAccountUUID,
}

/// Scopes of access
#[derive(Clone, Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub enum Scope {
    System,
    Link,
    Account,
    Network,
}

#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    client: Client,
    api: Url,
    jwt: String,
}

#[derive(Clone, Default)]
pub struct AuthConfig {
    /// Keystore is a parsed JWKS document that is used to validate JWTs.
    keystore: Option<Arc<KeyStore>>,
    /// API Key Config allows making a request to an external service to validate API keys.
    apikey: Option<ApiKeyConfig>,
    /// Static user tokens resolve to a UUID.
    #[cfg(feature = "static-tokens")]
    static_user: HashMap<String, Uuid>,
    /// Static system tokens resolve to a UUID.
    #[cfg(feature = "static-tokens")]
    static_system: HashMap<String, Uuid>,
    #[cfg(feature = "insecure-stub")]
    /// Enabling this turns off authentication altogether, simply parsing passed tokens
    /// as UUIDs and accepting them as valid.
    insecure_stub: bool,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("keystore", &"keystore")
            .field("apikey", &self.apikey)
            .finish()
    }
}

impl AuthConfig {
    pub fn new() -> AuthConfig {
        AuthConfig::default()
    }

    pub fn with_keystore(self, keystore: KeyStore) -> Self {
        AuthConfig {
            keystore: Some(Arc::new(keystore)),
            apikey: self.apikey,
            #[cfg(feature = "static-tokens")]
            static_user: self.static_user,
            #[cfg(feature = "static-tokens")]
            static_system: self.static_system,
            #[cfg(feature = "insecure-stub")]
            insecure_stub: self.insecure_stub,
        }
    }

    pub fn with_apikey_config(self, client: Client, api: Url, jwt: String) -> Self {
        AuthConfig {
            keystore: self.keystore,
            apikey: Some(ApiKeyConfig { client, api, jwt }),
            #[cfg(feature = "static-tokens")]
            static_user: self.static_user,
            #[cfg(feature = "static-tokens")]
            static_system: self.static_system,
            #[cfg(feature = "insecure-stub")]
            insecure_stub: self.insecure_stub,
        }
    }

    #[cfg(feature = "insecure-stub")]
    pub fn with_insecure_stub(self, stub: bool) -> Self {
        AuthConfig {
            keystore: self.keystore,
            apikey: self.apikey,
            insecure_stub: stub,
            #[cfg(feature = "static-tokens")]
            static_user: self.static_user,
            #[cfg(feature = "static-tokens")]
            static_system: self.static_system,
        }
    }

    #[cfg(feature = "static-tokens")]
    pub fn add_static_user(&mut self, token: &str, uuid: &Uuid) {
        self.static_user.insert(token.to_string(), uuid.clone());
    }

    #[cfg(feature = "static-tokens")]
    pub fn add_static_system(&mut self, token: &str, uuid: &Uuid) {
        self.static_system.insert(token.to_string(), uuid.clone());
    }
}

#[derive(Serialize, Deserialize)]
struct CheckTokenRequest {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct CheckTokenResponse {
    uuid: Uuid,
}

/// Generic request context. May contain idempotency token, request ID, a JWT
/// pulled from the cookies, or a token pulled from the header.
#[cfg_attr(feature = "openapi", derive(OpenApiFromRequest))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserContext {
    account: Uuid,
    scope: Option<Scope>,
    idempotency_token: Option<Uuid>,
    ip_addr: IpAddr,
    system: bool,
}

impl UserContext {
    /// Get request user's account UUID
    pub fn account(&self) -> Uuid {
        self.account.clone()
    }

    pub fn scope(&self) -> &Option<Scope> {
        &self.scope
    }

    /// Get request idempotency token
    pub fn idempotency(&self) -> Option<Uuid> {
        self.idempotency_token.clone()
    }

    /// Get request IP
    pub fn ip(&self) -> IpAddr {
        self.ip_addr
    }

    pub fn allowed(&self, _scope: Scope) -> Result<(), AuthError> {
        Ok(())
    }

    /// Try to validate token
    pub async fn from_token(
        config: &AuthConfig,
        token: &str,
        ip_addr: IpAddr,
    ) -> Result<UserContext, AuthError> {
        let mut system = false;

        #[cfg(feature = "static-tokens")]
        if let Some(uuid) = config.static_user.get(token) {
            return Ok(UserContext {
                account: uuid.clone(),
                scope: None,
                idempotency_token: None,
                ip_addr,
                system: false,
            });
        }

        #[cfg(feature = "static-tokens")]
        if let Some(uuid) = config.static_system.get(token) {
            return Ok(UserContext {
                account: uuid.clone(),
                scope: None,
                idempotency_token: None,
                ip_addr,
                system: true,
            });
        }

        #[cfg(feature = "insecure-stub")]
        if config.insecure_stub {
            if let Ok(account) = Uuid::from_str(token) {
                return Ok(UserContext {
                    account,
                    scope: None,
                    idempotency_token: None,
                    ip_addr,
                    system: false,
                });
            }
        }

        if let Some(api_key_config) = &config.apikey {
            if token.len() == AUTH_TOKEN_LENGTH {
                let request = CheckTokenRequest {
                    token: token.to_string(),
                };
                let response = api_key_config
                    .client
                    .post(&api_key_config.api.to_string())
                    .header("Authorization", format!("Bearer {}", &api_key_config.jwt))
                    .json(&request)
                    .send()
                    .await?;

                if response.status().is_success() {
                    let response = response.json::<CheckTokenResponse>().await?;
                    return Ok(UserContext {
                        account: response.uuid,
                        scope: None,
                        idempotency_token: None,
                        ip_addr,
                        system: false,
                    });
                } else {
                    return Err(AuthError::InvalidAuthToken);
                }
            }
        }

        if let Some(keystore) = &config.keystore {
            let jwt = keystore.verify(token)?;
            let account = jwt.payload().sub().ok_or(AuthError::PayloadError)?;
            let account = Uuid::parse_str(account).map_err(|_| AuthError::PayloadError)?;

            let scopes = jwt
                .payload()
                .get_str("scope")
                .ok_or(AuthError::PayloadError)?;
            let scope_vec: Vec<&str> = scopes.split_whitespace().collect();
            if scope_vec.contains(&"system") {
                system = true;
            }

            Ok(UserContext {
                account,
                scope: None,
                idempotency_token: None,
                ip_addr,
                system,
            })
        } else {
            Err(AuthError::MissingKeyStore)
        }
    }

    pub fn parse_idempotency_token(&mut self, token: &str) -> Result<(), AuthError> {
        let token = Uuid::from_str(token)?;
        self.idempotency_token = Some(token);
        Ok(())
    }

    #[cfg(test)]
    pub fn new_for_test(account: Uuid, ip_addr: IpAddr, idempotency_token: Option<Uuid>) -> Self {
        UserContext {
            account,
            ip_addr,
            scope: None,
            idempotency_token,
            system: false,
        }
    }
}

#[cfg(feature = "rocket")]
#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserContext {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match IpAddr::from_request(req).await {
            Outcome::Success(ip) => ip,
            _ => unimplemented!(),
        };

        let config = match req.rocket().state::<AuthConfig>() {
            Some(config) => config,
            None => {
                return Outcome::Failure((Status::InternalServerError, AuthError::MissingConfig))
            }
        };

        let token = match req
            .headers()
            .get_one("Authorization")
            .map(|h| h.to_string())
        {
            Some(s) => s,
            None => return Outcome::Failure((Status::Unauthorized, AuthError::TokenMissing)),
        };
        let token = match token.strip_prefix("Bearer ") {
            Some(token) => token,
            None => return Outcome::Failure((Status::Unauthorized, AuthError::TokenMissing)),
        };
        let mut auth = match UserContext::from_token(config, &token, ip).await {
            Ok(auth) => auth,
            Err(e) => return Outcome::Failure((Status::Unauthorized, e)),
        };

        if auth.system {
            let header = req
                .headers()
                .get_one("Override-Account-UUID")
                .map(|h| h.to_string());
            if let Some(header) = header {
                auth.account = header
                    .parse()
                    .err_map(|_| AuthError::InvalidOverrideAccountUUID)?;
            }
        }

        // get idempotency token
        match req.headers().get_one("Idempotency-Token") {
            Some(token) => {
                auth.parse_idempotency_token(&token.to_string());
            }
            None => {}
        }

        Outcome::Success(auth)
    }
}

/// System request context. May contain idempotency token, request ID, a JWT
/// pulled from the cookies, or a token pulled from the header. This context
/// requires 'system' claim.
#[cfg_attr(feature = "openapi", derive(OpenApiFromRequest))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemContext {
    account: Uuid,
    scope: Option<Scope>,
    idempotency_token: Option<Uuid>,
    ip_addr: IpAddr,
}

impl SystemContext {
    /// Get request user's account UUID
    pub fn account(&self) -> Uuid {
        self.account.clone()
    }

    pub fn scope(&self) -> &Option<Scope> {
        &self.scope
    }

    /// Get request idempotency token
    pub fn idempotency(&self) -> Option<Uuid> {
        self.idempotency_token.clone()
    }

    /// Get request IP
    pub fn ip(&self) -> IpAddr {
        self.ip_addr
    }

    pub fn allowed(&self, _scope: Scope) -> Result<(), AuthError> {
        Ok(())
    }

    /// Try to validate token
    pub async fn from_token(
        config: &AuthConfig,
        token: &str,
        ip_addr: IpAddr,
    ) -> Result<SystemContext, AuthError> {
        #[cfg(feature = "static-tokens")]
        if let Some(uuid) = config.static_system.get(token) {
            return Ok(SystemContext {
                account: uuid.clone(),
                scope: None,
                idempotency_token: None,
                ip_addr,
            });
        }

        #[cfg(feature = "insecure-stub")]
        if config.insecure_stub {
            if let Ok(account) = Uuid::from_str(token) {
                return Ok(SystemContext {
                    account,
                    scope: None,
                    idempotency_token: None,
                    ip_addr,
                });
            }
        }

        if let Some(keystore) = &config.keystore {
            let jwt = keystore.verify(token)?;
            let account = jwt.payload().sub().ok_or(AuthError::PayloadError)?;
            let account = Uuid::parse_str(account).map_err(|_| AuthError::PayloadError)?;
            let scopes = jwt
                .payload()
                .get_str("scope")
                .ok_or(AuthError::PayloadError)?;
            let scope_vec: Vec<&str> = scopes.split_whitespace().collect();

            if !scope_vec.contains(&"system") {
                return Err(AuthError::ScopeError);
            }

            debug!("Current: {:?}", SystemTime::now());
            let expiry = SystemTime::now() + Duration::from_secs(SYSTEM_CONTEXT_WARNING_THRESHOLD);
            debug!("Expiry: {expiry:?}");
            debug!("JWT expiry: {:?}", jwt.payload().expiry());
            if jwt.expired_time(expiry) == Some(true) {
                warn!("SystemContext token will expire in one week");
            }

            Ok(SystemContext {
                account,
                scope: None,
                idempotency_token: None,
                ip_addr,
            })
        } else {
            Err(AuthError::MissingKeyStore)
        }
    }

    /// This method will pretend to check a token, but always accept it without
    /// inspecting it. Only meant for usage while debugging.
    pub async fn danger_insecure_accept(
        _config: &AuthConfig,
        _token: &str,
        ip_addr: IpAddr,
    ) -> Result<SystemContext, AuthError> {
        Ok(SystemContext {
            account: Uuid::from_str("aeaaa28d-f1b7-4d8a-9257-797cff0f77c1").unwrap(),
            scope: None,
            idempotency_token: None,
            ip_addr,
        })
    }

    pub fn parse_idempotency_token(&mut self, token: &str) -> Result<(), AuthError> {
        let token = Uuid::from_str(token)?;
        self.idempotency_token = Some(token);
        Ok(())
    }

    #[cfg(test)]
    pub fn new_for_test(account: Uuid, ip_addr: IpAddr, idempotency_token: Option<Uuid>) -> Self {
        SystemContext {
            account,
            ip_addr,
            scope: None,
            idempotency_token,
        }
    }
}

#[cfg(feature = "rocket")]
#[rocket::async_trait]
impl<'r> FromRequest<'r> for SystemContext {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match IpAddr::from_request(req).await {
            Outcome::Success(ip) => ip,
            _ => unimplemented!(),
        };

        let config = match req.rocket().state::<AuthConfig>() {
            Some(config) => config,
            None => {
                return Outcome::Failure((Status::InternalServerError, AuthError::MissingConfig))
            }
        };

        let token = match req
            .headers()
            .get_one("Authorization")
            .map(|h| h.to_string())
        {
            Some(s) => s,
            None => return Outcome::Failure((Status::Unauthorized, AuthError::TokenMissing)),
        };
        let token = match token.strip_prefix("Bearer ") {
            Some(token) => token,
            None => return Outcome::Failure((Status::Unauthorized, AuthError::TokenMissing)),
        };
        let mut auth = match SystemContext::from_token(config, &token, ip).await {
            Ok(auth) => auth,
            Err(e) => return Outcome::Failure((Status::Unauthorized, e)),
        };

        let header = req
            .headers()
            .get_one("Override-Account-UUID")
            .map(|h| h.to_string());
        if let Some(header) = header {
            auth.account = header
                .parse()
                .err_map(|_| AuthError::InvalidOverrideAccountUUID)?;
        }

        // get idempotency token
        match req.headers().get_one("Idempotency-Token") {
            Some(token) => {
                auth.parse_idempotency_token(&token.to_string());
            }
            None => {}
        }

        Outcome::Success(auth)
    }
}

#[cfg(feature = "static-tokens")]
#[derive(thiserror::Error, Debug, Clone)]
pub enum StaticTokenError {
    #[error("Missing Token")]
    MissingToken,
    #[error("Error parsing static token UUID: {0:}")]
    UuidParse(#[from] uuid::Error),
    #[error("Unexpected extra part while parsing static token: {0:}")]
    ExtraTokenParts(String),
}

/// Convenience CLI wrapper type for static tokens.
#[cfg(feature = "static-tokens")]
#[derive(Clone, Debug)]
pub struct StaticToken {
    pub token: String,
    pub account: Uuid,
}

#[cfg(feature = "static-tokens")]
impl StaticToken {
    /// New static token from token and account Uuid.
    pub fn new(token: String, account: Uuid) -> Self {
        StaticToken { token, account }
    }

    /// New static token from token with random account Uuid.
    pub fn new_random(token: String) -> Self {
        StaticToken {
            token,
            account: Uuid::new_v4(),
        }
    }

    /// Get token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Get account Uuid.
    pub fn account(&self) -> &Uuid {
        &self.account
    }
}

#[cfg(feature = "static-tokens")]
impl std::str::FromStr for StaticToken {
    type Err = StaticTokenError;
    fn from_str(from: &str) -> Result<Self, Self::Err> {
        let mut parts = from.split(":");
        let token = parts
            .next()
            .ok_or(StaticTokenError::MissingToken)?
            .to_string();
        let account = if let Some(account) = parts.next() {
            account.parse()?
        } else {
            Uuid::default()
        };
        if let Some(part) = parts.next() {
            return Err(StaticTokenError::ExtraTokenParts(part.to_string()));
        }
        Ok(StaticToken { token, account })
    }
}
