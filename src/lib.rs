use jwks_client::error::Error as JwksError;
pub use jwks_client::keyset::KeyStore;
use reqwest::Client;
#[cfg(feature = "rocket")]
use rocket::http::Status;
#[cfg(feature = "rocket")]
use rocket::request::{FromRequest, Outcome, Request};
#[cfg(feature = "openapi")]
use rocket_okapi::request::OpenApiFromRequest;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

const AUTH_TOKEN_LENGTH: usize = 40;

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

#[derive(Clone)]
pub struct AuthConfig {
    keystore: Arc<KeyStore>,
    apikey: Option<ApiKeyConfig>,
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
    pub fn new(keystore: KeyStore) -> AuthConfig {
        AuthConfig {
            keystore: Arc::new(keystore),
            apikey: None,
        }
    }

    pub fn apikey_config(&mut self, client: Client, api: Url, jwt: String) {
        self.apikey = Some(ApiKeyConfig { client, api, jwt });
    }
}

#[derive(Serialize)]
struct CheckTokenRequest {
    token: String,
}

#[derive(Deserialize)]
struct CheckTokenResponse {
    uuid: Uuid,
}

/// Generic request context. May contain idempotency token, request ID, a JWT
/// pulled from the cookies, or a token pulled from the header.
#[cfg_attr(feature = "openapi", derive(OpenApiFromRequest))]
pub struct UserContext {
    account: Uuid,
    scope: Option<Scope>,
    idempotency_token: Option<Uuid>,
    ip_addr: IpAddr,
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
                    });
                } else {
                    return Err(AuthError::InvalidAuthToken);
                }
            }
        }

        let jwt = config.keystore.verify(token)?;
        let account = jwt.payload().sub().ok_or(AuthError::PayloadError)?;
        let account = Uuid::parse_str(account).map_err(|_| AuthError::PayloadError)?;

        Ok(UserContext {
            account,
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
        let jwt = config.keystore.verify(token)?;
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

        Ok(SystemContext {
            account,
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
