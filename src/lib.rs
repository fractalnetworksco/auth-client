use jwks_client::error::Error as JwksError;
use jwks_client::keyset::KeyStore;
use rocket::http::Status;
use rocket::outcome;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::uuid::Uuid;
#[cfg(feature = "openapi")]
use rocket_okapi::request::OpenApiFromRequest;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

pub async fn key_store(url: &str) -> Result<KeyStore, JwksError> {
    KeyStore::new_from(url.to_string()).await
}

/// Errors that can happen when validating authentication
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("KeyStore missing")]
    MissingKeyStore,
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
}

/// Scopes of access
#[derive(Clone, Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub enum Scope {
    System,
    Link,
    Account,
    Network,
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
    pub fn account(&self) -> Uuid {
        self.account.clone()
    }

    pub fn scope(&self) -> &Option<Scope> {
        &self.scope
    }

    pub fn idempotency(&self) -> Option<Uuid> {
        self.idempotency_token.clone()
    }

    pub fn ip(&self) -> IpAddr {
        self.ip_addr
    }

    pub fn allowed(&self, scope: Scope) -> Result<(), AuthError> {
        Ok(())
    }

    pub fn from_jwt(
        key_store: &KeyStore,
        jwt: &str,
        ip_addr: IpAddr,
    ) -> Result<UserContext, AuthError> {
        let jwt = key_store.verify(jwt)?;
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

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserContext {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let ip = match IpAddr::from_request(req).await {
            Outcome::Success(ip) => ip,
            _ => unimplemented!(),
        };

        let store = match req.rocket().state::<KeyStore>() {
            Some(store) => store,
            None => {
                return Outcome::Failure((Status::InternalServerError, AuthError::MissingKeyStore))
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
        let mut auth = match UserContext::from_jwt(store, &token, ip) {
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
