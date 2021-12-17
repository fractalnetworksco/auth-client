use jwks_client::error::Error as JwksError;
use jwks_client::keyset::KeyStore;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::uuid::Uuid;
use std::collections::HashSet;
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
pub struct Auth {
    account: Uuid,
    scope: Option<Scope>,
}

impl Auth {
    pub fn account(&self) -> Uuid {
        self.account.clone()
    }

    pub fn scope(&self) -> &Option<Scope> {
        &self.scope
    }

    pub fn allowed(&self, scope: Scope) -> Result<(), AuthError> {
        Ok(())
    }

    pub fn from_jwt(key_store: &KeyStore, jwt: &str) -> Result<Auth, AuthError> {
        let jwt = key_store.decode(jwt)?;
        let account = jwt.payload().sub().ok_or(AuthError::PayloadError)?;
        let account = Uuid::parse_str(account).map_err(|_| AuthError::PayloadError)?;

        Ok(Auth {
            account,
            scope: None,
        })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Auth {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
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
        let auth = match Auth::from_jwt(store, &token) {
            Ok(auth) => auth,
            Err(e) => return Outcome::Failure((Status::Unauthorized, e)),
        };
        Outcome::Success(auth)
    }
}
