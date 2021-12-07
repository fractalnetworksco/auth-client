use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::uuid::Uuid;
use thiserror::Error;
use std::collections::HashSet;

/// Scopes of access
#[derive(Clone, Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub enum Scope {
    Link,
    LinkRead,
    Account,
    AccountRead,
    Network,
    NetworkRead,
}

/// Generic request context. May contain idempotency token, request ID, a JWT
/// pulled from the cookies, or a token pulled from the header.
pub struct Auth {
    uuid: Uuid,
    scopes: HashSet<Scope>,
}

impl Auth {
    pub fn user(&self) -> Uuid {
        self.uuid.clone()
    }

    pub fn scopes(&self) -> &HashSet<Scope> {
        &self.scopes
    }

    pub fn allowed(&self, scope: Scope) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Errors that can happen when validating authentication
#[derive(Error, Clone, Debug)]
pub enum AuthError {
    #[error("JWT is wrong")]
    TokenInvalid,
    #[error("JWT is missing")]
    TokenMissing,
    #[error("JWT is expired")]
    TokenExpired,
    #[error("JWT missing scope")]
    Unauthorized,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Auth {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = match req.headers().get_one("Authorization").map(|h| h.to_string()) {
            Some(s) => s,
            None => return Outcome::Failure((Status::Unauthorized, AuthError::TokenMissing)),
        };
        let uuid: Uuid = match token.parse() {
            Ok(uuid) => uuid,
            Err(_) => return Outcome::Failure((Status::Unauthorized, AuthError::TokenInvalid)),
        };
        Outcome::Success(Auth {
            uuid,
            scopes: HashSet::from([Scope::Link]),
        })
    }
}


