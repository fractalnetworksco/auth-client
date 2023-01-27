use crate::*;
use ::rocket::{
    async_trait,
    http::Status,
    request::{FromRequest, Outcome, Request},
};

#[async_trait]
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
                auth.account = match header.parse() {
                    Ok(value) => value,
                    Err(error) => {
                        return Outcome::Failure((
                            Status::Unauthorized,
                            AuthError::InvalidOverrideAccountUUID,
                        ));
                    }
                };
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

#[async_trait]
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
            auth.account = match header.parse() {
                Ok(value) => value,
                Err(error) => {
                    return Outcome::Failure((
                        Status::Unauthorized,
                        AuthError::InvalidOverrideAccountUUID,
                    ));
                }
            };
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
