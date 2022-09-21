use crate::{AuthConfig, SystemContext, UserContext};
use axum::{
    async_trait,
    extract::{ConnectInfo, Extension, FromRequest, RequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

#[async_trait]
impl<B> FromRequest<B> for UserContext
where
    B: Send,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // extract authentication token
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|err| err.into_response())?;

        // extract authentication config
        let Extension(config): Extension<AuthConfig> = Extension::from_request(req)
            .await
            .map_err(|err| err.into_response())?;

        // get client IP
        let ConnectInfo(addr): ConnectInfo<SocketAddr> = ConnectInfo::from_request(req)
            .await
            .map_err(|err| err.into_response())?;

        let mut context = UserContext::from_token(&config, bearer.token(), addr.ip())
            .await
            .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()).into_response())?;

        if let Some(header) = req.headers().get("Idempotency-Token") {
            if let Ok(header) = header.to_str() {
                context.parse_idempotency_token(header);
            }
        }

        Ok(context)
    }
}

#[async_trait]
impl<B> FromRequest<B> for SystemContext
where
    B: Send,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // extract authentication token
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|err| err.into_response())?;

        // extract authentication config
        let Extension(config): Extension<AuthConfig> = Extension::from_request(req)
            .await
            .map_err(|err| err.into_response())?;

        // get client IP
        let ConnectInfo(addr): ConnectInfo<SocketAddr> = ConnectInfo::from_request(req)
            .await
            .map_err(|err| err.into_response())?;

        let mut context = SystemContext::from_token(&config, bearer.token(), addr.ip())
            .await
            .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()).into_response())?;

        if let Some(header) = req.headers().get("Idempotency-Token") {
            if let Ok(header) = header.to_str() {
                context.parse_idempotency_token(header);
            }
        }

        Ok(context)
    }
}
