use crate::*;
use anyhow::Result;
use matches::assert_matches;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use warp::http::StatusCode;
use warp::Filter;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

#[tokio::test]
async fn test_user_context_default() {
    let auth_config = AuthConfig::new();

    let context = UserContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
}

#[ignore]
#[tokio::test]
async fn test_user_context_jwt() {
    // FIXME: implement test case checking JWT.
    assert!(false);
}

/// Starts a fake account API, used for testing.
///
/// When a request to the returned URL is made, and the token matches the expected
/// token, a successful response is returned with the given account UUID.
async fn account_api(expected: String, account: Uuid) -> Result<Url> {
    let checker = warp::post()
        .and(warp::path("check"))
        .and(warp::body::content_length_limit(16 * 1024))
        .and(warp::body::json())
        .then(move |token: CheckTokenRequest| {
            let expected = Arc::new(expected.clone());
            async move {
                let expected = expected.clone();
                if &token.token == expected.as_ref() {
                    Box::new(warp::reply::json(&CheckTokenResponse {
                        uuid: account.clone(),
                    }))
                } else {
                    Box::new(StatusCode::BAD_REQUEST) as Box<dyn warp::Reply>
                }
            }
        });

    let (socket, future) = warp::serve(checker).bind_ephemeral(([127, 0, 0, 1], 0));
    tokio::spawn(future);
    Ok(Url::parse(&format!("http://{}/check", socket))?)
}

/// Generate new API key
fn apikey_new(c: char) -> String {
    (0..AUTH_TOKEN_LENGTH).map(|_| c).collect::<String>()
}

#[tokio::test]
async fn test_user_context_apikey() {
    let apikey = apikey_new('a');
    let account = Uuid::new_v4();
    let account_api = account_api(apikey.clone(), account.clone()).await.unwrap();
    let auth_config =
        AuthConfig::new().with_apikey_config(Client::new(), account_api, String::new());

    let context = UserContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = UserContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = UserContext::from_token(&auth_config, &apikey_new('b'), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::InvalidAuthToken));
    let context = UserContext::from_token(&auth_config, &apikey, LOCALHOST).await;
    assert_matches!(context, Ok(_));
    let context = context.unwrap();
    assert_eq!(context.account(), account);
    assert_eq!(context.ip(), LOCALHOST);
}

#[tokio::test]
async fn test_system_context_apikey() {
    // system contexts currently do not accept api tokens. this is for security.
    let apikey = apikey_new('a');
    let account = Uuid::new_v4();
    let account_api = account_api(apikey.clone(), account.clone()).await.unwrap();
    let auth_config =
        AuthConfig::new().with_apikey_config(Client::new(), account_api, String::new());

    let context = SystemContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = SystemContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = SystemContext::from_token(&auth_config, &apikey, LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = SystemContext::from_token(&auth_config, &apikey_new('b'), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
}

#[cfg(feature = "insecure-stub")]
#[tokio::test]
async fn test_user_context_insecure() {
    // generate account uuid
    let account = Uuid::new_v4();

    // insecure stub does nothing if not enabled
    let auth_config = AuthConfig::new();
    let context = UserContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = UserContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));

    // insecure stub does nothing if disabled
    let auth_config = AuthConfig::new().with_insecure_stub(false);
    let context = UserContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = UserContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));

    // insecure stub allows uuid if enabled
    let auth_config = AuthConfig::new().with_insecure_stub(true);
    let context = UserContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = UserContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Ok(_));
    let context = context.unwrap();
    assert_eq!(context.account(), account);
    assert_eq!(context.ip(), LOCALHOST);
}

#[cfg(feature = "insecure-stub")]
#[tokio::test]
async fn test_system_context_insecure() {
    // generate account uuid
    let account = Uuid::new_v4();

    // insecure stub does nothing if not enabled
    let auth_config = AuthConfig::new();
    let context = SystemContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = SystemContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));

    // insecure stub does nothing if disabled
    let auth_config = AuthConfig::new().with_insecure_stub(false);
    let context = SystemContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = SystemContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));

    // insecure stub allows uuid if enabled
    let auth_config = AuthConfig::new().with_insecure_stub(true);
    let context = SystemContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
    let context = SystemContext::from_token(&auth_config, &account.to_string(), LOCALHOST).await;
    assert_matches!(context, Ok(_));
    let context = context.unwrap();
    assert_eq!(context.account(), account);
    assert_eq!(context.ip(), LOCALHOST);
}
