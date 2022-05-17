use crate::*;
use matches::assert_matches;
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

#[tokio::test]
async fn test_client_context_default() {
    let auth_config = AuthConfig::new();

    let context = UserContext::from_token(&auth_config, "", LOCALHOST).await;
    assert_matches!(context, Err(AuthError::MissingKeyStore));
}

#[tokio::test]
async fn test_client_context_jwt() {
    // FIXME: write
}

#[cfg(feature = "insecure-stub")]
#[tokio::test]
async fn test_client_context_insecure() {
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
