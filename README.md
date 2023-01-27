# Authentication Client Library

This is a library crate that is used to authenticate incoming requests. It
supports different authentication mechanisms, including JWT authentication (by
fetching and parsing a JWKS that contains keys needed to validate the JWT),
authentication via making an API call to a dedicated accounts API or hardcoded
static authentication tokens.

The library distinguishes between user tokens (that represent real user
accounts) and system tokens (that represent internal administrative accounts).
System tokens are usually required for administrative APIs. Accounts are
represented by UUIDs. It has support for Rocket built-in, but can also be used
without it.

You want to use this library if you want an existing, but opinionated
authentication library that is relatively flexible in that it can be setup to
support different authentication mechanisms, which is quite useful for enabling
local development (with authentication turned off or done with static tokens)
but still being able to deploy to production (where JWTs are used, for
instance).

Resources:
- Documentation: [nightly][rustdoc], [latest release][docs]
- Crates.io: [fractal-btrfs-wrappers][cratesio]

## Examples

The client library needs an instance of `AuthConfig` in order to function. This
is where the authentication providers can be set up.

```rust
use fractal_auth_client::{AuthConfig, key_store};
use uuid::Uuid;

// new, empty authentication config
let mut auth_config = AuthConfig::new();

let key_store = fractal_auth_client::key_store(&jwks.to_string()).await?;
auth_config = auth_config.with_keystore(key_store("http://example.com/path/to/jwks").await?);

// add static user
auth_config.add_static_user(&"secure-token", &Uuid::new_v4());
```

In order to use it with Rocket, the `UserContext` and `SystemContext` guards can be added to routes.

```rust
use fractal_auth_client::UserContext;

/// Example route.
#[get("/example")]
async fn link_create(
    user: UserContext,
) -> String {
    format!("Hello {}", user.account())
}
```

## Optional Features

Features that can be enabled:

- `axum` turns on support for Axum.
- `rocket` turns on support for Rocket.
- `static-tokens` turns on support for defining static tokens (enabled by default).
- **Deprecated**: `insecure-stub` enables the insecure-auth option of the `AuthConfig` struct, which bypasses authentication. Use static tokens instead.

## License

[AGPL 3.0](LICENSE.md), commercial licensing available upon request.

[rustdoc]: https://fractalnetworks.gitlab.io/libraries/auth-client/doc/fractal_auth_client
[docs]: https://docs.rs/fractal-auth-client
[cratesio]: https://crates.io/crates/fractal-auth-client
