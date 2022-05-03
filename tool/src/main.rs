use anyhow::Result;
use fractal_auth_client::{key_store, AuthConfig, SystemContext, UserContext};
use log::*;
use reqwest::Client;
use std::net::IpAddr;
use structopt::StructOpt;
use url::Url;

#[derive(StructOpt, Debug, Clone)]
pub struct Options {
    #[structopt(short = "k", long, global = true)]
    jwks: Option<Url>,
    #[structopt(short, long, global = true)]
    jwt: Option<String>,
    #[structopt(short, long, global = true)]
    auth: Option<Url>,
    #[structopt(short, long, global = true)]
    insecure: bool,
    #[structopt(long, global = true, default_value = "127.0.0.1")]
    ip: IpAddr,
    #[structopt(subcommand)]
    command: Command,
}

impl Options {
    pub async fn auth_config(&self) -> Result<AuthConfig> {
        let mut auth_config = AuthConfig::new();
        if let Some(jwks) = &self.jwks {
            info!("Fetching JWKS");
            let key_store = key_store(&jwks.to_string()).await?;
            auth_config = auth_config.with_keystore(key_store);
        }
        if let Some(auth) = &self.auth {
            info!("Enabling API token validation");
            let jwt = self.jwt.clone().unwrap_or_else(|| {
                warn!("No JWT passed for API token validation");
                String::default()
            });
            auth_config = auth_config.with_apikey_config(Client::new(), auth.clone(), jwt);
        }
        if self.insecure {
            warn!("Enabling insecure (stub) mode");
            auth_config = auth_config.with_insecure_stub(true);
        }
        Ok(auth_config)
    }

    pub async fn run(&self) -> Result<()> {
        let auth_config = self.auth_config().await?;
        use Command::*;
        match &self.command {
            VerifyUserContext { token } => {
                let context = UserContext::from_token(&auth_config, &token, self.ip).await?;
                println!("{context:#?}");
            }
            VerifySystemContext { token } => {
                let context = SystemContext::from_token(&auth_config, &token, self.ip).await?;
                println!("{context:#?}");
            }
        }
        Ok(())
    }
}

#[derive(StructOpt, Debug, Clone)]
pub enum Command {
    VerifyUserContext { token: String },
    VerifySystemContext { token: String },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let options = Options::from_args();
    match options.run().await {
        Ok(()) => {}
        Err(error) => eprintln!("Error: {error:?}"),
    }
}
