#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::commands::ClientType;
use crate::commands::{DatabaseType, WalletOpts};
use crate::error::BDKCliError as Error;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct WalletConfig {
    pub wallets: HashMap<String, WalletConfigInner>,
}

#[derive(Debug, Deserialize)]
pub struct WalletConfigInner {
    pub name: String,
    pub ext_descriptor: String,
    pub int_descriptor: String,
    pub database_type: String,
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    pub client_type: String,
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    pub server_url: String,
    #[cfg(feature = "rpc")]
    pub rpc_user: String,
    #[cfg(feature = "rpc")]
    pub rpc_password: String,
}

impl WalletConfig {
    /// Load configuration from a TOML file in the wallet's data directory
    pub fn load(datadir: &Path) -> Result<Option<WalletConfig>, Error> {
        let config_path = datadir.join("config.toml");
        if !config_path.exists() {
            return Ok(None);
        }
        let config_content = fs::read_to_string(&config_path)
            .map_err(|e| Error::Generic(format!("Failed to read config file: {}", e)))?;
        let config: WalletConfig = toml::from_str(&config_content)
            .map_err(|e| Error::Generic(format!("Failed to parse config file: {}", e)))?;
        Ok(Some(config))
    }

    /// Get config for a wallet
    pub fn get_wallet_opts(&self, wallet_name: &str) -> Result<WalletOpts, Error> {
        let wallet_config = self
            .wallets
            .get(wallet_name)
            .ok_or_else(|| Error::Generic(format!("Wallet {} not found in config", wallet_name)))?;

        #[cfg(feature = "sqlite")]
        let database_type = match wallet_config.database_type.as_str() {
            "sqlite" => DatabaseType::Sqlite,
            _ => {
                return Err(Error::Generic(format!(
                    "Invalid database type: {}",
                    wallet_config.database_type
                )))
            }
        };

        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "rpc",
            feature = "cbf"
        ))]
        let client_type = match wallet_config.client_type.as_str() {
            #[cfg(feature = "electrum")]
            "electrum" => ClientType::Electrum,
            #[cfg(feature = "esplora")]
            "esplora" => ClientType::Esplora,
            #[cfg(feature = "rpc")]
            "rpc" => ClientType::Rpc,
            #[cfg(feature = "cbf")]
            "cbf" => ClientType::Cbf,
            _ => {
                return Err(Error::Generic(format!(
                    "Invalid client type: {}",
                    wallet_config.client_type
                )))
            }
        };

        Ok(WalletOpts {
            wallet: Some(wallet_config.name.clone()),
            verbose: false,
            ext_descriptor: Some(wallet_config.ext_descriptor.clone()),
            int_descriptor: Some(wallet_config.int_descriptor.clone()),
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            client_type: Some(client_type),
            #[cfg(feature = "sqlite")]
            database_type: Some(database_type),
            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
            url: Some(wallet_config.server_url.clone()),
            #[cfg(feature = "electrum")]
            batch_size: 10,
            #[cfg(feature = "esplora")]
            parallel_requests: 5,
            #[cfg(feature = "rpc")]
            basic_auth: Some((
                wallet_config.rpc_user.clone(),
                wallet_config.rpc_password.clone(),
            )),
            #[cfg(feature = "rpc")]
            cookie: None,
            #[cfg(feature = "cbf")]
            compactfilter_opts: crate::commands::CompactFilterOpts {
                conn_count: 2,
                skip_blocks: None,
            },
        })
    }
}
