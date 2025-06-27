#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::commands::ClientType;
#[cfg(feature = "sqlite")]
use crate::commands::DatabaseType;
use crate::commands::WalletOpts;
use crate::error::BDKCliError as Error;
use bdk_wallet::bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub wallets: HashMap<String, WalletConfigInner>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletConfigInner {
    pub name: String,
    pub network: String,
    pub ext_descriptor: String,
    pub int_descriptor: String,
    #[cfg(feature = "sqlite")]
    pub database_type: String,
    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    pub client_type: Option<String>,
    #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
    pub server_url: Option<String>,
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
            .map_err(|e| Error::Generic(format!("Failed to read config file: {e}")))?;
        let config: WalletConfig = toml::from_str(&config_content)
            .map_err(|e| Error::Generic(format!("Failed to parse config file: {e}")))?;
        Ok(Some(config))
    }

    /// Save configuration to a TOML file
    pub fn save(&self, datadir: &Path) -> Result<(), Error> {
        let config_path = datadir.join("config.toml");
        let config_content = toml::to_string_pretty(self)
            .map_err(|e| Error::Generic(format!("Failed to serialize config: {e}")))?;
        fs::create_dir_all(datadir)
            .map_err(|e| Error::Generic(format!("Failed to create directory {datadir:?}: {e}")))?;
        fs::write(&config_path, config_content).map_err(|e| {
            Error::Generic(format!("Failed to write config file {config_path:?}: {e}"))
        })?;
        log::debug!("Saved config to {config_path:?}");
        Ok(())
    }

    /// Get config for a wallet
    pub fn get_wallet_opts(&self, wallet_name: &str) -> Result<WalletOpts, Error> {
        let wallet_config = self
            .wallets
            .get(wallet_name)
            .ok_or_else(|| Error::Generic(format!("Wallet {wallet_name} not found in config")))?;

        let _network = match wallet_config.network.as_str() {
            "bitcoin" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            _ => {
                return Err(Error::Generic(format!(
                    "Invalid network: {network}",
                    network = wallet_config.network
                )))
            }
        };

        #[cfg(feature = "sqlite")]
        let database_type = match wallet_config.database_type.as_str() {
            "sqlite" => DatabaseType::Sqlite,
            _ => {
                return Err(Error::Generic(format!(
                    "Invalid database type: {database_type}",
                    database_type = wallet_config.database_type
                )))
            }
        };

        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "rpc",
            feature = "cbf"
        ))]
        let client_type = match wallet_config.client_type.as_deref() {
            #[cfg(feature = "electrum")]
            Some("electrum") => Some(ClientType::Electrum),
            #[cfg(feature = "esplora")]
            Some("esplora") => Some(ClientType::Esplora),
            #[cfg(feature = "rpc")]
            Some("rpc") => Some(ClientType::Rpc),
            #[cfg(feature = "cbf")]
            Some("cbf") => Some(ClientType::Cbf),
            Some(other) => return Err(Error::Generic(format!("Invalid client type: {other}"))),
            None => None,
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
            client_type,
            #[cfg(feature = "sqlite")]
            database_type: Some(database_type),
            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
            url: wallet_config.server_url.clone(),
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
