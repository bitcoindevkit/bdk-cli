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
    pub wallet: String,
    pub network: String,
    pub ext_descriptor: String,
    pub int_descriptor: Option<String>,
    #[cfg(any(feature = "sqlite", feature = "redb"))]
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
    pub rpc_user: Option<String>,
    #[cfg(feature = "rpc")]
    pub rpc_password: Option<String>,
    #[cfg(feature = "electrum")]
    pub batch_size: Option<usize>,
    #[cfg(feature = "esplora")]
    pub parallel_requests: Option<usize>,
    #[cfg(feature = "rpc")]
    pub cookie: Option<String>,
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
                return Err(Error::Generic("Invalid network".to_string()));
            }
        };

        #[cfg(any(feature = "sqlite", feature = "redb"))]
        let database_type = match wallet_config.database_type.as_str() {
            #[cfg(feature = "sqlite")]
            "sqlite" => DatabaseType::Sqlite,
            #[cfg(feature = "redb")]
            "redb" => DatabaseType::Redb,
            _ => {
                return Err(Error::Generic("Invalid database type".to_string()));
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
            Some("electrum") => ClientType::Electrum,
            #[cfg(feature = "esplora")]
            Some("esplora") => ClientType::Esplora,
            #[cfg(feature = "rpc")]
            Some("rpc") => ClientType::Rpc,
            #[cfg(feature = "cbf")]
            Some("cbf") => ClientType::Cbf,
            _ => return Err(Error::Generic(format!("Invalid client type"))),
        };

        Ok(WalletOpts {
            wallet: Some(wallet_config.wallet.clone()),
            verbose: false,
            ext_descriptor: Some(wallet_config.ext_descriptor.clone()),
            int_descriptor: wallet_config.int_descriptor.clone(),
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            client_type,
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            database_type,
            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
            url: wallet_config
                .server_url
                .clone()
                .ok_or_else(|| Error::Generic(format!("Server url not found")))?,
            #[cfg(feature = "electrum")]
            batch_size: 10,
            #[cfg(feature = "esplora")]
            parallel_requests: 5,
            #[cfg(feature = "rpc")]
            basic_auth: (
                wallet_config
                    .rpc_user
                    .clone()
                    .unwrap_or_else(|| "user".into()),
                wallet_config
                    .rpc_password
                    .clone()
                    .unwrap_or_else(|| "password".into()),
            ),
            #[cfg(feature = "rpc")]
            cookie: wallet_config.cookie.clone(),
            #[cfg(feature = "cbf")]
            compactfilter_opts: crate::commands::CompactFilterOpts {
                conn_count: 2,
                skip_blocks: None,
            },
        })
    }
}
