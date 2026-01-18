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
#[cfg(any(feature = "sqlite", feature = "redb"))]
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletConfig {
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
        self.wallets
            .get(wallet_name)
            .ok_or_else(|| Error::Generic(format!("Wallet {wallet_name} not found in config")))?
            .try_into()
    }
}

impl TryFrom<&WalletConfigInner> for WalletOpts {
    type Error = Error;

    fn try_from(config: &WalletConfigInner) -> Result<Self, Self::Error> {
        let _network = Network::from_str(&config.network)
            .map_err(|_| Error::Generic("Invalid network".to_string()))?;

        #[cfg(any(feature = "sqlite", feature = "redb"))]
        let database_type = DatabaseType::from_str(&config.database_type, true)
            .map_err(|_| Error::Generic("Invalid database type".to_string()))?;

        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "rpc",
            feature = "cbf"
        ))]
        let client_type = config
            .client_type
            .as_deref()
            .ok_or_else(|| Error::Generic("Client type missing".into()))
            .and_then(|s| {
                ClientType::from_str(s, true)
                    .map_err(|_| Error::Generic("Invalid client type".into()))
            })?;

        Ok(WalletOpts {
            wallet: Some(config.wallet.clone()),
            verbose: false,
            ext_descriptor: config.ext_descriptor.clone(),
            int_descriptor: config.int_descriptor.clone(),

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
            url: config
                .server_url
                .clone()
                .ok_or_else(|| Error::Generic("Server url not found".into()))?,

            #[cfg(feature = "electrum")]
            batch_size: config.batch_size.unwrap_or(10),

            #[cfg(feature = "esplora")]
            parallel_requests: config.parallel_requests.unwrap_or(5),

            #[cfg(feature = "rpc")]
            basic_auth: (
                config.rpc_user.clone().unwrap_or_else(|| "user".into()),
                config
                    .rpc_password
                    .clone()
                    .unwrap_or_else(|| "password".into()),
            ),

            #[cfg(feature = "rpc")]
            cookie: config.cookie.clone(),

            #[cfg(feature = "cbf")]
            compactfilter_opts: crate::commands::CompactFilterOpts { conn_count: 2 },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn test_wallet_config_inner_to_opts_conversion() {
        let wallet_config = WalletConfigInner {
            wallet: "test_wallet".to_string(),
            network: "testnet4".to_string(),
            ext_descriptor: "wpkh([07234a14/84'/1'/0']tpubDCSgT6PaVLQH9h2TAxKryhvkEurUBcYRJc9dhTcMDyahhWiMWfEWvQQX89yaw7w7XU8bcVujoALfxq59VkFATri3Cxm5mkp9kfHfRFDckEh/0/*)#429nsxmg".to_string(),
            int_descriptor: Some("wpkh([07234a14/84'/1'/0']tpubDCSgT6PaVLQH9h2TAxKryhvkEurUBcYRJc9dhTcMDyahhWiMWfEWvQQX89yaw7w7XU8bcVujoALfxq59VkFATri3Cxm5mkp9kfHfRFDckEh/1/*)#y7qjdnts".to_string()),
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            database_type: "sqlite".to_string(),
            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc", feature = "cbf"))]
            client_type: Some("esplora".to_string()),
            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
            server_url: Some(" https://blockstream.info/testnet4/api".to_string()),
            #[cfg(feature = "electrum")]
            batch_size: None,
            #[cfg(feature = "esplora")]
            parallel_requests: None,
            #[cfg(feature = "rpc")]
            rpc_user: None,
            #[cfg(feature = "rpc")]
            rpc_password: None,
            #[cfg(feature = "rpc")]
            cookie: None,
        };

        let opts: WalletOpts = (&wallet_config)
            .try_into()
            .expect("Conversion should succeed");

        assert_eq!(opts.wallet, Some("test_wallet".to_string()));
        assert_eq!(
            opts.ext_descriptor,
            "wpkh([07234a14/84'/1'/0']tpubDCSgT6PaVLQH9h2TAxKryhvkEurUBcYRJc9dhTcMDyahhWiMWfEWvQQX89yaw7w7XU8bcVujoALfxq59VkFATri3Cxm5mkp9kfHfRFDckEh/0/*)#429nsxmg"
        );

        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "rpc",
            feature = "cbf"
        ))]
        assert_eq!(opts.client_type, ClientType::Esplora);

        #[cfg(feature = "sqlite")]
        assert_eq!(opts.database_type, DatabaseType::Sqlite);

        #[cfg(feature = "electrum")]
        assert_eq!(opts.batch_size, 10);

        #[cfg(feature = "esplora")]
        assert_eq!(opts.parallel_requests, 5);
    }

    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    #[test]
    fn test_invalid_client_type_fails() {
        let inner = WalletConfigInner {
            wallet: "test".to_string(),
            network: "regtest".to_string(),
            ext_descriptor: "desc".to_string(),
            int_descriptor: None,
            #[cfg(any(feature = "sqlite", feature = "redb"))]
            database_type: "sqlite".to_string(),
            #[cfg(any(
                feature = "electrum",
                feature = "esplora",
                feature = "rpc",
                feature = "cbf"
            ))]
            client_type: Some("invalid_backend".to_string()),
            #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
            server_url: Some("url".to_string()),
            #[cfg(feature = "electrum")]
            batch_size: None,
            #[cfg(feature = "esplora")]
            parallel_requests: None,
            #[cfg(feature = "rpc")]
            rpc_user: None,
            #[cfg(feature = "rpc")]
            rpc_password: None,
            #[cfg(feature = "rpc")]
            cookie: None,
        };

        let result: Result<WalletOpts, Error> = (&inner).try_into();
        assert!(result.is_err());
    }
}
