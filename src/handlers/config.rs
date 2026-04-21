use std::collections::HashMap;
use std::path::Path;

#[cfg(any(feature = "sqlite", feature = "redb"))]
#[cfg(feature = "sqlite")]
use crate::commands::DatabaseType;
use crate::commands::WalletOpts;
use crate::config::{WalletConfig, WalletConfigInner};
use crate::error::BDKCliError as Error;
use bdk_wallet::bitcoin::Network;
use serde_json::json;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::commands::ClientType;

/// Handle wallet config subcommand to create or update config.toml
pub fn handle_config_subcommand(
    datadir: &Path,
    network: Network,
    wallet: String,
    wallet_opts: &WalletOpts,
    force: bool,
) -> Result<String, Error> {
    if network == Network::Bitcoin {
        eprintln!(
            "WARNING: You are configuring a wallet for Bitcoin MAINNET.
             This software is experimental and not recommended for use with real funds.
             Consider using a testnet for testing purposes. \n"
        );
    }

    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    if ext_descriptor.contains("xprv") || ext_descriptor.contains("tprv") {
        eprintln!(
            "WARNING: Your external descriptor contains PRIVATE KEYS.
             Private keys will be saved in PLAINTEXT in the config file.
             This is a security risk. Consider using public descriptors instead.\n"
        );
    }

    if let Some(ref internal_desc) = int_descriptor
        && (internal_desc.contains("xprv") || internal_desc.contains("tprv"))
    {
        eprintln!(
            "WARNING: Your internal descriptor contains PRIVATE KEYS.
                 Private keys will be saved in PLAINTEXT in the config file.
                 This is a security risk. Consider using public descriptors instead.\n"
        );
    }

    let mut config = WalletConfig::load(datadir)?.unwrap_or(WalletConfig {
        wallets: HashMap::new(),
    });

    if config.wallets.contains_key(&wallet) && !force {
        return Err(Error::Generic(format!(
            "Wallet '{wallet}' already exists in config.toml. Use --force to overwrite."
        )));
    }

    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    let client_type = wallet_opts.client_type.clone();
    #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
    let url = &wallet_opts.url.clone();
    #[cfg(any(feature = "sqlite", feature = "redb"))]
    let database_type = match wallet_opts.database_type {
        #[cfg(feature = "sqlite")]
        DatabaseType::Sqlite => "sqlite".to_string(),
        #[cfg(feature = "redb")]
        DatabaseType::Redb => "redb".to_string(),
    };

    #[cfg(any(
        feature = "electrum",
        feature = "esplora",
        feature = "rpc",
        feature = "cbf"
    ))]
    let client_type = match client_type {
        #[cfg(feature = "electrum")]
        ClientType::Electrum => "electrum".to_string(),
        #[cfg(feature = "esplora")]
        ClientType::Esplora => "esplora".to_string(),
        #[cfg(feature = "rpc")]
        ClientType::Rpc => "rpc".to_string(),
        #[cfg(feature = "cbf")]
        ClientType::Cbf => "cbf".to_string(),
    };

    let wallet_config = WalletConfigInner {
        wallet: wallet.clone(),
        network: network.to_string(),
        ext_descriptor,
        int_descriptor,
        #[cfg(any(feature = "sqlite", feature = "redb"))]
        database_type,
        #[cfg(any(
            feature = "electrum",
            feature = "esplora",
            feature = "rpc",
            feature = "cbf"
        ))]
        client_type: Some(client_type),
        #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc",))]
        server_url: Some(url.to_string()),
        #[cfg(feature = "rpc")]
        rpc_user: Some(wallet_opts.basic_auth.0.clone()),
        #[cfg(feature = "rpc")]
        rpc_password: Some(wallet_opts.basic_auth.1.clone()),
        #[cfg(feature = "electrum")]
        batch_size: Some(wallet_opts.batch_size),
        #[cfg(feature = "esplora")]
        parallel_requests: Some(wallet_opts.parallel_requests),
        #[cfg(feature = "rpc")]
        cookie: wallet_opts.cookie.clone(),
    };

    config.wallets.insert(wallet.clone(), wallet_config);
    config.save(datadir)?;

    Ok(serde_json::to_string_pretty(&json!({
        "message": format!("Wallet '{wallet}' initialized successfully in {:?}", datadir.join("config.toml"))
    }))?)
}
