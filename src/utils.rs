// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utility Tools
//!
//! This module includes all the utility tools used by the App.

use std::path::PathBuf;
use std::str::FromStr;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use crate::backend::Backend;
use crate::commands::WalletOpts;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{Address, Network, OutPoint, Script};
#[cfg(feature = "compact_filters")]
use bdk::blockchain::compact_filters::{BitcoinPeerConfig, CompactFiltersBlockchainConfig};
#[cfg(feature = "esplora")]
use bdk::blockchain::esplora::EsploraBlockchainConfig;
#[cfg(feature = "rpc")]
use bdk::blockchain::rpc::{Auth, RpcConfig};
#[cfg(feature = "electrum")]
use bdk::blockchain::ElectrumBlockchainConfig;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk::blockchain::{AnyBlockchain, AnyBlockchainConfig, ConfigurableBlockchain};
#[cfg(feature = "key-value-db")]
use bdk::database::any::SledDbConfiguration;
#[cfg(feature = "sqlite-db")]
use bdk::database::any::SqliteDbConfiguration;
use bdk::database::{AnyDatabase, AnyDatabaseConfig, BatchDatabase, ConfigurableDatabase};
use bdk::wallet::wallet_name_from_descriptor;
use bdk::{Error, Wallet};

/// Create a randomized wallet name from the descriptor checksum.
/// If wallet options already includes a name, use that instead.
pub(crate) fn maybe_descriptor_wallet_name(
    wallet_opts: WalletOpts,
    network: Network,
) -> Result<WalletOpts, Error> {
    if wallet_opts.wallet.is_some() {
        return Ok(wallet_opts);
    }
    // Use deterministic wallet name derived from descriptor
    let wallet_name = wallet_name_from_descriptor(
        &wallet_opts.descriptor[..],
        wallet_opts.change_descriptor.as_deref(),
        network,
        &Secp256k1::new(),
    )?;
    let mut wallet_opts = wallet_opts;
    wallet_opts.wallet = Some(wallet_name);

    Ok(wallet_opts)
}

/// Parse the recipient (Address,Amount) argument from cli input
pub(crate) fn parse_recipient(s: &str) -> Result<(Script, u64), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }
    let addr = Address::from_str(parts[0]).map_err(|e| e.to_string())?;
    let val = u64::from_str(parts[1]).map_err(|e| e.to_string())?;

    Ok((addr.script_pubkey(), val))
}
#[cfg(any(
    feature = "electrum",
    feature = "compact_filters",
    feature = "esplora",
    feature = "rpc"
))]
/// Parse the proxy (Socket:Port) argument from the cli input
pub(crate) fn parse_proxy_auth(s: &str) -> Result<(String, String), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }

    let user = parts[0].to_string();
    let passwd = parts[1].to_string();

    Ok((user, passwd))
}

/// Parse a outpoint (Txid:Vout) argument from cli input
pub(crate) fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
    OutPoint::from_str(s).map_err(|e| e.to_string())
}

/// prepare bdk_cli home and wallet directory
pub(crate) fn prepare_home_wallet_dir(wallet_name: &str) -> Result<PathBuf, Error> {
    let mut dir = PathBuf::new();
    dir.push(
        &dirs_next::home_dir().ok_or_else(|| Error::Generic("home dir not found".to_string()))?,
    );
    dir.push(".bdk-bitcoin");

    if !dir.exists() {
        log::info!("Creating home directory {}", dir.as_path().display());
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    dir.push(wallet_name);

    if !dir.exists() {
        log::info!("Creating wallet directory {}", dir.as_path().display());
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

/// Prepare wallet database directory
pub(crate) fn prepare_wallet_db_dir(wallet_name: &str) -> Result<PathBuf, Error> {
    let mut db_dir = prepare_home_wallet_dir(wallet_name)?;

    #[cfg(feature = "key-value-db")]
    db_dir.push("wallet.sled");

    #[cfg(feature = "sqlite-db")]
    db_dir.push("wallet.sqlite");

    #[cfg(not(feature = "sqlite-db"))]
    if !db_dir.exists() {
        log::info!("Creating database directory {}", db_dir.as_path().display());
        std::fs::create_dir(&db_dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(db_dir)
}

/// Prepare blockchain data directory (for compact filters)
#[cfg(feature = "compact_filters")]
pub(crate) fn prepare_bc_dir(wallet_name: &str) -> Result<PathBuf, Error> {
    let mut bc_dir = prepare_home_wallet_dir(wallet_name)?;

    bc_dir.push("compact_filters");

    if !bc_dir.exists() {
        log::info!(
            "Creating blockchain directory {}",
            bc_dir.as_path().display()
        );
        std::fs::create_dir(&bc_dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(bc_dir)
}

/// Open the wallet database
pub(crate) fn open_database(wallet_opts: &WalletOpts) -> Result<AnyDatabase, Error> {
    let wallet_name = wallet_opts.wallet.as_ref().expect("wallet name");
    let database_path = prepare_wallet_db_dir(wallet_name)?;

    #[cfg(feature = "key-value-db")]
    let config = AnyDatabaseConfig::Sled(SledDbConfiguration {
        path: database_path
            .into_os_string()
            .into_string()
            .expect("path string"),
        tree_name: wallet_name.to_string(),
    });
    #[cfg(feature = "sqlite-db")]
    let config = AnyDatabaseConfig::Sqlite(SqliteDbConfiguration {
        path: database_path
            .into_os_string()
            .into_string()
            .expect("path string"),
    });
    let database = AnyDatabase::from_config(&config)?;
    log::debug!("database opened successfully");
    Ok(database)
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
/// Create a new blockchain for a given [Backend] if available
/// Or else create one from the wallet configuration options
pub(crate) fn new_blockchain(
    _network: Network,
    wallet_opts: &WalletOpts,
    _backend: &Backend,
) -> Result<AnyBlockchain, Error> {
    #[cfg(feature = "electrum")]
    let config = {
        let url = match _backend {
            Backend::Electrum { electrum_url } => electrum_url.to_owned(),
            _ => wallet_opts.electrum_opts.server.clone(),
        };

        AnyBlockchainConfig::Electrum(ElectrumBlockchainConfig {
            url,
            socks5: wallet_opts.proxy_opts.proxy.clone(),
            retry: wallet_opts.proxy_opts.retries,
            timeout: wallet_opts.electrum_opts.timeout,
            stop_gap: wallet_opts.electrum_opts.stop_gap,
        })
    };

    #[cfg(feature = "esplora")]
    let config = AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
        base_url: wallet_opts.esplora_opts.server.clone(),
        timeout: Some(wallet_opts.esplora_opts.timeout),
        concurrency: Some(wallet_opts.esplora_opts.conc),
        stop_gap: wallet_opts.esplora_opts.stop_gap,
        proxy: wallet_opts.proxy_opts.proxy.clone(),
    });

    #[cfg(feature = "compact_filters")]
    let config = {
        let mut peers = vec![];
        for addrs in wallet_opts.compactfilter_opts.address.clone() {
            for _ in 0..wallet_opts.compactfilter_opts.conn_count {
                peers.push(BitcoinPeerConfig {
                    address: addrs.clone(),
                    socks5: wallet_opts.proxy_opts.proxy.clone(),
                    socks5_credentials: wallet_opts.proxy_opts.proxy_auth.clone(),
                })
            }
        }

        let wallet_name = wallet_opts.wallet.as_ref().expect("wallet name");
        AnyBlockchainConfig::CompactFilters(CompactFiltersBlockchainConfig {
            peers,
            network: _network,
            storage_dir: prepare_bc_dir(wallet_name)?
                .into_os_string()
                .into_string()
                .map_err(|_| Error::Generic("Internal OS_String conversion error".to_string()))?,
            skip_blocks: Some(wallet_opts.compactfilter_opts.skip_blocks),
        })
    };

    #[cfg(feature = "rpc")]
    let config: AnyBlockchainConfig = {
        let (url, auth) = match _backend {
            Backend::Bitcoin { rpc_url, rpc_auth } => (
                rpc_url,
                Auth::Cookie {
                    file: rpc_auth.into(),
                },
            ),
            _ => {
                let auth = if let Some(cookie) = &wallet_opts.rpc_opts.cookie {
                    Auth::Cookie {
                        file: cookie.into(),
                    }
                } else {
                    Auth::UserPass {
                        username: wallet_opts.rpc_opts.basic_auth.0.clone(),
                        password: wallet_opts.rpc_opts.basic_auth.1.clone(),
                    }
                };
                (&wallet_opts.rpc_opts.address, auth)
            }
        };
        // Use deterministic wallet name derived from descriptor
        let wallet_name = wallet_name_from_descriptor(
            &wallet_opts.descriptor[..],
            wallet_opts.change_descriptor.as_deref(),
            _network,
            &Secp256k1::new(),
        )?;

        let rpc_url = "http://".to_string() + url;

        let rpc_config = RpcConfig {
            url: rpc_url,
            auth,
            network: _network,
            wallet_name,
            skip_blocks: wallet_opts.rpc_opts.skip_blocks,
        };

        AnyBlockchainConfig::Rpc(rpc_config)
    };

    AnyBlockchain::from_config(&config)
}

/// Create a new wallet from given wallet configuration options
pub(crate) fn new_wallet<D>(
    network: Network,
    wallet_opts: &WalletOpts,
    database: D,
) -> Result<Wallet<D>, Error>
where
    D: BatchDatabase,
{
    let descriptor = wallet_opts.descriptor.as_str();
    let change_descriptor = wallet_opts.change_descriptor.as_deref();
    let wallet = Wallet::new(descriptor, change_descriptor, network, database)?;
    Ok(wallet)
}
