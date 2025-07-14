// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utility Tools
//!
//! This module includes all the utility tools used by the App.
use crate::error::BDKCliError as Error;
use std::str::FromStr;

use std::path::{Path, PathBuf};

use crate::commands::WalletOpts;
#[cfg(feature = "cbf")]
use bdk_kyoto::{
    Info, LightClient, NodeBuilderExt, Receiver,
    ScanType::{Recovery, Sync},
    UnboundedReceiver, Warning,
    builder::NodeBuilder,
};
use bdk_wallet::bitcoin::{Address, Network, OutPoint, ScriptBuf};

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf"
))]
use crate::commands::ClientType;

use bdk_wallet::Wallet;
#[cfg(any(feature = "sqlite", feature = "redb"))]
use bdk_wallet::{KeychainKind, PersistedWallet, WalletPersister};

/// Parse the recipient (Address,Amount) argument from cli input.
pub(crate) fn parse_recipient(s: &str) -> Result<(ScriptBuf, u64), String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid format".to_string());
    }
    let addr = Address::from_str(parts[0])
        .map_err(|e| e.to_string())?
        .assume_checked();
    let val = u64::from_str(parts[1]).map_err(|e| e.to_string())?;

    Ok((addr.script_pubkey(), val))
}

#[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
/// Parse the proxy (Socket:Port) argument from the cli input.
pub(crate) fn parse_proxy_auth(s: &str) -> Result<(String, String), Error> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(Error::Generic("Invalid format".to_string()));
    }

    let user = parts[0].to_string();
    let passwd = parts[1].to_string();

    Ok((user, passwd))
}

/// Parse a outpoint (Txid:Vout) argument from cli input.
pub(crate) fn parse_outpoint(s: &str) -> Result<OutPoint, Error> {
    Ok(OutPoint::from_str(s)?)
}

/// Parse an address string into `Address<NetworkChecked>`.
pub(crate) fn parse_address(address_str: &str) -> Result<Address, Error> {
    let unchecked_address = Address::from_str(address_str)?;
    Ok(unchecked_address.assume_checked())
}

/// Prepare bdk-cli home directory
///
/// This function is called to check if [`crate::CliOpts`] datadir is set.
/// If not the default home directory is created at `~/.bdk-bitcoin`.
#[allow(dead_code)]
pub(crate) fn prepare_home_dir(home_path: Option<PathBuf>) -> Result<PathBuf, Error> {
    let dir = home_path.unwrap_or_else(|| {
        let mut dir = PathBuf::new();
        dir.push(
            dirs::home_dir()
                .ok_or_else(|| Error::Generic("home dir not found".to_string()))
                .unwrap(),
        );
        dir.push(".bdk-bitcoin");
        dir
    });

    if !dir.exists() {
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

/// Prepare wallet database directory.
#[allow(dead_code)]
pub(crate) fn prepare_wallet_db_dir(
    wallet_name: &Option<String>,
    home_path: &Path,
) -> Result<std::path::PathBuf, Error> {
    let mut dir = home_path.to_owned();
    if let Some(wallet_name) = wallet_name {
        dir.push(wallet_name);
    }

    if !dir.exists() {
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf",
))]
pub(crate) enum BlockchainClient {
    #[cfg(feature = "electrum")]
    Electrum {
        client: Box<bdk_electrum::BdkElectrumClient<bdk_electrum::electrum_client::Client>>,
        batch_size: usize,
    },
    #[cfg(feature = "esplora")]
    Esplora {
        client: Box<bdk_esplora::esplora_client::AsyncClient>,
        parallel_requests: usize,
    },
    #[cfg(feature = "rpc")]
    RpcClient {
        client: Box<bdk_bitcoind_rpc::bitcoincore_rpc::Client>,
    },

    #[cfg(feature = "cbf")]
    KyotoClient { client: Box<LightClient> },
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "rpc",
    feature = "cbf",
))]
/// Create a new blockchain from the wallet configuration options.
pub(crate) fn new_blockchain_client(
    wallet_opts: &WalletOpts,
    _wallet: &Wallet,
    _datadir: PathBuf,
) -> Result<BlockchainClient, Error> {
    #[cfg(any(feature = "electrum", feature = "esplora", feature = "rpc"))]
    let url = wallet_opts.url.as_str();
    let client = match wallet_opts.client_type {
        #[cfg(feature = "electrum")]
        ClientType::Electrum => {
            let client = bdk_electrum::electrum_client::Client::new(url)
                .map(bdk_electrum::BdkElectrumClient::new)?;
            BlockchainClient::Electrum {
                client: Box::new(client),
                batch_size: wallet_opts.batch_size,
            }
        }
        #[cfg(feature = "esplora")]
        ClientType::Esplora => {
            let client = bdk_esplora::esplora_client::Builder::new(url).build_async()?;
            BlockchainClient::Esplora {
                client: Box::new(client),
                parallel_requests: wallet_opts.parallel_requests,
            }
        }

        #[cfg(feature = "rpc")]
        ClientType::Rpc => {
            let auth = match &wallet_opts.cookie {
                Some(cookie) => bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(cookie.into()),
                None => bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass(
                    wallet_opts.basic_auth.0.clone(),
                    wallet_opts.basic_auth.1.clone(),
                ),
            };
            let client = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(url, auth)
                .map_err(|e| Error::Generic(e.to_string()))?;
            BlockchainClient::RpcClient {
                client: Box::new(client),
            }
        }

        #[cfg(feature = "cbf")]
        ClientType::Cbf => {
            let scan_type = match wallet_opts.compactfilter_opts.skip_blocks {
                Some(from_height) => Recovery { from_height },
                None => Sync,
            };

            let builder = NodeBuilder::new(_wallet.network());

            let client = builder
                .required_peers(wallet_opts.compactfilter_opts.conn_count)
                .data_dir(&_datadir)
                .build_with_wallet(_wallet, scan_type)?;

            BlockchainClient::KyotoClient {
                client: Box::new(client),
            }
        }
    };
    Ok(client)
}

#[cfg(any(feature = "sqlite", feature = "redb"))]
/// Create a new persisted wallet from given wallet configuration options.
pub(crate) fn new_persisted_wallet<P: WalletPersister>(
    network: Network,
    persister: &mut P,
    wallet_opts: &WalletOpts,
) -> Result<PersistedWallet<P>, Error>
where
    P::Error: std::fmt::Display,
{
    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    let mut wallet_load_params = Wallet::load();
    if ext_descriptor.is_some() {
        wallet_load_params =
            wallet_load_params.descriptor(KeychainKind::External, ext_descriptor.clone());
    }
    if int_descriptor.is_some() {
        wallet_load_params =
            wallet_load_params.descriptor(KeychainKind::Internal, int_descriptor.clone());
    }
    if ext_descriptor.is_some() || int_descriptor.is_some() {
        wallet_load_params = wallet_load_params.extract_keys();
    }

    let wallet_opt = wallet_load_params
        .check_network(network)
        .load_wallet(persister)
        .map_err(|e| Error::Generic(e.to_string()))?;

    let wallet = match wallet_opt {
        Some(wallet) => wallet,
        None => match (ext_descriptor, int_descriptor) {
            (Some(ext_descriptor), Some(int_descriptor)) => {
                let wallet = Wallet::create(ext_descriptor, int_descriptor)
                    .network(network)
                    .create_wallet(persister)
                    .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(wallet)
            }
            (Some(ext_descriptor), None) => {
                let wallet = Wallet::create_single(ext_descriptor)
                    .network(network)
                    .create_wallet(persister)
                    .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(wallet)
            }
            _ => Err(Error::Generic(
                "An external descriptor is required.".to_string(),
            )),
        }?,
    };

    Ok(wallet)
}

#[cfg(not(any(feature = "sqlite", feature = "redb")))]
/// Create a new non-persisted wallet from given wallet configuration options.
pub(crate) fn new_wallet(network: Network, wallet_opts: &WalletOpts) -> Result<Wallet, Error> {
    let ext_descriptor = wallet_opts.ext_descriptor.clone();
    let int_descriptor = wallet_opts.int_descriptor.clone();

    match (ext_descriptor, int_descriptor) {
        (Some(ext_descriptor), Some(int_descriptor)) => {
            let wallet = Wallet::create(ext_descriptor, int_descriptor)
                .network(network)
                .create_wallet_no_persist()?;
            Ok(wallet)
        }
        (Some(ext_descriptor), None) => {
            let wallet = Wallet::create_single(ext_descriptor)
                .network(network)
                .create_wallet_no_persist()?;
            Ok(wallet)
        }
        _ => Err(Error::Generic(
            "An external descriptor is required.".to_string(),
        )),
    }
}

#[cfg(feature = "cbf")]
pub async fn trace_logger(
    mut log_subscriber: Receiver<String>,
    mut info_subcriber: Receiver<Info>,
    mut warning_subscriber: UnboundedReceiver<Warning>,
) {
    loop {
        tokio::select! {
            log = log_subscriber.recv() => {
                if let Some(log) = log {
                    tracing::info!("{log}")
                }
            }
            info = info_subcriber.recv() => {
                if let Some(info) = info {
                    tracing::info!("{info}")
                }
            }
            warn = warning_subscriber.recv() => {
                if let Some(warn) = warn {
                    tracing::warn!("{warn}")
                }
            }
        }
    }
}

// Handle Kyoto Client sync
#[cfg(feature = "cbf")]
pub async fn sync_kyoto_client(wallet: &mut Wallet, client: Box<LightClient>) -> Result<(), Error> {
    let LightClient {
        requester,
        log_subscriber,
        info_subscriber,
        warning_subscriber,
        mut update_subscriber,
        node,
    } = *client;

    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| Error::Generic(format!("SetGlobalDefault error: {}", e)))?;

    tokio::task::spawn(async move { node.run().await });
    tokio::task::spawn(async move {
        trace_logger(log_subscriber, info_subscriber, warning_subscriber).await
    });

    if !requester.is_running() {
        tracing::error!("Kyoto node is not running");
        return Err(Error::Generic("Kyoto node failed to start".to_string()));
    }
    tracing::info!("Kyoto node is running");

    let update = update_subscriber.update().await?;
    tracing::info!("Received update: applying to wallet");
    wallet
        .apply_update(update)
        .map_err(|e| Error::Generic(format!("Failed to apply update: {}", e)))?;

    tracing::info!(
        "Chain tip: {}, Transactions: {}, Balance: {}",
        wallet.local_chain().tip().height(),
        wallet.transactions().count(),
        wallet.balance().total().to_sat()
    );

    tracing::info!(
        "Sync completed: tx_count={}, balance={}",
        wallet.transactions().count(),
        wallet.balance().total().to_sat()
    );

    Ok(())
}
