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

use crate::commands::WalletOpts;
use crate::error::BDKCliError as Error;
use crate::nodes::Nodes;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Network, OutPoint, ScriptBuf};
use bdk_wallet::{wallet_name_from_descriptor, PersistedWallet, Wallet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(feature = "hardware-signer")]
use {
    bdk_wallet::{
        signer::{SignerError, SignerOrdering},
        KeychainKind,
    },
    hwi::{interface::HWIClient, signer::HWISigner, types::HWIChain},
    std::sync::Arc,
};

#[cfg(all(feature = "reserves", feature = "electrum"))]
use {
    bdk_electrum::electrum_client::{Client, ElectrumApi},
    bdk_wallet::bitcoin::TxOut,
    electrsd::corepc_client::client_sync::v17::blockchain,
};

#[cfg(feature = "esplora")]
// use bdk::blockchain::esplora::EsploraBlockchainConfig; //haven't gotten import
use bdk_bitcoind_rpc::bitcoincore_rpc::Auth;
use bdk_esplora::EsploraAsyncExt;
#[cfg(feature = "compact_filters")]
use bdk_reserves::bdk::blockchain::compact_filters::{
    BitcoinPeerConfig, CompactFiltersBlockchainConfig,
}; // can't find compact_filters
use bdk_reserves::bdk::blockchain::ConfigurableBlockchain;
#[cfg(feature = "rpc")]
use bdk_wallet::blockchain::rpc::{RpcConfig, RpcSyncParams};
#[cfg(feature = "electrum")]
use bdk_wallet::blockchain::ElectrumBlockchainConfig;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
use bdk_wallet::blockchain::{AnyBlockchain, AnyBlockchainConfig, ConfigurableBlockchain};
#[cfg(feature = "sqlite-db")]
use bdk_wallet::rusqlite::{Connection, OpenFlags};

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

/// Fetch all the utxos, for a given address.
#[cfg(all(feature = "reserves", feature = "electrum"))]
pub fn get_outpoints_for_address(
    address: Address,
    client: &Client,
    max_confirmation_height: Option<usize>,
) -> Result<Vec<(OutPoint, TxOut)>, Error> {
    let unspents = client
        .script_list_unspent(&address.script_pubkey())
        .map_err(|e| Error::Generic(e.to_string()))?;
    unspents
        .iter()
        .filter(|utxo| {
            utxo.height > 0 && utxo.height <= max_confirmation_height.unwrap_or(usize::MAX)
        })
        .map(|utxo| {
            let tx = match client.transaction_get(&utxo.tx_hash) {
                Ok(tx) => tx,
                Err(e) => return Err(e).map_err(|e| Error::Generic(e.to_string()))?,
            };

            Ok((
                OutPoint {
                    txid: utxo.tx_hash,
                    vout: utxo.tx_pos as u32,
                },
                tx.output[utxo.tx_pos].clone(),
            ))
        })
        .collect()
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
pub(crate) fn prepare_home_dir(home_path: Option<PathBuf>) -> Result<PathBuf, Error> {
    let dir = home_path.unwrap_or_else(|| {
        let mut dir = PathBuf::new();
        dir.push(
            dirs_next::home_dir()
                .ok_or_else(|| Error::Generic("home dir not found".to_string()))
                .unwrap(),
        );
        dir.push(".bdk-bitcoin");
        dir
    });

    if !dir.exists() {
        log::info!("Creating home directory {}", dir.as_path().display());
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

/// Prepare bdk_cli wallet directory.
#[cfg(any(feature = "sqlite-db", feature = "compact_filters"))]
fn prepare_wallet_dir(wallet_name: &str, home_path: &Path) -> Result<PathBuf, Error> {
    let mut dir = home_path.to_owned();

    dir.push(wallet_name);

    if !dir.exists() {
        log::info!("Creating wallet directory {}", dir.as_path().display());
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

/// Prepare wallet database directory.
#[cfg(feature = "sqlite-db")]
fn prepare_wallet_db_dir(wallet_name: &str, home_path: &Path) -> Result<PathBuf, Error> {
    let mut db_dir = prepare_wallet_dir(wallet_name, home_path)?;

    db_dir.push("wallet.sqlite");

    Ok(db_dir)
}

/// Prepare blockchain data directory (for compact filters).
#[cfg(feature = "compact_filters")]
fn prepare_bc_dir(wallet_name: &str, home_path: &Path) -> Result<PathBuf, Error> {
    let mut bc_dir = prepare_wallet_dir(wallet_name, home_path)?;

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

/// Create the global bitcoind directory.
/// multiple wallets can access the same node datadir, and they will have separate
/// wallet names in `<home_path>/bitcoind/regtest/wallets`.
#[cfg(feature = "regtest-node")]
pub(crate) fn prepare_bitcoind_datadir(home_path: &Path) -> Result<PathBuf, Error> {
    let mut dir = home_path.to_owned();

    dir.push("bitcoind");

    if !dir.exists() {
        log::info!("Creating node directory {}", dir.as_path().display());
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

/// Create the global electrsd directory.
/// multiple wallets can access the same node datadir, and they will have separate
/// wallet names in `<home_path>/bitcoind/regtest/wallets`.
#[cfg(feature = "regtest-electrum")]
pub(crate) fn prepare_electrum_datadir(home_path: &Path) -> Result<PathBuf, Error> {
    let mut dir = home_path.to_owned();

    dir.push("electrsd");

    if !dir.exists() {
        log::info!("Creating node directory {}", dir.as_path().display());
        std::fs::create_dir(&dir).map_err(|e| Error::Generic(e.to_string()))?;
    }

    Ok(dir)
}

#[allow(unused_variables)]
#[cfg(feature = "sqlite-db")]
/// Open the wallet database.
pub(crate) fn open_database(
    wallet_opts: &WalletOpts,
    home_path: &Path,
) -> Result<Connection, Error> {
    let wallet_name = wallet_opts.wallet.as_ref().expect("wallet name");
    let database_path = prepare_wallet_db_dir(wallet_name, home_path)?;

    let db_file = database_path.join("wallet.sqlite");

    let database = Connection::open_with_flags(db_file, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    log::debug!("database opened successfully");
    Ok(database)
}

/// Create a new backend node at given datadir.
#[allow(dead_code)]
pub(crate) fn new_backend(_datadir: &Path) -> Result<Nodes, Error> {
    #[cfg(feature = "regtest-node")]
    let bitcoind = {
        // Configure node directory according to cli options
        // nodes always have a persistent directory
        let datadir = prepare_bitcoind_datadir(_datadir)?;
        let mut bitcoind_conf = electrsd::corepc_node::Conf::default();
        bitcoind_conf.staticdir = Some(datadir);
        let bitcoind_exe =
            electrsd::downloaded_exe_path().expect("We should always have downloaded path");
        let node = electrsd::corepc_node::Node::with_conf(bitcoind_exe, &bitcoind_conf)?;
        Arc::new(node)
    };

    #[cfg(feature = "regtest-bitcoin")]
    let backend = {
        Nodes::Bitcoin {
            bitcoind: Arc::clone(&bitcoind),
        }
    };

    #[cfg(feature = "regtest-electrum")]
    let backend = {
        // Configure node directory according to cli options
        // nodes always have a persistent directory
        let datadir = prepare_electrum_datadir(_datadir)?;
        let mut elect_conf = electrsd::Conf::default();
        elect_conf.staticdir = Some(datadir);
        let elect_exe =
            electrsd::downloaded_exe_path().expect("We should always have downloaded path");
        let electrsd = electrsd::ElectrsD::with_conf(elect_exe, &bitcoind, &elect_conf)?;
        Nodes::Electrum {
            bitcoind: Arc::clone(&bitcoind),
            electrsd: Box::new(electrsd),
        }
    };

    #[cfg(any(feature = "regtest-esplora-ureq", feature = "regtest-esplora-reqwest"))]
    let backend = {
        // Configure node directory according to cli options
        // nodes always have a persistent directory
        let datadir = prepare_electrum_datadir(_datadir)?;
        let mut elect_conf = electrsd::Conf::default();
        elect_conf.staticdir = Some(datadir);
        elect_conf.http_enabled = true;
        let elect_exe =
            electrsd::downloaded_exe_path().expect("Electrsd downloaded binaries not found");
        let electrsd = electrsd::ElectrsD::with_conf(elect_exe, &bitcoind, &elect_conf).unwrap();
        Nodes::Esplora {
            bitcoind: Arc::clone(&bitcoind),
            esplorad: Box::new(electrsd),
        }
    };

    #[cfg(not(feature = "regtest-node"))]
    let backend = Nodes::None;

    Ok(backend)
}

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
/// Create a new blockchain for a given [Nodes] if available
/// or else create one from the wallet configuration options.
pub(crate) fn new_blockchain(
    _network: Network,
    wallet_opts: &WalletOpts,
    _backend: &Nodes,
    _home_dir: &Path,
) -> Result<AnyBlockchain, Error> {
    #[cfg(feature = "electrum")]
    let config = {
        let url = match _backend {
            #[cfg(feature = "regtest-electrum")]
            Nodes::Electrum { electrsd, .. } => &electrsd.electrum_url,
            _ => &wallet_opts.electrum_opts.server,
        };

        AnyBlockchainConfig::Electrum(ElectrumBlockchainConfig {
            url: url.to_owned(),
            socks5: wallet_opts.proxy_opts.proxy.clone(),
            retry: wallet_opts.proxy_opts.retries,
            timeout: wallet_opts.electrum_opts.timeout,
            stop_gap: wallet_opts.electrum_opts.stop_gap,
            validate_domain: true,
        })
    };

    #[cfg(feature = "esplora")]
    let config = {
        let url = match _backend {
            #[cfg(any(feature = "regtest-esplora-ureq", feature = "regtest-esplora-reqwest"))]
            Nodes::Esplora { esplorad, bitcoind } => {
                esplorad.esplora_url.expect("Esplora url expected")
            }
            _ => wallet_opts.esplora_opts.server.clone(),
        };

        AnyBlockchainConfig::Esplora(EsploraBlockchainConfig {
            base_url: url,
            timeout: Some(wallet_opts.esplora_opts.timeout),
            concurrency: Some(wallet_opts.esplora_opts.conc),
            stop_gap: wallet_opts.esplora_opts.stop_gap,
            proxy: wallet_opts.proxy_opts.proxy.clone(),
        })
    };

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
            storage_dir: prepare_bc_dir(wallet_name, _home_dir)?
                .into_os_string()
                .into_string()
                .map_err(|_| Error::Generic("Internal OS_String conversion error".to_string()))?,
            skip_blocks: Some(wallet_opts.compactfilter_opts.skip_blocks),
        })
    };

    #[cfg(feature = "rpc")]
    let config: AnyBlockchainConfig = {
        let (url, auth) = match _backend {
            #[cfg(feature = "regtest-node")]
            Nodes::Bitcoin { bitcoind } => (
                bitcoind.params.rpc_socket.to_string(),
                Auth::CookieFile(bitcoind.params.cookie_file.clone()),
            ),
            _ => {
                let auth = if let Some(cookie) = &wallet_opts.rpc_opts.cookie {
                    Auth::CookieFile(cookie.into())
                } else {
                    Auth::UserPass(
                        wallet_opts.rpc_opts.basic_auth.0.clone(),
                        wallet_opts.rpc_opts.basic_auth.1.clone(),
                    )
                };
                (wallet_opts.rpc_opts.address.clone(), auth)
            }
        };
        let wallet_name = wallet_opts
            .wallet
            .to_owned()
            .expect("Wallet name should be available this level");

        let rpc_url = "http://".to_string() + &url;

        let rpc_config = RpcConfig {
            url: rpc_url,
            auth,
            network: _network,
            wallet_name,
            // TODO add cli options to set all rpc sync params
            sync_params: Some(RpcSyncParams {
                start_time: wallet_opts.rpc_opts.start_time,
                ..Default::default()
            }),
        };

        AnyBlockchainConfig::Rpc(rpc_config)
    };

    AnyBlockchain::from_config(&config)
}

/// Create a new wallet from given wallet configuration options.
pub(crate) fn new_wallet(
    network: Network,
    wallet_opts: &WalletOpts,
    mut database: Connection,
) -> Result<PersistedWallet<Connection>, Error> {
    let descriptor = wallet_opts.descriptor.clone();
    let change_descriptor = wallet_opts.change_descriptor.clone();
    let wallet = Wallet::create(descriptor, change_descriptor.unwrap())
        .network(network)
        .create_wallet(&mut database)
        .map_err(|e| Error::Generic(e.to_string()))?;

    #[cfg(feature = "hardware-signer")]
    let wallet = add_hardware_signers(wallet, network)?;

    Ok(wallet)
}

/// Add hardware wallets as signers to the wallet
#[cfg(feature = "hardware-signer")]
fn add_hardware_signers(
    wallet: PersistedWallet<Connection>,
    network: Network,
) -> Result<PersistedWallet<Connection>, Error> {
    let mut wallet = wallet;
    let chain = HWIChain::from(network);
    let devices = HWIClient::enumerate().map_err(|e| Error::Generic(e.to_string()))?;
    for device in devices {
        let device = device.map_err(|e| Error::Generic(e.to_string()))?;
        // Creating a custom signer from the device
        let custom_signer = HWISigner::from_device(&device, chain.clone())
            .map_err(|e| Error::Generic(e.to_string()))?;

        // Adding the hardware signer to the BDK wallet
        wallet.add_signer(
            KeychainKind::External,
            SignerOrdering(200),
            Arc::new(custom_signer),
        );
        println!("Added {} as a signer to the wallet.", device.model);
    }

    Ok(wallet)
}
