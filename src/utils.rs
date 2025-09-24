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
use std::{
    fmt::{Display, Formatter},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::commands::WalletOpts;
#[cfg(feature = "cbf")]
use bdk_kyoto::{
    BuilderExt, Info, LightClient, Receiver, ScanType::Sync, UnboundedReceiver, Warning,
    builder::Builder,
};
use bdk_wallet::bitcoin::{Address, Network, OutPoint, ScriptBuf};
use bdk_wallet::miniscript::Legacy;

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

use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::bip32::Fingerprint;
use bdk_wallet::bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use bdk_wallet::descriptor::{
    Segwitv0, {Descriptor, DescriptorPublicKey},
};
use bdk_wallet::keys::{
    DerivableKey, ExtendedKey,
    bip39::WordCount,
    {DescriptorSecretKey, GeneratableKey, GeneratedKey, IntoDescriptorKey},
};
use bdk_wallet::miniscript::{
    Tap,
    descriptor::{DescriptorXKey, Wildcard},
};
use serde_json::{Value, json};

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
            let scan_type = Sync;
            let builder = Builder::new(_wallet.network());

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
    mut info_subcriber: Receiver<Info>,
    mut warning_subscriber: UnboundedReceiver<Warning>,
) {
    loop {
        tokio::select! {
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
        info_subscriber,
        warning_subscriber,
        mut update_subscriber,
        node,
    } = *client;

    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| Error::Generic(format!("SetGlobalDefault error: {e}")))?;

    tokio::task::spawn(async move { node.run().await });
    tokio::task::spawn(async move { trace_logger(info_subscriber, warning_subscriber).await });

    if !requester.is_running() {
        tracing::error!("Kyoto node is not running");
        return Err(Error::Generic("Kyoto node failed to start".to_string()));
    }
    tracing::info!("Kyoto node is running");

    let update = update_subscriber.update().await?;
    tracing::info!("Received update: applying to wallet");
    wallet
        .apply_update(update)
        .map_err(|e| Error::Generic(format!("Failed to apply update: {e}")))?;

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

pub fn is_mnemonic(s: &str) -> bool {
    let word_count = s.split_whitespace().count();
    (12..=24).contains(&word_count) && s.chars().all(|c| c.is_alphanumeric() || c.is_whitespace())
}

pub fn generate_descriptors(
    network: &Network,
    descriptor_type: DescriptorType,
    key: &str,
    multipath_label: bool,
) -> Result<Value, Error> {
    type DescriptorConstructor =
        fn(DescriptorPublicKey) -> Result<Descriptor<DescriptorPublicKey>, Error>;

    let purpose = match descriptor_type {
        DescriptorType::Bip44 => 44,
        DescriptorType::Bip49 => 49,
        DescriptorType::Bip84 => 84,
        DescriptorType::Bip86 => 86,
    };

    let derivation_base = format!("/{purpose}h/1h/0h");

    let descriptor_constructor: DescriptorConstructor = match descriptor_type {
        DescriptorType::Bip44 => |key| Descriptor::new_pkh(key).map_err(Error::from),
        DescriptorType::Bip49 => |key| Descriptor::new_sh_wpkh(key).map_err(Error::from),
        DescriptorType::Bip84 => |key| Descriptor::new_wpkh(key).map_err(Error::from),
        DescriptorType::Bip86 => |key| Descriptor::new_tr(key, None).map_err(Error::from),
    };

    let secp = Secp256k1::new();
    let derivation_path = DerivationPath::from_str(&format!("m{derivation_base}"))?;

    let is_private = key.starts_with("xprv") || key.starts_with("tprv");

    type DescriptorBuilderFn = Box<dyn Fn(u32) -> Result<(String, Option<String>), Error>>;

    let (fingerprint, make_desc): (Fingerprint, DescriptorBuilderFn) = if is_private {
        let xprv: Xpriv = key.parse()?;
        let fingerprint = xprv.fingerprint(&secp);

        let closure = move |change: u32| -> Result<(String, Option<String>), Error> {
            let branch_path = DerivationPath::from_str(&change.to_string())?;

            let desc_xprv = DescriptorXKey {
                origin: Some((fingerprint, derivation_path.clone())),
                xkey: xprv,
                derivation_path: branch_path,
                wildcard: Wildcard::Unhardened,
            };

            let desc_secret = DescriptorSecretKey::XPrv(desc_xprv.clone());
            let (desc_key, keymap, _) = match descriptor_type {
                DescriptorType::Bip44 => {
                    IntoDescriptorKey::<Legacy>::into_descriptor_key(desc_secret)?.extract(&secp)?
                }
                DescriptorType::Bip84 | DescriptorType::Bip49 => {
                    IntoDescriptorKey::<Segwitv0>::into_descriptor_key(desc_secret)?
                        .extract(&secp)?
                }
                DescriptorType::Bip86 => {
                    IntoDescriptorKey::<Tap>::into_descriptor_key(desc_secret)?.extract(&secp)?
                }
            };

            let descriptor = descriptor_constructor(desc_key)?;
            Ok((
                descriptor.to_string(),
                Some(descriptor.to_string_with_secret(&keymap)),
            ))
        };

        (fingerprint, Box::new(closure))
    } else {
        let xpub: Xpub = key.parse()?;
        let fingerprint = xpub.fingerprint();

        let closure = move |change: u32| -> Result<(String, Option<String>), Error> {
            let branch_path = DerivationPath::from_str(&change.to_string())?;

            let desc_xpub = DescriptorXKey {
                origin: Some((fingerprint, derivation_path.clone())),
                xkey: xpub,
                derivation_path: branch_path,
                wildcard: Wildcard::Unhardened,
            };

            let desc_key = DescriptorPublicKey::XPub(desc_xpub);
            let descriptor = descriptor_constructor(desc_key)?;
            Ok((descriptor.to_string(), None))
        };

        (fingerprint, Box::new(closure))
    };

    let (external_pub, external_priv) = make_desc(0)?;
    let (internal_pub, internal_priv) = make_desc(1)?;

    let type_label = if multipath_label {
        format!("{descriptor_type}-multipath")
    } else {
        descriptor_type.to_string()
    };

    let mut result = json!({
        "type": type_label,
        "public_descriptors": {
            "external": external_pub,
            "internal": internal_pub
        },
        "fingerprint": fingerprint.to_string(),
        "network": network.to_string(),
    });

    if let (Some(priv_ext), Some(priv_int)) = (external_priv, internal_priv) {
        result["private_descriptors"] = json!({
            "external": priv_ext,
            "internal": priv_int
        });
    }

    Ok(result)
}

pub fn generate_new_descriptor_with_mnemonic(
    network: Network,
    descriptor_type: DescriptorType,
) -> Result<serde_json::Value, Error> {
    let mnemonic: GeneratedKey<Mnemonic, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English)).map_err(Error::BIP39Error)?;

    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed)?;

    let mut result = generate_descriptors(&network, descriptor_type, &xprv.to_string(), false)?;
    result["mnemonic"] = json!(mnemonic.to_string());
    Ok(result)
}

pub fn generate_descriptor_from_mnemonic_string(
    mnemonic_str: &str,
    network: Network,
    descriptor_type: DescriptorType,
) -> Result<serde_json::Value, Error> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)?;
    let ext_key: ExtendedKey = mnemonic.into_extended_key()?;
    let xprv = ext_key
        .into_xprv(network)
        .ok_or_else(|| Error::Generic("No xprv found".to_string()))?;

    let mut result = generate_descriptors(&network, descriptor_type, &xprv.to_string(), false)?;
    result["mnemonic"] = json!(mnemonic_str);
    Ok(result)
}

// Enum for descriptor types
#[derive(Debug, Clone, Copy)]
pub enum DescriptorType {
    Bip44,
    Bip49,
    Bip84,
    Bip86,
}

impl Display for DescriptorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DescriptorType::Bip44 => "bip44",
            DescriptorType::Bip49 => "bip49",
            DescriptorType::Bip84 => "bip84",
            DescriptorType::Bip86 => "bip86",
        };
        write!(f, "{s}")
    }
}

pub(crate) fn shorten(displayable: impl Display, start: u8, end: u8) -> String {
    let displayable = displayable.to_string();
    let start_str: &str = &displayable[0..start as usize];
    let end_str: &str = &displayable[displayable.len() - end as usize..];
    format!("{start_str}...{end_str}")
}
