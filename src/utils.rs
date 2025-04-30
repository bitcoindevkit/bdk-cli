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
use std::{fmt::Display, path::{Path, PathBuf}, str::FromStr};
use std::str::FromStr;

use std::path::{Path, PathBuf};

use crate::commands::WalletOpts;
#[cfg(feature = "cbf")]
use bdk_kyoto::{
    BuilderExt, Info, LightClient, Receiver, ScanType::Sync, UnboundedReceiver, Warning,
    builder::Builder,
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

use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::bip32::ChildNumber;
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

pub(crate) fn shorten(displayable: impl Display, start: u8, end: u8) -> String {
    let displayable = displayable.to_string();
    let start_str: &str = &displayable[0..start as usize];
    let end_str: &str = &displayable[displayable.len() - end as usize..];
    format!("{start_str}...{end_str}")
pub fn generate_descriptor_from_key_by_type(
    network: &Network,
    key: &str,
    descriptor_type: DescriptorType,
) -> Result<serde_json::Value, Error> {
    let derivation_path = match descriptor_type {
        DescriptorType::Bip44 => "m/44h/1h/0h",
        DescriptorType::Bip49 => "m/49h/1h/0h",
        DescriptorType::Bip84 => "m/84h/1h/0h",
        DescriptorType::Bip86 => "m/86h/1h/0h",
    };

    generate_bip_descriptor_from_key(network, key, derivation_path, descriptor_type)
}

pub fn generate_new_descriptor_with_mnemonic(
    network: Network,
    descriptor_type: DescriptorType,
) -> Result<serde_json::Value, Error> {
    let secp = Secp256k1::new();

    // Generate a new BIP39 mnemonic
    let mnemonic: GeneratedKey<Mnemonic, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English)).map_err(|e| {
            Error::MnemonicGenerationError(format!("Mnemonic generation failed: {:?}", e))
        })?;

    let seed = mnemonic.to_seed("");
    let xprv =
        Xpriv::new_master(network, &seed).map_err(|e| Error::XprivCreationError(e.to_string()))?;

    let origin = xprv.fingerprint(&secp);

    let (derivation_base, external_fmt, internal_fmt) = match descriptor_type {
        DescriptorType::Bip44 => ("/44h/1h/0h", "pkh", "pkh"),
        DescriptorType::Bip49 => ("/49h/1h/0h", "sh(wpkh", "sh(wpkh"),
        DescriptorType::Bip84 => ("/84h/1h/0h", "wpkh", "wpkh"),
        DescriptorType::Bip86 => ("/86h/1h/0h", "tr", "tr"),
    };
    let path = DerivationPath::from_str(&format!("m{}", derivation_base))
        .map_err(|e| Error::Generic(e.to_string()))?;

    let derived_xprv = xprv
        .derive_priv(&secp, &path)
        .map_err(|e| Error::Generic(e.to_string()))?;

    let xprv_str = derived_xprv.to_string();

    // Construct descriptors
    let external_desc = match descriptor_type {
        DescriptorType::Bip49 => format!(
            "{}([{}{}]{}{}))",
            external_fmt, origin, derivation_base, xprv_str, "/0"
        ),
        _ => format!(
            "{}([{}{}]{}{})",
            external_fmt, origin, derivation_base, xprv_str, "/0"
        ),
    };

    let internal_desc = match descriptor_type {
        DescriptorType::Bip49 => format!(
            "{}([{}{}]{}{}))",
            internal_fmt, origin, derivation_base, xprv_str, "/1"
        ),
        _ => format!(
            "{}([{}{}]{}{})",
            internal_fmt, origin, derivation_base, xprv_str, "/1"
        ),
    };

    // Parse descriptors
    let (ext_desc, ext_keymap) =
        Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &external_desc)
            .map_err(|e| Error::DescriptorParsingError(e.to_string()))?;

    let (int_desc, int_keymap) =
        Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &internal_desc).map_err(
            |e| {
                Error::DescriptorParsingError(format!("Failed to parse internal descriptor: {}", e))
            },
        )?;

    Ok(serde_json::json!({
        "type": descriptor_type.to_string(),
        "mnemonic": mnemonic.to_string(),
        "private_descriptors": {
            "external": ext_desc.to_string_with_secret(&ext_keymap),
            "internal": int_desc.to_string_with_secret(&int_keymap),
        },
        "public_descriptors": {
            "external": ext_desc.to_string(),
            "internal": int_desc.to_string(),
        }
    }))
}

pub fn generate_multipath_descriptor(
    network: &Network,
    script_type: u8,
    key: &str,
) -> Result<Value, Error> {
    use DescriptorType::*;

    let descriptor_type = match script_type {
        44 => Bip44,
        49 => Bip49,
        84 => Bip84,
        86 => Bip86,
        _ => return Err(Error::UnsupportedScriptType(script_type)),
    };

    type DescriptorConstructor =
        fn(DescriptorPublicKey) -> Result<Descriptor<DescriptorPublicKey>, Error>;

    let (derivation_base, descriptor_constructor): (&str, DescriptorConstructor) =
        match descriptor_type {
            Bip44 => ("/44h/1h/0h", |key| {
                Descriptor::new_pkh(key).map_err(Error::from)
            }),
            Bip49 => ("/49h/1h/0h", |key| {
                Descriptor::new_sh_wpkh(key).map_err(Error::from)
            }),
            Bip84 => ("/84h/1h/0h", |key| {
                Descriptor::new_wpkh(key).map_err(Error::from)
            }),
            Bip86 => ("/86h/1h/0h", |key| {
                Descriptor::new_tr(key, None).map_err(Error::from)
            }),
        };

    let secp = Secp256k1::new();
    let derivation_path = DerivationPath::from_str(&format!("m{}", derivation_base))
        .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;

    // Determine if it's an xprv or xpub
    let is_private = key.starts_with("xprv") || key.starts_with("tprv");

    // Use xprv or xpub accordingly
    type DescriptorBuilderFn = Box<dyn Fn(u32) -> Result<(String, Option<String>), Error>>;

    let (fingerprint, make_desc): (_, DescriptorBuilderFn) = if is_private {
        let xprv: Xpriv = key
            .parse()
            .map_err(|e| Error::InvalidKey(format!("Invalid xprv: {e}")))?;
        let fingerprint = xprv.fingerprint(&secp);

        let closure = move |change: u32| -> Result<(String, Option<String>), Error> {
            let branch_path = DerivationPath::from_str(&change.to_string())
                .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;

            let desc_xprv = DescriptorXKey {
                origin: Some((fingerprint, derivation_path.clone())),
                xkey: xprv,
                derivation_path: branch_path,
                wildcard: Wildcard::Unhardened,
            };

            let desc_secret = DescriptorSecretKey::XPrv(desc_xprv.clone());
            let (desc_key, keymap, _) = match descriptor_type {
                DescriptorType::Bip84 | DescriptorType::Bip49 | DescriptorType::Bip44 => {
                    IntoDescriptorKey::<Segwitv0>::into_descriptor_key(desc_secret)
                        .map_err(|e| Error::DescriptorKeyError(e.to_string()))?
                        .extract(&secp)
                        .map_err(|e| Error::DescriptorKeyError(e.to_string()))?
                }
                DescriptorType::Bip86 => IntoDescriptorKey::<Tap>::into_descriptor_key(desc_secret)
                    .map_err(|e| Error::DescriptorKeyError(e.to_string()))?
                    .extract(&secp)
                    .map_err(|e| Error::DescriptorKeyError(e.to_string()))?,
            };

            let public_descriptor = descriptor_constructor(desc_key.clone())?;
            let private_descriptor = descriptor_constructor(desc_key)?;

            Ok((
                public_descriptor.to_string(),
                Some(private_descriptor.to_string_with_secret(&keymap)),
            ))
        };

        (fingerprint, Box::new(closure))
    } else {
        let xpub: Xpub = key
            .parse()
            .map_err(|e| Error::InvalidKey(format!("Invalid xpub: {e}")))?;
        let fingerprint = xpub.fingerprint();

        let closure = move |change: u32| -> Result<(String, Option<String>), Error> {
            let branch_path = DerivationPath::from_str(&change.to_string())
                .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;

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

    // Build descriptors
    let (external_pub, external_priv) = make_desc(0)?;
    let (internal_pub, internal_priv) = make_desc(1)?;

    let mut result = json!({
        "type": format!("{}-multipath", descriptor_type),
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

pub fn generate_bip_descriptor_from_key(
    network: &Network,
    key: &str,
    derivation_path_str: &str,
    descriptor_type: DescriptorType,
) -> Result<serde_json::Value, Error> {
    let secp = Secp256k1::new();

    let derivation_path: DerivationPath = derivation_path_str
        .parse()
        .map_err(|e| Error::InvalidDerivationPath(format!("DerivationPath Error: {e}")))?;

    let xprv: Xpriv = key
        .parse()
        .map_err(|e| Error::InvalidKey(format!("Invalid xprv: {e}")))?;

    let fingerprint = xprv.fingerprint(&secp);

    let make_desc_key = |branch: u32| -> Result<(String, String), Error> {
        let branch_path = DerivationPath::from(vec![ChildNumber::Normal { index: branch }]);

        let desc_xprv = DescriptorXKey {
            origin: Some((fingerprint, derivation_path.clone())),
            xkey: xprv,
            derivation_path: branch_path.clone(),
            wildcard: Wildcard::Unhardened,
        };

        let desc_secret = DescriptorSecretKey::XPrv(desc_xprv.clone());

        let (desc_key, keymap, _) =
            IntoDescriptorKey::<Segwitv0>::into_descriptor_key(desc_secret.clone())
                .map_err(|e| Error::DescriptorKeyError(e.to_string()))?
                .extract(&secp)
                .map_err(|e| Error::DescriptorKeyError(e.to_string()))?;

        let public_descriptor = match descriptor_type {
            DescriptorType::Bip84 => Descriptor::new_wpkh(desc_key.clone())?,
            DescriptorType::Bip86 => Descriptor::new_tr(desc_key.clone(), None)?,
            DescriptorType::Bip49 => Descriptor::new_sh_wpkh(desc_key.clone())?,
            DescriptorType::Bip44 => Descriptor::new_pkh(desc_key.clone())?,
        };

        let private_descriptor = match descriptor_type {
            DescriptorType::Bip84 => Descriptor::new_wpkh(desc_key)?,
            DescriptorType::Bip86 => Descriptor::new_tr(desc_key, None)?,
            DescriptorType::Bip49 => Descriptor::new_sh_wpkh(desc_key)?,
            DescriptorType::Bip44 => Descriptor::new_pkh(desc_key)?,
        };

        Ok((
            public_descriptor.to_string(),
            private_descriptor.to_string_with_secret(&keymap),
        ))
    };

    let (external_pub, external_priv) = make_desc_key(0)?;
    let (internal_pub, internal_priv) = make_desc_key(1)?;

    Ok(json!({
        "type": descriptor_type.to_string(),
        "fingerprint": fingerprint.to_string(),
        "network": network.to_string(),
        "private_descriptors": {
            "external": external_priv,
            "internal": internal_priv
        },
        "public_descriptors": {
            "external": external_pub,
            "internal": internal_pub
        }
    }))
}

pub fn generate_descriptor_from_mnemonic_string(
    mnemonic_str: &str,
    network: Network,
    derivation_path_str: &str,
    descriptor_type: DescriptorType,
) -> Result<serde_json::Value, Error> {
    let secp = Secp256k1::new();

    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
        .map_err(|e| Error::Generic(e.to_string()))?;
    let ext_key: ExtendedKey = mnemonic
        .into_extended_key()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let xprv = ext_key
        .into_xprv(network)
        .ok_or_else(|| Error::Generic("No xprv found".to_string()))?;

    let _fingerprint = xprv.fingerprint(&secp);
    let derivation_path: DerivationPath = derivation_path_str
        .parse()
        .map_err(|e| Error::InvalidDerivationPath(format!("DerivationPath Error: {e}")))?;

    let xprv = xprv
        .derive_priv(&secp, &derivation_path)
        .map_err(|e| Error::InvalidKey(format!("Failed to derive xprv: {e}")))?;

    generate_bip_descriptor_from_key(
        &network,
        &xprv.to_string(),
        derivation_path_str,
        descriptor_type,
    )
}

pub fn is_mnemonic(s: &str) -> bool {
    let word_count = s.split_whitespace().count();
    (12..=24).contains(&word_count) && s.chars().all(|c| c.is_alphanumeric() || c.is_whitespace())
}
// Enum for descriptor types
#[derive(Debug, Clone, Copy)]
pub enum DescriptorType {
    Bip44,
    Bip49,
    Bip84,
    Bip86,
}
