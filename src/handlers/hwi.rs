//! Hardware wallet (HWI) command handlers.
//!
//! HWI operations are split by their data dependency:
//!
//! - Device-only utilities live under the top-level `hwi` command
//!   ([`HwiCommand`]): `hwi xpub` reads a device extended public key and
//!   `hwi devices` lists connected devices. Neither needs a wallet — `hwi xpub`
//!   is the bootstrap step used to build a descriptor.
//! - Wallet-scoped operations live under `wallet <name> hwi …`
//!   ([`WalletHwiCommand`]): `register`, `address` and `sign`. These take the
//!   wallet policy from the loaded wallet's descriptors, so no descriptor needs
//!   to be passed on the command line.

use async_hwi::AddressScript;
use bdk_wallet::KeychainKind;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::str::FromStr;

use crate::error::BDKCliError as Error;
use crate::handlers::{AppContext, AsyncAppCommand, Init, OfflineOperations};
use crate::utils::hwi::{HwiWallet, enumerate_hwi_devices, first_hwi_device};

use bdk_wallet::bitcoin::{
    Psbt,
    bip32::{ChildNumber, DerivationPath},
    hex::DisplayHex,
};
use bdk_wallet::miniscript::{Descriptor, DescriptorPublicKey, descriptor::ShInner};

/// Device-only HWI utilities that do not require a wallet.
#[derive(Debug, Parser, Clone, PartialEq, Eq)]
pub struct HwiCommand {
    #[command(subcommand)]
    pub subcommand: HwiSubCommand,
}

/// Subcommands for the top-level `hwi` command.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
#[command(rename_all = "snake")]
pub enum HwiSubCommand {
    /// Read an extended public key from the device at a derivation path.
    ///
    /// Needed to build a wallet descriptor for the device.
    Xpub {
        /// Derivation path, e.g. `m/84'/1'/0'`.
        #[arg(default_value = "m/84'/1'/0'")]
        path: String,

        /// Output descriptor script type.
        #[arg(long = "type", value_parser = ["wpkh", "tr", "pkh"])]
        script_type: Option<String>,
    },
    /// List all connected hardware wallet devices.
    Devices,
}

impl AsyncAppCommand<AppContext<Init>> for HwiCommand {
    type Output = serde_json::Value;

    async fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let network = ctx.network;
        // Device-only commands operate without a wallet policy.
        let hwi_wallet = HwiWallet::default();

        match &self.subcommand {
            HwiSubCommand::Xpub { path, script_type } => {
                let derivation = DerivationPath::from_str(path)
                    .map_err(|e| Error::Generic(format!("Invalid derivation path: {e}")))?;
                let device = first_hwi_device(network, &hwi_wallet).await?;
                let xpub = device.get_extended_pubkey(&derivation).await?;
                let fingerprint = device.get_master_fingerprint().await?.to_string();
                let origin = path.trim_start_matches('m').trim_start_matches('/');
                let key_expression = format!("[{fingerprint}/{origin}]{xpub}");

                let mut out = json!({
                    "path": path,
                    "xpub": xpub.to_string(),
                    "master_fingerprint": fingerprint,
                    "key_expression": key_expression,
                });

                match script_type
                    .clone()
                    .or_else(|| infer_script_type(path).map(str::to_string))
                {
                    Some(stype) => {
                        out["script_type"] = json!(stype);
                        out["external_descriptor"] =
                            json!(build_descriptor(&stype, &key_expression, 0)?);
                        out["internal_descriptor"] =
                            json!(build_descriptor(&stype, &key_expression, 1)?);
                    }
                    None => {
                        out["note"] = json!(
                            "Non-standard or multisig path; pass --type to emit descriptors, or use key_expression"
                        );
                    }
                }
                Ok(out)
            }

            HwiSubCommand::Devices => {
                let devices = enumerate_hwi_devices(network, &hwi_wallet).await?;
                let mut listed = Vec::with_capacity(devices.len());
                for device in &devices {
                    let fingerprint = device.get_master_fingerprint().await?.to_string();
                    listed.push(json!({
                        "fingerprint": fingerprint,
                        "model": device.device_kind().to_string(),
                    }));
                }
                Ok(json!({ "count": listed.len(), "devices": listed }))
            }
        }
    }
}

/// Wallet-scoped HWI operations (`wallet <name> hwi …`).
#[derive(Debug, Parser, Clone, PartialEq, Eq)]
pub struct WalletHwiCommand {
    /// Registration HMAC returned by `register`, required to reuse a registered
    /// policy on a Ledger for `address`/`sign`.
    #[arg(env = "HWI_HMAC", long)]
    pub hmac: Option<String>,
    #[command(subcommand)]
    pub subcommand: WalletHwiSubCommand,
}

/// Subcommands for `wallet <name> hwi`.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
#[command(rename_all = "snake")]
pub enum WalletHwiSubCommand {
    /// Register the wallet's policy on the device, returning its HMAC.
    Register,
    /// Display a receive address on the device.
    Address {
        /// Address index to derive.
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Derive from the change (internal) keychain instead of external.
        #[arg(long)]
        change: bool,
    },
    /// Sign a PSBT with the device.
    ///
    /// The device produces partial signatures; the returned PSBT still needs to
    /// be finalized before it can be broadcasted.
    Sign {
        /// The base64-encoded PSBT to sign.
        psbt: String,
    },
}

impl WalletHwiCommand {
    /// Run a wallet-scoped HWI operation. The wallet policy is derived from the
    /// loaded wallet's public descriptors and `wallet_name` is used as the
    /// device registration name.
    pub async fn run(
        &self,
        ctx: &mut AppContext<OfflineOperations<'_>>,
        wallet_name: &str,
    ) -> Result<serde_json::Value, Error> {
        let network = ctx.network;

        // Derive the multipath policy from the wallet's public descriptors.
        let ext_desc = ctx
            .state
            .wallet
            .public_descriptor(KeychainKind::External)
            .clone();
        let int_desc = ctx
            .state
            .wallet
            .public_descriptor(KeychainKind::Internal)
            .clone();

        let kind = WalletKind::classify(&ext_desc);

        // Only multisig/miniscript wallets get a registered device policy;
        // single-sig wallets are signed straight from the PSBT, so attaching a
        // policy (which BitBox/Ledger reject for single-sig) is skipped.

        let ext = ext_desc.to_string();
        let int = int_desc.to_string();
        let int = if int == ext { None } else { Some(int) };
        let policy = build_device_policy(&ext, int.as_deref())?;

        let hwi_wallet = HwiWallet {
            name: Some(wallet_name),
            policy: matches!(kind, WalletKind::Policy).then_some(policy.as_str()),
            hmac: self.hmac.as_deref(),
        };

        match &self.subcommand {
            WalletHwiSubCommand::Register => {
                tracing::debug!("Registering wallet '{wallet_name}' with policy '{policy}'");
                let device = first_hwi_device(network, &hwi_wallet).await?;
                match device.register_wallet(wallet_name, &policy).await {
                    Ok(hmac) => Ok(json!({
                        "success": true,
                        "hmac": hmac.map(|h| h.to_lower_hex_string()),
                    })),
                    // Some devices don't implement registration.
                    Err(async_hwi::Error::UnimplementedMethod) => Ok(json!({
                        "success": true,
                        "hmac": null,
                        "message": "This device does not support wallet registration",
                    })),
                    Err(e) => Err(Error::HwiError(e)),
                }
            }
            WalletHwiSubCommand::Address { index, change } => {
                let keychain = if *change {
                    KeychainKind::Internal
                } else {
                    KeychainKind::External
                };
                let address = ctx
                    .state
                    .wallet
                    .peek_address(keychain, *index)
                    .address
                    .to_string();

                // Attempt to derive and display the address on the device and on the cli.
                // If it fails to derive from the device, it falls back on the wallet to generate and display
                let script = match kind {
                    WalletKind::TaprootSingleSig => {
                        let desc = if *change { &int_desc } else { &ext_desc };
                        taproot_address_path(desc, *index).map(AddressScript::P2TR)
                    }
                    _ => Some(AddressScript::Miniscript {
                        index: *index,
                        change: *change,
                    }),
                };

                let device = first_hwi_device(network, &hwi_wallet).await?;
                let displayed = match script {
                    Some(script) => match device.display_address(&script).await {
                        Ok(()) => (
                            true,
                            "Verify this address matches the one shown on your device".to_string(),
                        ),
                        // The device attempted but declined (e.g. unsupported
                        // for this script type, or no registered policy).
                        Err(e) => (
                            false,
                            format!("Device did not display the address ({e}); showing the locally derived address"),
                        ),
                    },
                    None => (
                        false,
                        "Could not build a device address request; showing the locally derived address".to_string(),
                    ),
                };

                Ok(json!({
                    "index": index,
                    "change": change,
                    "address": address,
                    "displayed_on_device": displayed,
                }))
            }

            WalletHwiSubCommand::Sign { psbt } => {
                let mut psbt = Psbt::from_str(psbt)
                    .map_err(|e| Error::Generic(format!("Failed to parse PSBT: {e}")))?;
                let device = first_hwi_device(network, &hwi_wallet).await?;
                device.sign_tx(&mut psbt).await?;
                Ok(json!({ "psbt": psbt.to_string() }))
            }
        }
    }
}

/// Strip a trailing descriptor checksum.
fn strip_checksum(descriptor: &str) -> &str {
    descriptor.split('#').next().unwrap_or(descriptor)
}

/// How a wallet's descriptor maps onto a hardware device's capabilities.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WalletKind {
    /// BIP-86 taproot single-sig — shown on device via the simple P2TR path.
    TaprootSingleSig,
    /// Other single-sig (wpkh/pkh/sh-wpkh) — signable, but no on-device address
    /// display path in async-hwi.
    SingleSig,
    /// Multisig/miniscript — requires policy registration.
    Policy,
}

impl WalletKind {
    fn classify(desc: &Descriptor<DescriptorPublicKey>) -> Self {
        match desc {
            Descriptor::Tr(tr) if tr.tap_tree().is_none() => WalletKind::TaprootSingleSig,
            Descriptor::Wpkh(_) | Descriptor::Pkh(_) => WalletKind::SingleSig,
            Descriptor::Sh(sh) if matches!(sh.as_inner(), ShInner::Wpkh(_)) => {
                WalletKind::SingleSig
            }
            _ => WalletKind::Policy,
        }
    }
}

/// Build the full BIP-32 path (from the master key) to the taproot single-sig
/// address at `index`, e.g. `86'/1'/0'/0/index`. Returns `None` unless the
/// descriptor is a keyspend-only taproot over an xpub key.
fn taproot_address_path(
    desc: &Descriptor<DescriptorPublicKey>,
    index: u32,
) -> Option<DerivationPath> {
    let Descriptor::Tr(tr) = desc else {
        return None;
    };
    if tr.tap_tree().is_some() {
        return None;
    }
    let DescriptorPublicKey::XPub(xkey) = tr.internal_key() else {
        return None;
    };
    // Full path from the master key: [origin]/[xpub derivation]/index.
    let base = match &xkey.origin {
        Some((_, origin_path)) => origin_path.extend(&xkey.derivation_path),
        None => xkey.derivation_path.clone(),
    };
    let index = ChildNumber::from_normal_idx(index).ok()?;
    Some(base.extend([index]))
}

/// Infer the single-sig descriptor script type from a derivation path's.
fn infer_script_type(path: &str) -> Option<&'static str> {
    let purpose = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != "m")
        .find_map(|s| s.trim_end_matches(['\'', 'h']).parse::<u32>().ok())?;
    match purpose {
        44 => Some("pkh"),
        49 => Some("sh-wpkh"),
        84 => Some("wpkh"),
        86 => Some("tr"),
        _ => None,
    }
}

/// Wrap a key expression into a checksummed single-sig descriptor for the given
/// keychain branch (0 = external, 1 = internal).
fn build_descriptor(script_type: &str, key_expr: &str, branch: u32) -> Result<String, Error> {
    let raw = match script_type {
        "tr" => format!("tr({key_expr}/{branch}/*)"),
        "pkh" => format!("pkh({key_expr}/{branch}/*)"),
        "sh-wpkh" => format!("sh(wpkh({key_expr}/{branch}/*))"),
        _ => format!("wpkh({key_expr}/{branch}/*)"),
    };
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&raw)
        .map_err(|e| Error::Generic(format!("Failed to build descriptor: {e}")))?;
    Ok(descriptor.to_string())
}

/// Build the wallet policy
///
/// - Rejects private-key.
/// - Passes an already-multipath descriptor (`/**` or `/<..>/*`) through
///   unchanged.
/// - Combines a standard `/0/*` external and `/1/*` internal pair into a single
///   `/<0;1>/*` multipath descriptor.
fn build_device_policy(ext: &str, int: Option<&str>) -> Result<String, Error> {
    let ext = strip_checksum(ext).trim().to_string();

    if ext.contains("xprv") || ext.contains("tprv") {
        return Err(Error::Generic(
            "Hardware wallet policy must use public keys (xpub), not private keys".to_string(),
        ));
    }

    // Already a multipath descriptor: use as-is.
    if ext.contains("/**") || ext.contains('<') {
        return Ok(ext);
    }

    match int {
        Some(int) => {
            let int = strip_checksum(int).trim();
            if int.contains("xprv") || int.contains("tprv") {
                return Err(Error::Generic(
                    "Hardware wallet policy must use public keys (xpub), not private keys"
                        .to_string(),
                ));
            }
            // `/0/*` and `/1/*` only ever appear as a key's wildcard branch.
            if ext.replace("/0/*", "/1/*") != int {
                return Err(Error::Generic(
                    "Cannot derive a multipath policy: the wallet's external and internal \
                     descriptors are not a standard `/0/*` and `/1/*` pair."
                        .to_string(),
                ));
            }
            Ok(ext.replace("/0/*", "/<0;1>/*"))
        }
        None => {
            tracing::warn!(
                "Wallet has no separate internal (change) descriptor; the device policy will \
                 only cover receive addresses."
            );
            Ok(ext)
        }
    }
}
