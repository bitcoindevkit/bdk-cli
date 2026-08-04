//! Hardware wallet (HWI) command handlers.
//!
//! HWI operations are split by their data dependency:
//!
//! - Device-only utilities live under the top-level `hwi` command
//!   ([`HwiCommand`]): `hwi xpub` reads a device extended public key and
//!   `hwi devices` lists connected devices. Neither needs a wallet — `hwi xpub`
//!   is the bootstrap step used to build a descriptor in the first place.
//! - Wallet-scoped operations live under `wallet <name> hwi …`
//!   ([`WalletHwiCommand`]): `register`, `address` and `sign`. These take the
//!   wallet policy from the loaded wallet's descriptors, so no descriptor needs
//!   to be passed on the command line.
//!
//! `async-hwi` expects a *wallet policy*: a single, public (xpub) descriptor
//! whose keys carry origin info and use multipath (`/<0;1>/*`) notation so the
//! policy covers both the receive and change chains. BDK exposes the external
//! and internal chains as two single-path public descriptors, so
//! [`build_device_policy`] combines them into the multipath form the device
//! needs.

use async_hwi::AddressScript;
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::{Psbt, bip32::DerivationPath, hex::DisplayHex};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::str::FromStr;

use crate::error::BDKCliError as Error;
use crate::handlers::{AppContext, AsyncAppCommand, Init, OfflineOperations};
use crate::utils::hwi::{HwiWallet, enumerate_hwi_devices, first_hwi_device};

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
    /// Use this first to obtain the key material needed to build a wallet
    /// descriptor for the device. The output includes a ready-to-use key
    /// expression (`[fingerprint/path]xpub`) to drop into a descriptor.
    Xpub {
        /// Derivation path, e.g. `m/84'/1'/0'`.
        #[arg(default_value = "m/84'/1'/0'")]
        path: String,
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
            HwiSubCommand::Xpub { path } => {
                let derivation = DerivationPath::from_str(path)
                    .map_err(|e| Error::Generic(format!("Invalid derivation path: {e}")))?;
                let device = first_hwi_device(network, &hwi_wallet).await?;
                let xpub = device.get_extended_pubkey(&derivation).await?;
                let fingerprint = device.get_master_fingerprint().await?.to_string();
                let origin = path.trim_start_matches('m').trim_start_matches('/');
                let key_expression = format!("[{fingerprint}/{origin}]{xpub}");
                Ok(json!({
                    "path": path,
                    "xpub": xpub.to_string(),
                    "master_fingerprint": fingerprint,
                    "key_expression": key_expression,
                }))
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
        let ext = ctx
            .state
            .wallet
            .public_descriptor(KeychainKind::External)
            .to_string();
        let int = ctx
            .state
            .wallet
            .public_descriptor(KeychainKind::Internal)
            .to_string();
        // A single-descriptor wallet returns the same descriptor for both
        // keychains.
        let int = if int == ext { None } else { Some(int) };
        let policy = build_device_policy(&ext, int.as_deref())?;

        let hwi_wallet = HwiWallet {
            name: Some(wallet_name),
            policy: Some(&policy),
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
                    // Devices like Specter don't use BIP-388 policy registration.
                    Err(async_hwi::Error::UnimplementedMethod) => Ok(json!({
                        "success": true,
                        "hmac": null,
                        "message": "This device does not require policy registration",
                    })),
                    Err(e) => Err(Error::HwiError(e)),
                }
            }

            WalletHwiSubCommand::Address { index, change } => {
                let device = first_hwi_device(network, &hwi_wallet).await?;
                let script = AddressScript::Miniscript {
                    index: *index,
                    change: *change,
                };
                // Not every device can show an address on screen (e.g. Specter);
                // fall back to the locally derived address instead of failing.
                let displayed = match device.display_address(&script).await {
                    Ok(()) => true,
                    Err(async_hwi::Error::UnimplementedMethod) => false,
                    Err(e) => return Err(Error::HwiError(e)),
                };
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
                let message = if displayed {
                    "Verify this address matches the one shown on your device"
                } else {
                    "This device cannot display an address on screen; derived locally"
                };
                Ok(json!({
                    "success": true,
                    "index": index,
                    "change": change,
                    "address": address,
                    "displayed_on_device": displayed,
                    "message": message,
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

/// Build the multipath wallet policy async-hwi expects from a wallet's external
/// and (optional) internal single-path public descriptors.
///
/// - Rejects private-key material — a device must only ever see public keys.
/// - Passes an already-multipath descriptor (`/**` or `/<..>/*`) through
///   unchanged.
/// - Combines a standard `/0/*` external and `/1/*` internal pair into a single
///   `/<0;1>/*` multipath descriptor.
/// - With no internal descriptor, returns the external descriptor and warns
///   that only the receive chain is covered.
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
            // `/0/*` and `/1/*` only ever appear as a key's wildcard branch (key
            // origins inside `[..]` are hardened and carry no `*`).
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
