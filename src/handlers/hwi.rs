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
use crate::utils::descriptors::{SingleSigScriptType, is_multipath_descriptor, strip_checksum};
use crate::utils::hwi::{HwiWallet, enumerate_hwi_devices, first_hwi_device};

use bdk_wallet::bitcoin::{
    Network, Psbt,
    bip32::{ChildNumber, DerivationPath},
    hex::DisplayHex,
};
use bdk_wallet::miniscript::{Descriptor, DescriptorPublicKey, descriptor::ShInner};

/// Device-only HWI utilities that do not require a wallet.
#[derive(Debug, Parser, Clone, PartialEq, Eq)]
pub struct HwiCommand {
    /// Target a specific connected by master fingerprint.
    #[arg(long, global = true)]
    pub fingerprint: Option<String>,

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
        /// Derivation path. Defaults to the standard path for `--type` and the
        /// current network, e.g. `m/84'/1'/0'`.
        path: Option<String>,

        /// Output descriptor script type. Inferred from the path when omitted.
        #[arg(long = "type", value_enum)]
        script_type: Option<SingleSigScriptType>,
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
        let target_fp = self.fingerprint.as_deref();

        match &self.subcommand {
            HwiSubCommand::Xpub { path, script_type } => {
                let script_type = *script_type;
                // Default to the standard path for the requested (or wpkh) type.
                let path = match path {
                    Some(path) => path.clone(),
                    None => {
                        let coin = if network == Network::Bitcoin { 0 } else { 1 };
                        let purpose = script_type.map_or(84, SingleSigScriptType::purpose);
                        format!("m/{purpose}'/{coin}'/0'")
                    }
                };

                let derivation = DerivationPath::from_str(&path)
                    .map_err(|e| Error::Generic(format!("Invalid derivation path: {e}")))?;
                let device = first_hwi_device(network, &hwi_wallet, target_fp).await?;
                let xpub = device.get_extended_pubkey(&derivation).await?;
                let master_fingerprint = device.get_master_fingerprint().await?.to_string();
                let origin = path.trim_start_matches('m').trim_start_matches('/');
                let key_expression = format!("[{master_fingerprint}/{origin}]{xpub}");

                let mut out = json!({
                    "path": path,
                    "xpub": xpub.to_string(),
                    "master_fingerprint": master_fingerprint,
                    "key_expression": key_expression,
                });

                match script_type.or_else(|| SingleSigScriptType::from_derivation_path(&derivation))
                {
                    Some(stype) => {
                        out["script_type"] = json!(stype.as_str());
                        out["external_descriptor"] = json!(stype.descriptor(&key_expression, 0)?);
                        out["internal_descriptor"] = json!(stype.descriptor(&key_expression, 1)?);
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
                    let (fingerprint, error) = match device.get_master_fingerprint().await {
                        Ok(fp) => (Some(fp.to_string()), None),
                        Err(e) => (None, Some(e.to_string())),
                    };

                    listed.push(json!({
                        "fingerprint": fingerprint,
                        "model": device.device_kind().to_string(),
                        "error": error,
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
    #[arg(env = "HWI_HMAC", long, global = true)]
    pub hmac: Option<String>,
    /// Target a specific connected device by master fingerprint (hex).
    #[arg(long, global = true)]
    pub fingerprint: Option<String>,
    #[command(subcommand)]
    pub subcommand: WalletHwiSubCommand,
}

/// Subcommands for `wallet <name> hwi`.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
#[command(rename_all = "snake")]
pub enum WalletHwiSubCommand {
    /// Register the wallet's policy on the device, returning its HMAC.
    Register,
    /// Display the receive address at an index on the device for verification.
    ///
    /// It derives and shows the address at `--index` but does NOT
    /// advance the wallet's receive index.
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

        let target_fp = self.fingerprint.as_deref();

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
        let policy = build_device_policy(&ext, int.as_deref(), network)?;

        let hwi_wallet = HwiWallet {
            name: Some(wallet_name),
            policy: matches!(kind, WalletKind::Policy).then_some(policy.as_str()),
            hmac: self.hmac.as_deref(),
        };

        match &self.subcommand {
            WalletHwiSubCommand::Register => {
                log::debug!("Registering wallet '{wallet_name}' with policy '{policy}'");
                let device = first_hwi_device(network, &hwi_wallet, target_fp).await?;
                match device.register_wallet(wallet_name, &policy).await {
                    Ok(hmac) => {
                        let hmac = hmac.map(|h| h.to_lower_hex_string());
                        let next_step = hmac.as_ref().map(|h| {
                            format!(
                                "Save this HMAC and pass it to `address`/`sign` with --hmac {h} (or set HWI_HMAC)."
                            )
                        });
                        Ok(json!({ "success": true, "hmac": hmac, "next_step": next_step }))
                    }
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

                let device = first_hwi_device(network, &hwi_wallet, target_fp).await?;
                let (displayed, message) = match script {
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
                    "message": message,
                }))
            }

            WalletHwiSubCommand::Sign { psbt } => {
                let mut psbt = Psbt::from_str(psbt)
                    .map_err(|e| Error::Generic(format!("Failed to parse PSBT: {e}")))?;
                let device = first_hwi_device(network, &hwi_wallet, target_fp).await?;
                device.sign_tx(&mut psbt).await?;
                Ok(json!({ "psbt": psbt.to_string() }))
            }
        }
    }
}

/// How a wallet's descriptor maps onto a hardware device's capabilities.
#[derive(Clone, Copy, PartialEq, Debug, Eq)]
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

/// Build the wallet policy
///
/// - Passes an already-multipath descriptor through unchanged.
/// - Combines a standard external and internal pair into a single
///   `/<0;1>/*` multipath descriptor.
///
/// The result is parsed as a [`DescriptorPublicKey`] descriptor, which rejects
/// any private key.
fn build_device_policy(ext: &str, int: Option<&str>, network: Network) -> Result<String, Error> {
    let ext = strip_checksum(ext).trim();

    let raw = if is_multipath_descriptor(ext, network)? {
        ext.to_string()
    } else {
        match int {
            Some(int) => {
                let int = strip_checksum(int).trim();
                // `/0/*` and `/1/*` only ever appear as a key's wildcard branch.
                if ext.replace("/0/*", "/1/*") != int {
                    return Err(Error::Generic(
                        "Cannot derive a multipath policy: the wallet's external and internal \
                         descriptors are not a standard `/0/*` and `/1/*` pair."
                            .to_string(),
                    ));
                }
                ext.replace("/0/*", "/<0;1>/*")
            }
            None => {
                log::warn!(
                    "Wallet has no separate internal (change) descriptor; the device policy will \
                     only cover receive addresses."
                );
                ext.to_string()
            }
        }
    };

    // Parsing as a public descriptor also rejects any private key.
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&raw).map_err(|e| {
        Error::Generic(format!(
            "Invalid wallet policy (must be a public descriptor): {e}"
        ))
    })?;
    Ok(descriptor.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::CliOpts;
    use bdk_wallet::bitcoin::{Network, bip32::Xpriv};
    use clap::CommandFactory;

    const EXT: &str = "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/0/*)";
    const INT: &str = "wpkh([f5acc2fd/84'/1'/0']tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/1/*)";
    const TPUB: &str = "tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP";

    fn desc(s: &str) -> Descriptor<DescriptorPublicKey> {
        Descriptor::<DescriptorPublicKey>::from_str(s).unwrap()
    }

    #[test]
    fn cli_definition_is_valid() {
        CliOpts::command().debug_assert();
    }

    #[test]
    fn classifies_wallet_kinds() {
        assert_eq!(WalletKind::classify(&desc(EXT)), WalletKind::SingleSig); // wpkh
        assert_eq!(
            WalletKind::classify(&desc(&format!("pkh([f5acc2fd/44'/1'/0']{TPUB}/0/*)"))),
            WalletKind::SingleSig
        );
        assert_eq!(
            WalletKind::classify(&desc(&format!("sh(wpkh([f5acc2fd/49'/1'/0']{TPUB}/0/*))"))),
            WalletKind::SingleSig
        );
        assert_eq!(
            WalletKind::classify(&desc(&format!("tr([f5acc2fd/86'/1'/0']{TPUB}/0/*)"))),
            WalletKind::TaprootSingleSig
        );
        // wsh(...) is neither single-sig nor taproot single-sig.
        assert_eq!(
            WalletKind::classify(&desc(&format!(
                "wsh(multi(1,[f5acc2fd/84'/1'/0']{TPUB}/0/*))"
            ))),
            WalletKind::Policy
        );
    }

    #[test]
    fn taproot_address_path_builds_full_path() {
        let tr = desc(&format!("tr([f5acc2fd/86'/1'/0']{TPUB}/0/*)"));
        assert_eq!(
            taproot_address_path(&tr, 5).unwrap(),
            DerivationPath::from_str("m/86'/1'/0'/0/5").unwrap()
        );
        // A non-taproot descriptor has no on-device taproot path.
        assert!(taproot_address_path(&desc(EXT), 0).is_none());
    }

    #[test]
    fn policy_combines_and_canonicalizes() {
        let policy = build_device_policy(EXT, Some(INT), Network::Testnet).unwrap();
        // Combined into a single multipath descriptor...
        assert!(policy.contains("<0;1>"));
        assert!(!policy.contains("/0/*"));
        assert!(!policy.contains("/1/*"));
        assert!(policy.contains('#'));
    }

    #[test]
    fn policy_rejects_private_keys() {
        let tprv = Xpriv::new_master(Network::Testnet, &[0u8; 32]).unwrap();
        let desc = format!("wpkh({tprv}/0/*)");
        assert!(build_device_policy(&desc, None, Network::Testnet).is_err());
    }

    #[test]
    fn policy_rejects_mismatched_pair() {
        let other = "wpkh([f5acc2fd/84'/1'/0']tpubDDtb2WPYwEWw2WWDV7reLV348iJHw2HmhzvPysKKrJw3hYmvrd4jasyoioVPdKGQqjyaBMEvTn1HvHWDSVqQ6amyyxRZ5YjpPBBGjJ8yu8S/1/*)";
        assert!(build_device_policy(EXT, Some(other), Network::Testnet).is_err());
    }
}
