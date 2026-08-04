//! Hardware wallet (HWI) command handlers.
//!
//! Provides the `hwi` top-level command with subcommands to list connected
//! devices, register a wallet policy, display a receive address on the device
//! and sign a PSBT. Device discovery lives in [`crate::utils::hwi`].

use crate::commands::WalletOpts;
use crate::error::BDKCliError as Error;
use crate::handlers::{AppContext, AsyncAppCommand, Init};
use crate::persister::new_wallet;
use crate::utils::hwi::{HwiWallet, enumerate_hwi_devices, first_hwi_device};
use crate::utils::load_wallet_config;
use async_hwi::AddressScript;
use bdk_wallet::bitcoin::{Psbt, bip32::DerivationPath, hex::DisplayHex};
use bdk_wallet::{KeychainKind, Wallet};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::path::Path;
use std::str::FromStr;

/// Options shared by all HWI subcommands.
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct HwiOpts {
    /// Wallet name registered on the device (required by Ledger and Coldcard).
    #[arg(env = "WALLET_NAME", short = 'w', long)]
    pub wallet: Option<String>,

    /// External descriptor / wallet policy to register or operate on.
    #[arg(env = "EXT_DESCRIPTOR", short = 'e', long)]
    pub ext_descriptor: Option<String>,

    /// Registration HMAC returned by `hwi register` (required to reuse a
    /// registered policy on a Ledger).
    #[arg(env = "HWI_HMAC", long)]
    pub hmac: Option<String>,
}

/// HWI subcommands.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
#[command(rename_all = "snake")]
pub enum HwiSubCommand {
    /// Read an extended public key from the device at a derivation path.
    ///
    /// Use this first to obtain the key material needed to build a wallet
    /// descriptor for the device.
    Xpub {
        /// Derivation path, e.g. `m/84'/1'/0'`.
        #[arg(default_value = "m/84'/1'/0'")]
        path: String,
    },
    /// List all connected hardware wallet devices.
    Devices,
    /// Register a wallet policy on the device, returning its HMAC.
    Register,
    /// Display a receive address on the device for verification.
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

/// The `hwi` top-level command.
#[derive(Debug, Parser, Clone, PartialEq, Eq)]
pub struct HwiCommand {
    #[command(flatten)]
    pub opts: HwiOpts,
    #[command(subcommand)]
    pub subcommand: HwiSubCommand,
}

impl HwiCommand {
    /// Load the saved wallet config when a descriptor is needed. Errors if `--wallet`
    ///  is set but its config cannot be read.
    fn load_wallet_opts(&self, datadir: &Path) -> Result<Option<WalletOpts>, Error> {
        if self.opts.ext_descriptor.is_some() {
            return Ok(None);
        }
        match &self.opts.wallet {
            Some(name) => load_wallet_config(datadir, name).map(|(opts, _network)| Some(opts)),
            None => Ok(None),
        }
    }

    /// Build the device wallet context, preferring an explicit `--ext-descriptor`
    /// and falling back to the loaded config's external descriptor.
    fn hwi_wallet<'a>(&'a self, opts: Option<&'a WalletOpts>) -> HwiWallet<'a> {
        let policy = self
            .opts
            .ext_descriptor
            .as_deref()
            .or_else(|| opts.map(|o| o.ext_descriptor.as_str()));
        HwiWallet {
            name: self.opts.wallet.as_deref(),
            policy,
            hmac: self.opts.hmac.as_deref(),
        }
    }

    /// Derive the address at `index` for the given keychain, from the saved
    /// config when available or from an explicit external descriptor otherwise.
    fn derive_address(
        &self,
        network: bdk_wallet::bitcoin::Network,
        opts: Option<&WalletOpts>,
        index: u32,
        change: bool,
    ) -> Result<Option<String>, Error> {
        let keychain = if change {
            KeychainKind::Internal
        } else {
            KeychainKind::External
        };

        let wallet = if let Some(opts) = opts {
            Some(new_wallet(network, opts)?)
        } else if let Some(desc) = self.opts.ext_descriptor.as_deref() {
            Some(
                Wallet::create_single(desc.to_string())
                    .network(network)
                    .create_wallet_no_persist()?,
            )
        } else {
            None
        };

        Ok(wallet.map(|w| w.peek_address(keychain, index).address.to_string()))
    }
}

impl AsyncAppCommand<AppContext<Init>> for HwiCommand {
    type Output = serde_json::Value;

    async fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let network = ctx.network;

        match &self.subcommand {
            HwiSubCommand::Xpub { path } => {
                let derivation = DerivationPath::from_str(path)
                    .map_err(|e| Error::Generic(format!("Invalid derivation path: {e}")))?;
                let wallet = self.hwi_wallet(None);
                let device = first_hwi_device(network, &wallet).await?;
                let xpub = device.get_extended_pubkey(&derivation).await?;
                let fingerprint = device.get_master_fingerprint().await?.to_string();
                Ok(json!({
                    "path": path,
                    "xpub": xpub.to_string(),
                    "master_fingerprint": fingerprint,
                }))
            }

            HwiSubCommand::Devices => {
                let wallet = self.hwi_wallet(None);
                let devices = enumerate_hwi_devices(network, &wallet).await?;
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

            HwiSubCommand::Register => {
                let opts = self.load_wallet_opts(&ctx.datadir)?;
                let wallet = self.hwi_wallet(opts.as_ref());
                let name = wallet.name.ok_or_else(|| {
                    Error::Generic("Wallet name is required to register".to_string())
                })?;
                let policy = wallet.policy.ok_or_else(|| {
                    Error::Generic(
                        "No descriptor found: pass --ext-descriptor or save a wallet config for --wallet"
                            .to_string(),
                    )
                })?;
                tracing::debug!("Registering wallet '{name}' with policy '{policy}'");
                // let device = first_hwi_device(network, &wallet).await?;
                let hmac = device_register(network, &wallet, name, policy).await?;

                // let hmac_hex = hmac.map(|h| h.to_lower_hex_string());
                Ok(json!({ "success": true, "hmac": hmac }))
            }

            HwiSubCommand::Address { index, change } => {
                let opts = self.load_wallet_opts(&ctx.datadir)?;
                let wallet = self.hwi_wallet(opts.as_ref());
                let device = first_hwi_device(network, &wallet).await?;
                let script = AddressScript::Miniscript {
                    index: *index,
                    change: *change,
                };
                device.display_address(&script).await?;
                let address = self.derive_address(network, opts.as_ref(), *index, *change)?;
                Ok(json!({
                    "success": true,
                    "index": index,
                    "change": change,
                    "address": address,
                    "message": "Verify this address matches the one shown on your device",
                }))
            }

            HwiSubCommand::Sign { psbt } => {
                let mut psbt = Psbt::from_str(psbt)
                    .map_err(|e| Error::Generic(format!("Failed to parse PSBT: {e}")))?;
                let opts = self.load_wallet_opts(&ctx.datadir)?;
                let wallet = self.hwi_wallet(opts.as_ref());
                let device = first_hwi_device(network, &wallet).await?;
                device.sign_tx(&mut psbt).await?;
                Ok(json!({ "psbt": psbt.to_string() }))
            }
        }
    }
}

/// Register a policy on the first connected device and return its HMAC (hex).
async fn device_register(
    network: bdk_wallet::bitcoin::Network,
    wallet: &HwiWallet<'_>,
    name: &str,
    policy: &str,
) -> Result<Option<String>, Error> {
    let device = first_hwi_device(network, wallet).await?;
    let hmac = device.register_wallet(name, policy).await?;
    Ok(hmac.map(|h| h.to_lower_hex_string()))
}
