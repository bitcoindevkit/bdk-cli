//! Hardware wallet (HWI) command handlers.
//!
//! Provides the `hwi` top-level command with subcommands to list connected
//! devices, register a wallet policy, display a receive address on the device
//! and sign a PSBT. Device discovery lives in [`crate::utils::hwi`].

use async_hwi::AddressScript;
use bdk_wallet::bitcoin::{Psbt, hex::DisplayHex};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::str::FromStr;

use crate::error::BDKCliError as Error;
use crate::handlers::{AppContext, AsyncAppCommand, Init};
use crate::utils::hwi::{HwiWallet, enumerate_hwi_devices, first_hwi_device};

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

impl HwiOpts {
    fn as_wallet(&self) -> HwiWallet<'_> {
        HwiWallet {
            name: self.wallet.as_deref(),
            policy: self.ext_descriptor.as_deref(),
            hmac: self.hmac.as_deref(),
        }
    }
}

/// HWI subcommands.
#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
#[command(rename_all = "snake")]
pub enum HwiSubCommand {
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

impl AsyncAppCommand<AppContext<Init>> for HwiCommand {
    type Output = serde_json::Value;

    async fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let network = ctx.network;
        let wallet = self.opts.as_wallet();

        match &self.subcommand {
            HwiSubCommand::Devices => {
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
                let name = self.opts.wallet.as_deref().ok_or_else(|| {
                    Error::Generic("Wallet name (--wallet) is required to register".to_string())
                })?;
                let policy = self.opts.ext_descriptor.as_deref().ok_or_else(|| {
                    Error::Generic(
                        "External descriptor (--ext-descriptor) is required to register"
                            .to_string(),
                    )
                })?;
                let device = first_hwi_device(network, &wallet).await?;
                tracing::debug!("Registering wallet '{name}' with policy '{policy}'");
                let hmac = device.register_wallet(name, policy).await?;
                let hmac_hex = hmac.map(|h| h.to_lower_hex_string());
                Ok(json!({ "success": true, "hmac": hmac_hex }))
            }

            HwiSubCommand::Address { index, change } => {
                let device = first_hwi_device(network, &wallet).await?;
                let script = AddressScript::Miniscript {
                    index: *index,
                    change: *change,
                };
                device.display_address(&script).await?;
                Ok(json!({
                    "success": true,
                    "index": index,
                    "change": change,
                    "message": "Address displayed on device for verification",
                }))
            }

            HwiSubCommand::Sign { psbt } => {
                let mut psbt = Psbt::from_str(psbt)
                    .map_err(|e| Error::Generic(format!("Failed to parse PSBT: {e}")))?;
                let device = first_hwi_device(network, &wallet).await?;
                device.sign_tx(&mut psbt).await?;
                Ok(json!({ "psbt": psbt.to_string() }))
            }
        }
    }
}
