use crate::handlers::Init;
use crate::utils::types::DescriptorResult;
use crate::{
    error::BDKCliError as Error,
    handlers::{AppCommand, AppContext},
    utils::{
        descriptors::{
            generate_descriptor_from_mnemonic, generate_descriptor_with_mnemonic,
            generate_descriptors,
        },
        is_mnemonic,
    },
};
use clap::Parser;
#[cfg(feature = "compiler")]
use {
    bdk_wallet::{
        bitcoin::{
            XOnlyPublicKey,
            key::{Parity, rand},
            secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
        },
        miniscript::{Descriptor, Miniscript, descriptor::TapTree, policy::Concrete},
    },
    std::{str::FromStr, sync::Arc},
};

#[cfg(feature = "silent-payments")]
use crate::utils::types::StatusResult;

#[cfg(feature = "compiler")]
const NUMS_UNSPENDABLE_KEY_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

#[derive(Parser, Debug, Clone, PartialEq)]
pub struct DescriptorCommand {
    /// Descriptor type (script type)
    #[arg(
            long = "type",
            short = 't',
            value_parser = ["pkh", "wpkh", "sh", "wsh", "tr"],
            default_value = "wsh"
        )]
    pub(crate) desc_type: String,

    /// Optional key: xprv, xpub, or mnemonic phrase
    key: Option<String>,
}
impl AppCommand<AppContext<Init>> for DescriptorCommand {
    type Output = DescriptorResult;

    fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        match &self.key {
            Some(key) => {
                if is_mnemonic(key) {
                    generate_descriptor_from_mnemonic(key, ctx.network, &self.desc_type)
                } else {
                    generate_descriptors(&self.desc_type, key, ctx.network)
                }
            }
            None => generate_descriptor_with_mnemonic(ctx.network, &self.desc_type),
        }
    }
}

#[cfg(feature = "compiler")]
#[derive(Parser, Debug, Clone, PartialEq)]
pub struct CompileCommand {
    /// Sets the spending policy to compile.
    #[arg(env = "POLICY", required = true, index = 1)]
    policy: String,
    /// Sets the script type used to embed the compiled policy.
    #[arg(env = "TYPE", short = 't', long = "type", default_value = "wsh", value_parser = ["sh","wsh", "sh-wsh", "tr"]
        )]
    script_type: String,
}

#[cfg(feature = "compiler")]
impl AppCommand<AppContext<Init>> for CompileCommand {
    type Output = DescriptorResult;

    fn execute(&self, _ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let policy: Concrete<String> = Concrete::from_str(&self.policy)
            .map_err(|e| Error::Generic(format!("Invalid policy: {e}")))?;

        let legacy_policy: Miniscript<String, bdk_wallet::miniscript::Legacy> = policy
            .compile()
            .map_err(|e| Error::Generic(e.to_string()))?;
        let segwit_policy: Miniscript<String, bdk_wallet::miniscript::Segwitv0> = policy
            .compile()
            .map_err(|e| Error::Generic(e.to_string()))?;
        let taproot_policy: Miniscript<String, bdk_wallet::miniscript::Tap> = policy
            .compile()
            .map_err(|e| Error::Generic(e.to_string()))?;

        let mut r = None;

        let descriptor = match self.script_type.as_str() {
            "sh" => Descriptor::new_sh(legacy_policy),
            "wsh" => Descriptor::new_wsh(segwit_policy),
            "sh-wsh" => Descriptor::new_sh_wsh(segwit_policy),
            "tr" => {
                // Use a randomized unspendable internal key (H + rG) instead of a fixed NUMS
                // point. This improves privacy by preventing observers from determining whether
                // key-path spending is disabled. `r` is returned so the user can verify the key
                // is derived from the NUMS point. See BIP-341.
                let secp = Secp256k1::new();
                let r_secret = SecretKey::new(&mut rand::thread_rng());
                r = Some(r_secret.display_secret().to_string());

                let nums_key = XOnlyPublicKey::from_str(NUMS_UNSPENDABLE_KEY_HEX)
                    .map_err(|e| Error::Generic(format!("Invalid NUMS key: {e}")))?;
                let nums_point = PublicKey::from_x_only_public_key(nums_key, Parity::Even);

                let internal_key_point =
                    nums_point
                        .add_exp_tweak(&secp, &Scalar::from(r_secret))
                        .map_err(|e| Error::Generic(format!("Failed to tweak NUMS key: {e}")))?;
                let (xonly_internal_key, _) = internal_key_point.x_only_public_key();

                let tree = TapTree::Leaf(Arc::new(taproot_policy));
                Descriptor::new_tr(xonly_internal_key.to_string(), Some(tree))
            }
            _ => {
                return Err(Error::Generic(
                    "Invalid script type. Supported: sh, wsh, sh-wsh, tr".into(),
                ));
            }
        }?;

        Ok(DescriptorResult {
            descriptor: Some(descriptor.to_string()),
            mnemonic: None,
            multipath_descriptor: None,
            public_descriptors: None,
            private_descriptors: None,
            fingerprint: None,
            r,
        })
    }
}

#[cfg(feature = "silent-payments")]
#[derive(Parser, Debug, Clone, PartialEq)]
pub struct SilentPaymentCodeCommand {
    /// The scan public key to use on the silent payment code.
    #[arg(long = "scan_key")]
    scan: bdk_sp::bitcoin::secp256k1::PublicKey,
    /// The spend public key to use on the silent payment code.
    #[arg(long = "spend_key")]
    spend: bdk_sp::bitcoin::secp256k1::PublicKey,
}

#[cfg(feature = "silent-payments")]
impl AppCommand<AppContext<Init>> for SilentPaymentCodeCommand {
    type Output = StatusResult;

    fn execute(&self, ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let sp_code =
            bdk_sp::encoding::SilentPaymentCode::new_v0(self.scan, self.spend, ctx.network);

        Ok(StatusResult {
            message: sp_code.to_string(),
        })
    }
}
