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
    crate::utils::taproot::generate_unspendable_internal_key,
    bdk_wallet::miniscript::{Descriptor, descriptor::TapTree, policy::Concrete},
    clap::ValueEnum,
    std::{str::FromStr, sync::Arc},
};

#[cfg(feature = "silent-payments")]
use crate::utils::types::StatusResult;

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
                    generate_descriptor_from_mnemonic(key, ctx.network.into(), &self.desc_type)
                } else {
                    generate_descriptors(&self.desc_type, key, ctx.network.into())
                }
            }
            None => generate_descriptor_with_mnemonic(ctx.network.into(), &self.desc_type),
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
    #[arg(
        env = "TYPE",
        short = 't',
        long = "type",
        value_enum,
        default_value_t = ScriptType::Wsh
    )]
    script_type: ScriptType,
}

/// Script types the compiled policy can be embedded in.
#[cfg(feature = "compiler")]
#[derive(Clone, Copy, ValueEnum, Debug, Eq, PartialEq)]
pub enum ScriptType {
    Sh,
    Wsh,
    ShWsh,
    Tr,
}

#[cfg(feature = "compiler")]
impl AppCommand<AppContext<Init>> for CompileCommand {
    type Output = DescriptorResult;

    fn execute(&self, _ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let policy: Concrete<String> = Concrete::from_str(&self.policy)
            .map_err(|e| Error::Generic(format!("Invalid policy: {e}")))?;

        let mut r = None;

        // Compile per branch, not once up front: the contexts have different script
        // limits, and the narrowest one would reject policies valid for the requested type.
        let descriptor = match self.script_type {
            ScriptType::Sh => Descriptor::new_sh(policy.compile()?),
            ScriptType::Wsh => Descriptor::new_wsh(policy.compile()?),
            ScriptType::ShWsh => Descriptor::new_sh_wsh(policy.compile()?),
            ScriptType::Tr => {
                let (internal_key, r_secret) = generate_unspendable_internal_key()?;
                r = Some(r_secret.display_secret().to_string());
                let tree = TapTree::Leaf(Arc::new(policy.compile()?));
                Descriptor::new_tr(internal_key.to_string(), Some(tree))
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
