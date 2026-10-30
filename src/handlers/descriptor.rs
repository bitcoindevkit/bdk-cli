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
    crate::utils::descriptors::{CompileScriptType, compile_policy},
    bdk_wallet::miniscript::descriptor::DescriptorPublicKey,
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
        default_value_t = CompileScriptType::Wsh
    )]
    script_type: CompileScriptType,
    /// Skip key and hash validation, accepting placeholders (e.g. pk(A)). Useful for
    /// inspecting a policy's shape without real keys. Descriptors compiled with this
    /// flag are not usable for spending.
    #[arg(long = "placeholders")]
    placeholders: bool,
}

#[cfg(feature = "compiler")]
impl AppCommand<AppContext<Init>> for CompileCommand {
    type Output = DescriptorResult;

    fn execute(&self, _ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let (descriptor, r) = if self.placeholders {
            compile_policy::<String>(&self.policy, self.script_type)?
        } else {
            compile_policy::<DescriptorPublicKey>(&self.policy, self.script_type)?
        };

        Ok(DescriptorResult {
            descriptor: Some(descriptor),
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
