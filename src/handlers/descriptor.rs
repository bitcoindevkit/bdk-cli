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
use clap::ValueEnum;
#[cfg(feature = "compiler")]
use {
    bdk_wallet::{
        bitcoin::{
            XOnlyPublicKey,
            key::{Parity, rand},
            secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
        },
        miniscript::{
            Descriptor, ForEachKey, FromStrKey, Legacy, MiniscriptKey, ScriptContext, Segwitv0,
            Tap,
            descriptor::{DescriptorPublicKey, TapTree},
            policy::Concrete,
        },
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
    /// Skip key and hash validation, accepting placeholders (e.g. pk(A)). Useful for
    /// inspecting a policy's shape without real keys. Descriptors compiled with this
    /// flag are not usable for spending.
    #[arg(long = "allow-placeholders")]
    allow_placeholders: bool,
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
/// Converts an x-only key into `Self`, so the `tr` branch can build its internal key
/// generically over the policy's key type. `String` can't get a `From<XOnlyPublicKey>`
/// impl here (orphan rules), hence this local trait instead.
trait TrInternalKey: MiniscriptKey {
    fn from_xonly(key: XOnlyPublicKey) -> Self;
}

#[cfg(feature = "compiler")]
impl TrInternalKey for String {
    fn from_xonly(key: XOnlyPublicKey) -> Self {
        key.to_string()
    }
}

#[cfg(feature = "compiler")]
impl TrInternalKey for DescriptorPublicKey {
    fn from_xonly(key: XOnlyPublicKey) -> Self {
        DescriptorPublicKey::from(key)
    }
}

#[cfg(feature = "compiler")]
/// Rejects keys that parse fine on their own but aren't valid for `Ctx` (e.g. an
/// x-only key under `Segwitv0`), which miniscript's compiler otherwise turns into
/// a panic instead of an error. A no-op for `Pk = String`, since `String` never
/// reports itself as uncompressed or x-only.
fn check_policy_keys<Pk: MiniscriptKey, Ctx: ScriptContext>(
    policy: &Concrete<Pk>,
) -> Result<(), Error> {
    let mut key_error = None;
    policy.for_each_key(|pk| match Ctx::check_pk(pk) {
        Ok(()) => true,
        Err(e) => {
            key_error = Some(e);
            false
        }
    });

    match key_error {
        Some(e) => Err(Error::Generic(format!("Invalid policy: {e}"))),
        None => Ok(()),
    }
}

#[cfg(feature = "compiler")]
/// Parses `policy_str` as `Pk` and compiles it for `script_type`. Returns the
/// descriptor string and, for `tr`, the random tweak `r` used to derive the
/// unspendable internal key so the caller can verify it.
fn compile_policy<Pk: FromStrKey + TrInternalKey>(
    policy_str: &str,
    script_type: ScriptType,
) -> Result<(String, Option<String>), Error> {
    let policy: Concrete<Pk> = Concrete::from_str(policy_str)
        .map_err(|e| Error::Generic(format!("Invalid policy: {e}")))?;

    let mut r = None;

    // Compile per branch, not once up front: the contexts have different script
    // limits, and the narrowest one would reject policies valid for the requested type.
    let descriptor = match script_type {
        ScriptType::Sh => {
            check_policy_keys::<Pk, Legacy>(&policy)?;
            Descriptor::new_sh(policy.compile()?)
        }
        ScriptType::Wsh => {
            check_policy_keys::<Pk, Segwitv0>(&policy)?;
            Descriptor::new_wsh(policy.compile()?)
        }
        ScriptType::ShWsh => {
            check_policy_keys::<Pk, Segwitv0>(&policy)?;
            Descriptor::new_sh_wsh(policy.compile()?)
        }
        ScriptType::Tr => {
            check_policy_keys::<Pk, Tap>(&policy)?;
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

            let internal_key_point = nums_point
                .add_exp_tweak(&secp, &Scalar::from(r_secret))
                .map_err(|e| Error::Generic(format!("Failed to tweak NUMS key: {e}")))?;
            let (xonly_internal_key, _) = internal_key_point.x_only_public_key();

            let tree = TapTree::Leaf(Arc::new(policy.compile()?));
            Descriptor::new_tr(Pk::from_xonly(xonly_internal_key), Some(tree))
        }
    }?;

    Ok((descriptor.to_string(), r))
}

#[cfg(feature = "compiler")]
impl AppCommand<AppContext<Init>> for CompileCommand {
    type Output = DescriptorResult;

    fn execute(&self, _ctx: &mut AppContext<Init>) -> Result<Self::Output, Error> {
        let (descriptor, r) = if self.allow_placeholders {
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
