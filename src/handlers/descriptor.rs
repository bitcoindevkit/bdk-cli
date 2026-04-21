use crate::{
    error::BDKCliError as Error,
    utils::{
        descriptors::{
            format_descriptor_output, generate_descriptor_from_mnemonic,
            generate_descriptor_with_mnemonic, generate_descriptors,
        },
        is_mnemonic,
    },
};

#[cfg(feature = "compiler")]
use {
    bdk_wallet::{
        bitcoin::XOnlyPublicKey,
        miniscript::{
            Descriptor, Legacy, Miniscript, Segwitv0, Tap, descriptor::TapTree, policy::Concrete,
        },
    },
    cli_table::{Cell, Style, Table},
    serde_json::json,
    std::{str::FromStr, sync::Arc},
};

use bdk_wallet::bitcoin::Network;

#[cfg(feature = "compiler")]
const NUMS_UNSPENDABLE_KEY_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Handle the top-level `descriptor` command
pub fn handle_descriptor_command(
    network: Network,
    desc_type: String,
    key: Option<String>,
    pretty: bool,
) -> Result<String, Error> {
    let result = match key {
        Some(key) => {
            if is_mnemonic(&key) {
                // User provided mnemonic
                generate_descriptor_from_mnemonic(&key, network, &desc_type)
            } else {
                // User provided xprv/xpub
                generate_descriptors(&desc_type, &key, network)
            }
        }
        // Generate new mnemonic and descriptors
        None => generate_descriptor_with_mnemonic(network, &desc_type),
    }?;
    format_descriptor_output(&result, pretty)
}

/// Handle the miniscript compiler sub-command
///
/// Compiler options are described in [`CliSubCommand::Compile`].
#[cfg(feature = "compiler")]
pub(crate) fn handle_compile_subcommand(
    _network: Network,
    policy: String,
    script_type: String,
    pretty: bool,
) -> Result<String, Error> {
    let policy = Concrete::<String>::from_str(policy.as_str())?;
    let legacy_policy: Miniscript<String, Legacy> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let segwit_policy: Miniscript<String, Segwitv0> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;
    let taproot_policy: Miniscript<String, Tap> = policy
        .compile()
        .map_err(|e| Error::Generic(e.to_string()))?;

    let descriptor = match script_type.as_str() {
        "sh" => Descriptor::new_sh(legacy_policy),
        "wsh" => Descriptor::new_wsh(segwit_policy),
        "sh-wsh" => Descriptor::new_sh_wsh(segwit_policy),
        "tr" => {
            // For tr descriptors, we use a well-known unspendable key (NUMS point).
            // This ensures the key path is effectively disabled and only script path can be used.
            // See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs

            let xonly_public_key = XOnlyPublicKey::from_str(NUMS_UNSPENDABLE_KEY_HEX)
                .map_err(|e| Error::Generic(format!("Invalid NUMS key: {e}")))?;

            let tree = TapTree::Leaf(Arc::new(taproot_policy));
            Descriptor::new_tr(xonly_public_key.to_string(), Some(tree))
        }
        _ => {
            return Err(Error::Generic(
                "Invalid script type. Supported types: sh, wsh, sh-wsh, tr".to_string(),
            ));
        }
    }?;
    if pretty {
        let table = vec![vec![
            "Descriptor".cell().bold(true),
            descriptor.to_string().cell(),
        ]]
        .table()
        .display()
        .map_err(|e| Error::Generic(e.to_string()))?;
        Ok(format!("{table}"))
    } else {
        Ok(serde_json::to_string_pretty(
            &json!({"descriptor": descriptor.to_string()}),
        )?)
    }
}
