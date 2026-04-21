use crate::commands::KeySubCommand;
use crate::error::BDKCliError as Error;
use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::bip32::KeySource;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Network, bip32::DerivationPath};
use bdk_wallet::keys::bip39::WordCount;
use bdk_wallet::keys::{DerivableKey, GeneratableKey};
use bdk_wallet::keys::{DescriptorKey, DescriptorKey::Secret, ExtendedKey, GeneratedKey};
use bdk_wallet::miniscript::{self, Segwitv0};
use cli_table::{Cell, Style, Table};
use serde_json::json;

/// Handle a key sub-command
///
/// Key sub-commands are described in [`KeySubCommand`].
pub(crate) fn handle_key_subcommand(
    network: Network,
    subcommand: KeySubCommand,
    pretty: bool,
) -> Result<String, Error> {
    let secp = Secp256k1::new();

    match subcommand {
        KeySubCommand::Generate {
            word_count,
            password,
        } => {
            let mnemonic_type = match word_count {
                12 => WordCount::Words12,
                _ => WordCount::Words24,
            };
            let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
                Mnemonic::generate((mnemonic_type, Language::English))
                    .map_err(|_| Error::Generic("Mnemonic generation error".to_string()))?;
            let mnemonic = mnemonic.into_key();
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);
            let phrase = mnemonic
                .words()
                .fold("".to_string(), |phrase, w| phrase + w + " ")
                .trim()
                .to_string();
            if pretty {
                let table = vec![
                    vec![
                        "Fingerprint".cell().bold(true),
                        fingerprint.to_string().cell(),
                    ],
                    vec!["Mnemonic".cell().bold(true), mnemonic.to_string().cell()],
                    vec!["Xprv".cell().bold(true), xprv.to_string().cell()],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({ "mnemonic": phrase, "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
                )?)
            }
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);
            if pretty {
                let table = vec![
                    vec![
                        "Fingerprint".cell().bold(true),
                        fingerprint.to_string().cell(),
                    ],
                    vec!["Mnemonic".cell().bold(true), mnemonic.to_string().cell()],
                    vec!["Xprv".cell().bold(true), xprv.to_string().cell()],
                ]
                .table()
                .display()
                .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(format!("{table}"))
            } else {
                Ok(serde_json::to_string_pretty(
                    &json!({ "xprv": xprv.to_string(), "fingerprint": fingerprint.to_string() }),
                )?)
            }
        }
        KeySubCommand::Derive { xprv, path } => {
            if xprv.network != network.into() {
                return Err(Error::Generic("Invalid network".to_string()));
            }
            let derived_xprv = &xprv.derive_priv(&secp, &path)?;

            let origin: KeySource = (xprv.fingerprint(&secp), path);

            let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
                derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;

            if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
                let desc_pubkey = desc_seckey.to_public(&secp)?;
                if pretty {
                    let table = vec![
                        vec!["Xpub".cell().bold(true), desc_pubkey.to_string().cell()],
                        vec!["Xprv".cell().bold(true), xprv.to_string().cell()],
                    ]
                    .table()
                    .display()
                    .map_err(|e| Error::Generic(e.to_string()))?;
                    Ok(format!("{table}"))
                } else {
                    Ok(serde_json::to_string_pretty(
                        &json!({"xpub": desc_pubkey.to_string(), "xprv": desc_seckey.to_string()}),
                    )?)
                }
            } else {
                Err(Error::Generic("Invalid key variant".to_string()))
            }
        }
    }
}
