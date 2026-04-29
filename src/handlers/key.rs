use crate::commands::KeySubCommand;
use crate::error::BDKCliError as Error;
use crate::handlers::types::KeyResult;
use crate::utils::output::FormatOutput;
use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::bip32::KeySource;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Network, bip32::DerivationPath};
use bdk_wallet::keys::bip39::WordCount;
use bdk_wallet::keys::{DerivableKey, GeneratableKey};
use bdk_wallet::keys::{DescriptorKey, DescriptorKey::Secret, ExtendedKey, GeneratedKey};
use bdk_wallet::miniscript::{self, Segwitv0};

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

            let result = KeyResult {
                xprv: xprv.to_string(),
                mnemonic: Some(phrase),
                fingerprint: Some(fingerprint.to_string()),
                xpub: None,
            };

            result.format(pretty)
        }
        KeySubCommand::Restore { mnemonic, password } => {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
            let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
            let xprv = xkey.into_xprv(network).ok_or_else(|| {
                Error::Generic("Privatekey info not found (should not happen)".to_string())
            })?;
            let fingerprint = xprv.fingerprint(&secp);

            let result = KeyResult {
                xprv: xprv.to_string(),
                mnemonic: Some(mnemonic.to_string()),
                fingerprint: Some(fingerprint.to_string()),
                xpub: None,
            };
            result.format(pretty)
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

                let result = KeyResult {
                    xprv: desc_seckey.to_string(),
                    xpub: Some(desc_pubkey.to_string()),
                    mnemonic: None,
                    fingerprint: None,
                };
                result.format(pretty)
            } else {
                Err(Error::Generic(
                    "Derived key is not a secret key".to_string(),
                ))
            }
        }
    }
}
