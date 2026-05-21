use crate::commands::KeySubCommand;
use crate::error::BDKCliError as Error;
use crate::handlers::{AppCommand, AppContext};
use crate::utils::output::FormatOutput;
use crate::utils::types::KeyResult;
use bdk_wallet::bip39::{Language, Mnemonic};
use bdk_wallet::bitcoin::bip32::DerivationPath;
use bdk_wallet::bitcoin::bip32::KeySource;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::keys::bip39::WordCount;
use bdk_wallet::keys::{DerivableKey, GeneratableKey};
use bdk_wallet::keys::{DescriptorKey, ExtendedKey, GeneratedKey};
use bdk_wallet::miniscript::{self, Segwitv0};
use clap::Parser;



impl KeySubCommand {
    pub fn execute(&self, ctx: &mut AppContext) -> Result<(), Error> {
        match self {
            KeySubCommand::Generate(generate_key_command) => {
                generate_key_command.execute(ctx)?.print()
            }
            KeySubCommand::Restore(restore_key_command) => {
                restore_key_command.execute(ctx)?.print()
            }
            KeySubCommand::Derive(derive_key_command) => derive_key_command.execute(ctx)?.print(),
        }
    }
}
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct GenerateKeyCommand {
    /// Entropy level based on number of random seed mnemonic words.
    #[arg(
        env = "WORD_COUNT",
        short = 'e',
        long = "entropy",
        default_value = "12"
    )]
    word_count: usize,
    /// Seed password.
    #[arg(env = "PASSWORD", short = 'p', long = "password")]
    password: Option<String>,
}

impl AppCommand for GenerateKeyCommand {
    type Output = KeyResult;

    fn execute(&self, ctx: &mut AppContext) -> Result<Self::Output, Error> {
        let secp = Secp256k1::new();
        let mnemonic_type = match self.word_count {
            12 => WordCount::Words12,
            _ => WordCount::Words24,
        };

        let mnemonic: GeneratedKey<_, miniscript::BareCtx> =
            Mnemonic::generate((mnemonic_type, Language::English))
                .map_err(|_| Error::Generic("Mnemonic generation error".to_string()))?;
        let mnemonic = mnemonic.into_key();
        let xkey: ExtendedKey = (mnemonic.clone(), self.password.clone()).into_extended_key()?;
        let xprv = xkey.into_xprv(ctx.network).ok_or_else(|| {
            Error::Generic("Privatekey info not found (should not happen)".to_string())
        })?;
        let fingerprint = xprv.fingerprint(&secp);
        let phrase = mnemonic
            .words()
            .fold("".to_string(), |phrase, w| phrase + w + " ")
            .trim()
            .to_string();

        Ok(KeyResult {
            xprv: xprv.to_string(),
            mnemonic: Some(phrase),
            fingerprint: Some(fingerprint.to_string()),
            xpub: None,
        })
    }
}

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct DeriveKeyCommand {
    /// Extended private key to derive from.
    #[arg(env = "XPRV", short = 'x', long = "xprv")]
    xprv: Xpriv,
    /// Path to use to derive extended public key from extended private key.
    #[arg(env = "DERIVATION_PATH", short = 'p', long = "derivation_path")]
    path: DerivationPath,
}

impl AppCommand for DeriveKeyCommand {
    type Output = KeyResult;

    fn execute(&self, ctx: &mut AppContext) -> Result<Self::Output, Error> {
        let secp = Secp256k1::new();

        let derived_xprv = &self.xprv.derive_priv(&secp, &self.path)?;

        let origin: KeySource = (self.xprv.fingerprint(&secp), self.path.clone());

        if self.xprv.network != ctx.network.into() {
            return Err(Error::Generic(
                "Extended key network does not match current network".to_string(),
            ));
        }

        let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
            derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;

        if let DescriptorKey::Secret(desc_seckey, _, _) = derived_xprv_desc_key {
            let desc_pubkey = desc_seckey.to_public(&secp)?;

            Ok(KeyResult {
                xprv: desc_seckey.to_string(),
                xpub: Some(desc_pubkey.to_string()),
                mnemonic: None,
                fingerprint: None,
            })
        } else {
            Err(Error::Generic(
                "Derived key is not a secret key".to_string(),
            ))
        }
    }
}

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
pub struct RestoreKeyCommand {
    /// Seed mnemonic words, must be quoted (eg. "word1 word2 ...").
    #[arg(env = "MNEMONIC", short = 'm', long = "mnemonic")]
    mnemonic: String,
    /// Seed password.
    #[arg(env = "PASSWORD", short = 'p', long = "password")]
    password: Option<String>,
}

impl AppCommand for RestoreKeyCommand {
    type Output = KeyResult;

    fn execute(&self, ctx: &mut AppContext) -> Result<Self::Output, Error> {
        let secp = Secp256k1::new();

        let mnemonic = Mnemonic::parse_in(Language::English, &self.mnemonic)?;
        let xkey: ExtendedKey = (mnemonic.clone(), &self.password).0.into_extended_key()?;
        let xprv = xkey.into_xprv(ctx.network).ok_or_else(|| {
            Error::Generic("Privatekey info not found (should not happen)".to_string())
        })?;
        let fingerprint = xprv.fingerprint(&secp);

        Ok(KeyResult {
            xprv: xprv.to_string(),
            mnemonic: Some(mnemonic.to_string()),
            fingerprint: Some(fingerprint.to_string()),
            xpub: None,
        })
    }
}
