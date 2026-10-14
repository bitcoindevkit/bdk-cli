use bdk_wallet::bitcoin::Network;
#[cfg(feature = "hwi")]
use bdk_wallet::bitcoin::bip32::ChildNumber;
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::keys::GeneratableKey;
#[cfg(feature = "hwi")]
use clap::ValueEnum;
use std::{str::FromStr, sync::Arc};

use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::{
    KeychainKind,
    bip39::{Language, Mnemonic},
    bitcoin::{
        NetworkKind,
        bip32::{DerivationPath, Xpriv, Xpub},
        secp256k1::Secp256k1,
    },
    keys::{GeneratedKey, bip39::WordCount},
    miniscript::{
        Descriptor, Miniscript, Segwitv0, Terminal,
        descriptor::{DescriptorXKey, Wildcard},
    },
    template::DescriptorTemplate,
};

use crate::error::BDKCliError as Error;
use crate::utils::types::DescriptorResult;
use crate::utils::types::KeychainPair;

pub fn generate_descriptors(
    desc_type: &str,
    key: &str,
    network: NetworkKind,
) -> Result<DescriptorResult, Error> {
    let is_private = key.starts_with("xprv") || key.starts_with("tprv");

    if is_private {
        generate_private_descriptors(desc_type, key, network)
    } else {
        let purpose = match desc_type.to_lowercase().as_str() {
            "pkh" => 44u32,
            "sh" => 49u32,
            "wpkh" | "wsh" => 84u32,
            "tr" => 86u32,
            _ => 84u32,
        };
        let coin_type = match network {
            NetworkKind::Main => 0u32,
            _ => 1u32,
        };
        let derivation_path = DerivationPath::from_str(&format!("m/{purpose}h/{coin_type}h/0h"))?;
        generate_public_descriptors(desc_type, key, &derivation_path)
    }
}

/// Generate descriptors from private key using BIP templates
fn generate_private_descriptors(
    desc_type: &str,
    key: &str,
    network: NetworkKind,
) -> Result<DescriptorResult, Error> {
    use bdk_wallet::template::{Bip44, Bip49, Bip84, Bip86};

    let secp = Secp256k1::new();
    let xprv: Xpriv = key.parse()?;
    let fingerprint = xprv.fingerprint(&secp);

    let (external_desc, external_keymap, _) = match desc_type.to_lowercase().as_str() {
        "pkh" => Bip44(xprv, KeychainKind::External).build(network)?,
        "sh" => Bip49(xprv, KeychainKind::External).build(network)?,
        "wpkh" | "wsh" => Bip84(xprv, KeychainKind::External).build(network)?,
        "tr" => Bip86(xprv, KeychainKind::External).build(network)?,
        _ => {
            return Err(Error::Generic(format!(
                "Unsupported descriptor type: {desc_type}"
            )));
        }
    };

    let (internal_desc, internal_keymap, _) = match desc_type.to_lowercase().as_str() {
        "pkh" => Bip44(xprv, KeychainKind::Internal).build(network)?,
        "sh" => Bip49(xprv, KeychainKind::Internal).build(network)?,
        "wpkh" | "wsh" => Bip84(xprv, KeychainKind::Internal).build(network)?,
        "tr" => Bip86(xprv, KeychainKind::Internal).build(network)?,
        _ => {
            return Err(Error::Generic(format!(
                "Unsupported descriptor type: {desc_type}"
            )));
        }
    };

    let external_priv = external_desc.to_string_with_secret(&external_keymap);
    let external_pub = external_desc.to_string();
    let internal_priv = internal_desc.to_string_with_secret(&internal_keymap);
    let internal_pub = internal_desc.to_string();

    Ok(DescriptorResult {
        descriptor: None,
        multipath_descriptor: None,
        public_descriptors: Some(KeychainPair {
            external: external_pub,
            internal: internal_pub,
        }),
        private_descriptors: Some(KeychainPair {
            external: external_priv,
            internal: internal_priv,
        }),
        mnemonic: None,
        fingerprint: Some(fingerprint.to_string()),
        r: None,
    })
}

/// Generate descriptors from public key (xpub/tpub)
pub fn generate_public_descriptors(
    desc_type: &str,
    key: &str,
    derivation_path: &DerivationPath,
) -> Result<DescriptorResult, Error> {
    let xpub: Xpub = key.parse()?;
    let fingerprint = xpub.fingerprint();

    let build_descriptor = |branch: &str| -> Result<String, Error> {
        let branch_path = DerivationPath::from_str(branch)?;
        let desc_xpub = DescriptorXKey {
            origin: Some((fingerprint, derivation_path.clone())),
            xkey: xpub,
            derivation_path: branch_path,
            wildcard: Wildcard::Unhardened,
        };
        let desc_pub = DescriptorPublicKey::XPub(desc_xpub);
        let descriptor = build_public_descriptor(desc_type, desc_pub)?;
        Ok(descriptor.to_string())
    };

    let external_pub = build_descriptor("0")?;
    let internal_pub = build_descriptor("1")?;
    Ok(DescriptorResult {
        descriptor: None,
        multipath_descriptor: None,
        public_descriptors: Some(KeychainPair {
            external: external_pub,
            internal: internal_pub,
        }),
        private_descriptors: None,
        mnemonic: None,
        fingerprint: Some(fingerprint.to_string()),
        r: None,
    })
}

/// Build a descriptor from a public key
pub fn build_public_descriptor(
    desc_type: &str,
    key: DescriptorPublicKey,
) -> Result<Descriptor<DescriptorPublicKey>, Error> {
    match desc_type.to_lowercase().as_str() {
        "pkh" => Descriptor::new_pkh(key).map_err(Error::from),
        "wpkh" => Descriptor::new_wpkh(key).map_err(Error::from),
        "sh" => Descriptor::new_sh_wpkh(key).map_err(Error::from),
        "wsh" => {
            let pk_k = Miniscript::from_ast(Terminal::PkK(key)).map_err(Error::from)?;
            let pk_ms: Miniscript<DescriptorPublicKey, Segwitv0> =
                Miniscript::from_ast(Terminal::Check(Arc::new(pk_k))).map_err(Error::from)?;
            Descriptor::new_wsh(pk_ms).map_err(Error::from)
        }
        "tr" => Descriptor::new_tr(key, None).map_err(Error::from),
        _ => Err(Error::Generic(format!(
            "Unsupported descriptor type: {desc_type}"
        ))),
    }
}

/// Generate new mnemonic and descriptors
pub fn generate_descriptor_with_mnemonic(
    network: NetworkKind,
    desc_type: &str,
) -> Result<DescriptorResult, Error> {
    let mnemonic: GeneratedKey<Mnemonic, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English)).map_err(Error::BIP39Error)?;

    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed)?;

    let mut result = generate_descriptors(desc_type, &xprv.to_string(), network)?;
    result.mnemonic = Some(mnemonic.to_string());
    Ok(result)
}

/// Generate descriptors from existing mnemonic
pub fn generate_descriptor_from_mnemonic(
    mnemonic_str: &str,
    network: NetworkKind,
    desc_type: &str,
) -> Result<DescriptorResult, Error> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed)?;

    let mut result = generate_descriptors(desc_type, &xprv.to_string(), network)?;
    result.mnemonic = Some(mnemonic_str.to_string());
    Ok(result)
}

/// Returns the number of derivation paths in `descriptor`.
///
/// Errors if the descriptor is unparseable or its keys don't match `network`.
fn descriptor_path_count(descriptor: &str, network: Network) -> Result<usize, Error> {
    let secp = Secp256k1::new();
    let (descriptor, _) = descriptor.into_wallet_descriptor(&secp, network.into())?;
    Ok(descriptor.into_single_descriptors()?.len())
}

/// Validates the external/internal descriptor pair, returning `true` if `ext_descriptor` is a
/// supported two-path BIP-389 multipath descriptor.
///
/// Errors if either descriptor is unparseable or doesn't match `network`, if `ext_descriptor` is
/// a multipath descriptor with a number of paths other than two (only external/internal two-path
/// multipath is supported), if a multipath `ext_descriptor` is paired with a separate
/// `int_descriptor`, or if `int_descriptor` is itself a multipath descriptor.
pub fn validate_descriptor_pair(
    ext_descriptor: &str,
    int_descriptor: Option<&str>,
    network: Network,
) -> Result<bool, Error> {
    let ext_paths = descriptor_path_count(ext_descriptor, network)?;
    if ext_paths > 2 {
        return Err(Error::Generic(format!(
            "Unsupported multipath descriptor: expected exactly 2 paths (external/internal), found {ext_paths}."
        )));
    }
    let ext_is_multipath = ext_paths == 2;

    if let Some(int_descriptor) = int_descriptor {
        if ext_is_multipath {
            return Err(Error::AmbiguousDescriptors);
        }
        if descriptor_path_count(int_descriptor, network)? > 1 {
            return Err(Error::MultipathInternalDescriptor);
        }
    }

    Ok(ext_is_multipath)
}

/// Strip a trailing descriptor checksum.
#[cfg(feature = "hwi")]
pub(crate) fn strip_checksum(descriptor: &str) -> &str {
    descriptor.split('#').next().unwrap_or(descriptor)
}

/// Returns `true` if `descriptor` is a BIP-389 multipath descriptor (more than
/// one derivation path).
///
/// Errors if the descriptor is unparseable or its keys don't match `network`.
#[cfg(feature = "hwi")]
pub fn is_multipath_descriptor(descriptor: &str, network: Network) -> Result<bool, Error> {
    Ok(descriptor_path_count(descriptor, network)? > 1)
}

/// Single-sig descriptor script types.
#[cfg(feature = "hwi")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SingleSigScriptType {
    Wpkh,
    Tr,
    ShWpkh,
    Pkh,
}

#[cfg(feature = "hwi")]
impl SingleSigScriptType {
    /// The BIP-43 purpose index for this type.
    pub fn purpose(self) -> u32 {
        match self {
            Self::Pkh => 44,
            Self::ShWpkh => 49,
            Self::Wpkh => 84,
            Self::Tr => 86,
        }
    }

    /// Map a BIP-43 purpose index back to a type.
    fn from_purpose(purpose: u32) -> Option<Self> {
        match purpose {
            44 => Some(Self::Pkh),
            49 => Some(Self::ShWpkh),
            84 => Some(Self::Wpkh),
            86 => Some(Self::Tr),
            _ => None,
        }
    }

    /// Infer the type from a derivation path's purpose (BIP-43). The purpose
    /// level must be hardened, so an unhardened path returns `None`.
    pub fn from_derivation_path(path: &DerivationPath) -> Option<Self> {
        let &ChildNumber::Hardened { index: purpose } = path.into_iter().next()? else {
            return None;
        };
        Self::from_purpose(purpose)
    }

    /// The `--type` / descriptor name for this type.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wpkh => "wpkh",
            Self::Tr => "tr",
            Self::ShWpkh => "sh-wpkh",
            Self::Pkh => "pkh",
        }
    }

    /// Build a checksummed single-sig descriptor from a key expression for the
    /// given keychain branch (0 = external, 1 = internal).
    pub fn descriptor(self, key_expr: &str, branch: u32) -> Result<String, Error> {
        let raw = match self {
            Self::Wpkh => format!("wpkh({key_expr}/{branch}/*)"),
            Self::Tr => format!("tr({key_expr}/{branch}/*)"),
            Self::ShWpkh => format!("sh(wpkh({key_expr}/{branch}/*))"),
            Self::Pkh => format!("pkh({key_expr}/{branch}/*)"),
        };
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&raw)
            .map_err(|e| Error::Generic(format!("Failed to build descriptor: {e}")))?;
        Ok(descriptor.to_string())
    }
}

#[cfg(test)]
mod multipath_tests {
    use super::*;

    const MULTIPATH: &str = "wpkh([9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)";
    const SINGLE: &str = "wpkh([07234a14/84'/1'/0']tpubDCSgT6PaVLQH9h2TAxKryhvkEurUBcYRJc9dhTcMDyahhWiMWfEWvQQX89yaw7w7XU8bcVujoALfxq59VkFATri3Cxm5mkp9kfHfRFDckEh/0/*)#429nsxmg";

    #[test]
    fn rejects_multipath_with_internal_descriptor() {
        assert!(matches!(
            validate_descriptor_pair(MULTIPATH, Some(SINGLE), Network::Testnet),
            Err(Error::AmbiguousDescriptors)
        ));
    }

    #[test]
    fn accepts_single_path_with_internal_descriptor() {
        assert!(!validate_descriptor_pair(SINGLE, Some(SINGLE), Network::Testnet).unwrap());
    }
    #[cfg(feature = "hwi")]
    #[test]
    fn detects_multipath_descriptor() {
        assert!(is_multipath_descriptor(MULTIPATH, Network::Testnet).unwrap());
        assert!(!is_multipath_descriptor(SINGLE, Network::Testnet).unwrap());
    }

    #[cfg(feature = "hwi")]
    #[test]
    fn infers_script_type_from_purpose() {
        let p = |s: &str| DerivationPath::from_str(s).unwrap();
        type T = SingleSigScriptType;
        assert_eq!(T::from_derivation_path(&p("m/44'/1'/0'")), Some(T::Pkh));
        assert_eq!(T::from_derivation_path(&p("m/49'/1'/0'")), Some(T::ShWpkh));
        assert_eq!(T::from_derivation_path(&p("m/84'/1'/0'")), Some(T::Wpkh));
        assert_eq!(T::from_derivation_path(&p("m/86h/0h/0h")), Some(T::Tr));
        assert_eq!(T::from_derivation_path(&p("m/48'/1'/0'/2'")), None);
        // BIP-43: an unhardened purpose is not a standard path.
        assert_eq!(T::from_derivation_path(&p("m/84/1/0")), None);
    }
}
