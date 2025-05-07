use crate::commands::GenerateDescriptorArgs;
use anyhow::{anyhow, Result};
#[allow(deprecated)]
use bdk_wallet::bitcoin::bip32::{ExtendedPubKey, Xpriv};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::descriptor::Segwitv0;
use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::{GeneratableKey, GeneratedKey};
use serde_json::json;
use serde_json::Value;

use bdk_wallet::bitcoin::bip32::DerivationPath;
use bdk_wallet::descriptor::{Descriptor, DescriptorPublicKey};

use bdk_wallet::keys::{DescriptorSecretKey, IntoDescriptorKey};
use miniscript::descriptor::{DescriptorXKey, Wildcard};

use std::str::FromStr;

use miniscript::Tap;

pub fn generate_descriptor_from_args(args: GenerateDescriptorArgs) -> Result<Value, anyhow::Error> {
    match (args.multipath, args.key.as_ref()) {
        (true, Some(key)) => generate_multipath_descriptor(&args.network, args.r#type, key),
        (false, Some(key)) => generate_standard_descriptor(&args.network, args.r#type, key),
        (false, None) => {
            // New default: generate descriptor from fresh mnemonic (for script_type 84 only maybe)
            if args.r#type == 84 {
                generate_new_bip84_descriptor_with_mnemonic(args.network)
            } else {
                Err(anyhow!(
                    "Only script type 84 is supported for mnemonic-based generation"
                ))
            }
        }
        _ => Err(anyhow!(
            "Invalid arguments: please provide a key or a weak string"
        )),
    }
}

pub fn generate_new_bip84_descriptor_with_mnemonic(network: Network) -> Result<serde_json::Value> {
    let secp = Secp256k1::new();

    let mnemonic: GeneratedKey<Mnemonic, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|e| anyhow!("Mnemonic generation failed: {:?}", e))?;

    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed)
        .map_err(|e| anyhow!("Failed to create extended private key: {}", e))?;

    let origin = xprv.fingerprint(&secp);
    let deriv_base = "/84h/1h/0h"; // You might want to dynamically compute this based on args
    let xprv_str = xprv.to_string();

    let external_desc = format!("wpkh([{}{}]{}{})", origin, deriv_base, xprv_str, "/0/*");
    let internal_desc = format!("wpkh([{}{}]{}{})", origin, deriv_base, xprv_str, "/1/*");

    let (desc, keymap) = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &external_desc)
        .map_err(|e| anyhow!("Failed to parse external descriptor: {}", e))?;
    let (int_desc, int_keymap) =
        Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &internal_desc)
            .map_err(|e| anyhow!("Failed to parse internal descriptor: {}", e))?;

    Ok(serde_json::json!({
        "mnemonic": mnemonic.to_string(),
        "external_descriptor": {
            "public": desc.to_string(),
            "private": desc.to_string_with_secret(&keymap),
        },
        "internal_descriptor": {
            "public": int_desc.to_string(),
            "private": int_desc.to_string_with_secret(&int_keymap),
        }
    }))
}

pub fn generate_multipath_descriptor(
    network: &Network,
    script_type: u8,
    key: &str,
) -> Result<Value> {
    // Only BIP84 supported in this example
    if script_type != 84 {
        return Err(anyhow!(
            "Only BIP84 is supported for multipath at the moment."
        ));
    }

    #[allow(deprecated)]
    let xpub: ExtendedPubKey = key.parse().map_err(|e| anyhow!("Invalid xpub: {e}"))?;

    let derivation_path = DerivationPath::from_str("m/84h/1h/0h")?;
    let fingerprint = xpub.fingerprint();

    let make_desc = |change: u32| -> Result<(String, DescriptorPublicKey)> {
        let branch_path = DerivationPath::from_str(&change.to_string())?;

        let desc_xpub = DescriptorXKey {
            origin: Some((fingerprint, derivation_path.clone())),
            xkey: xpub,
            derivation_path: branch_path,
            wildcard: Wildcard::Unhardened,
        };

        let desc_key = DescriptorPublicKey::XPub(desc_xpub);
        let descriptor = Descriptor::new_wpkh(desc_key.clone())?;
        Ok((descriptor.to_string(), desc_key))
    };

    let (external_desc, _) = make_desc(0)?;
    let (internal_desc, _) = make_desc(1)?;

    Ok(json!({
        "type": "bip84-multipath",
        "external": external_desc,
        "internal": internal_desc,
        "fingerprint": fingerprint.to_string(),
        "network": network.to_string(),
    }))
}

fn generate_standard_descriptor(
    network: &Network,
    script_type: u8,
    key: &str,
) -> Result<Value, anyhow::Error> {
    match script_type {
        84 => generate_bip84_descriptor_from_key(network, key),
        86 => generate_bip86_descriptor_from_key(network, key),
        49 => generate_bip49_descriptor_from_key(network, key),
        44 => generate_bip44_descriptor_from_key(network, key),
        _ => Err(anyhow!("Unsupported script type")),
    }
}

pub fn generate_bip84_descriptor_from_key(
    network: &Network,
    key: &str,
) -> Result<serde_json::Value, anyhow::Error> {
    let secp = Secp256k1::new();
    let derivation_path: DerivationPath = "m/84h/1h/0h".parse()?;
    let xprv: Xpriv = key.parse().map_err(|e| anyhow!("Invalid xprv: {e}"))?;
    let fingerprint = xprv.fingerprint(&secp);

    let make_desc_key = |branch: u32| -> Result<(String, String)> {
        let branch_path: DerivationPath = DerivationPath::from_str(&format!("{branch}"))?;

        let desc_xprv = DescriptorXKey {
            origin: Some((fingerprint, derivation_path.clone())), // only account-level path
            xkey: xprv,
            derivation_path: branch_path, // just the change (0 for external, 1 for internal)
            wildcard: Wildcard::Unhardened,
        };

        let desc_secret = DescriptorSecretKey::XPrv(desc_xprv);

        // Use the BDK extract() to get both descriptor and keymap
        let (desc_key, keymap, _) =
            IntoDescriptorKey::<Segwitv0>::into_descriptor_key(desc_secret.clone())?
                .extract(&secp)?;

        // Create the public descriptor from the public key
        let public_descriptor = Descriptor::new_wpkh(desc_key.clone())?;

        // Here, we need to ensure that `desc_secret` is a valid descriptor type
        // for the private descriptor; we must use DescriptorPublicKey
        let private_descriptor = Descriptor::new_wpkh(desc_key)?;

        // Convert both to string representations
        let public_descriptor_str = public_descriptor.to_string();
        let private_descriptor_str = private_descriptor.to_string_with_secret(&keymap);

        Ok((public_descriptor_str, private_descriptor_str))
    };

    let (external_pub, external_priv) = make_desc_key(0)?;
    let (internal_pub, internal_priv) = make_desc_key(1)?;

    Ok(serde_json::json!({
        "type": "bip84",
        "external": {
            "public": external_pub,
            "private": external_priv,
        },
        "internal": {
            "public": internal_pub,
            "private": internal_priv,
        },
        "fingerprint": fingerprint.to_string(),
        "network": network.to_string()
    }))
}

pub fn generate_bip86_descriptor_from_key(
    network: &Network,
    key: &str,
) -> Result<Value, anyhow::Error> {
    let secp = Secp256k1::new();
    let derivation_path: DerivationPath = "m/86h/1h/0h".parse()?;
    let xprv: Xpriv = key.parse().map_err(|e| anyhow!("Invalid xprv: {e}"))?;
    let fingerprint = xprv.fingerprint(&secp);

    let make_desc_key = |branch: u32| -> Result<(String, String)> {
        let branch_path: DerivationPath = DerivationPath::from_str(&format!("{branch}"))?;

        let desc_xprv = DescriptorXKey {
            origin: Some((fingerprint, derivation_path.clone())), // only account-level path
            xkey: xprv,
            derivation_path: branch_path, // just the change (0 for external, 1 for internal)
            wildcard: Wildcard::Unhardened,
        };

        let desc_secret = DescriptorSecretKey::XPrv(desc_xprv);

        // Use the BDK extract() to get both descriptor and keymap
        let (desc_key, keymap, _) =
            IntoDescriptorKey::<Tap>::into_descriptor_key(desc_secret.clone())?.extract(&secp)?;

        // Create the public descriptor from the public key
        let public_descriptor = Descriptor::new_tr(desc_key.clone(), None)?;

        // Here, we need to ensure that `desc_secret` is a valid descriptor type
        // for the private descriptor; we must use DescriptorPublicKey
        let private_descriptor = Descriptor::new_tr(desc_key, None)?;

        // Convert both to string representations
        let public_descriptor_str = public_descriptor.to_string();
        let private_descriptor_str = private_descriptor.to_string_with_secret(&keymap);

        Ok((public_descriptor_str, private_descriptor_str))
    };

    let (external_pub, external_priv) = make_desc_key(0)?;
    let (internal_pub, internal_priv) = make_desc_key(1)?;

    Ok(serde_json::json!({
        "type": "bip86",
        "external": {
            "public": external_pub,
            "private": external_priv,
        },
        "internal": {
            "public": internal_pub,
            "private": internal_priv,
        },
        "fingerprint": fingerprint.to_string(),
        "network": network.to_string()
    }))
}

pub fn generate_bip49_descriptor_from_key(
    network: &Network,
    key: &str,
) -> Result<Value, anyhow::Error> {
    let secp = Secp256k1::new();
    let derivation_path: DerivationPath = "m/49h/1h/0h".parse()?;
    let xprv: Xpriv = key.parse().map_err(|e| anyhow!("Invalid xprv: {e}"))?;
    let fingerprint = xprv.fingerprint(&secp);

    let make_desc_key = |branch: u32| -> Result<(String, String)> {
        let branch_path: DerivationPath = DerivationPath::from_str(&format!("{branch}"))?;

        let desc_xprv = DescriptorXKey {
            origin: Some((fingerprint, derivation_path.clone())), // only account-level path
            xkey: xprv,
            derivation_path: branch_path, // just the change (0 for external, 1 for internal)
            wildcard: Wildcard::Unhardened,
        };

        let desc_secret = DescriptorSecretKey::XPrv(desc_xprv);

        // Use the BDK extract() to get both descriptor and keymap
        let (desc_key, keymap, _) =
            IntoDescriptorKey::<Segwitv0>::into_descriptor_key(desc_secret.clone())?
                .extract(&secp)?;

        // Create the public descriptor from the public key
        let public_descriptor = Descriptor::new_sh_wpkh(desc_key.clone())?;

        // Here, we need to ensure that `desc_secret` is a valid descriptor type
        // for the private descriptor; we must use DescriptorPublicKey
        let private_descriptor = Descriptor::new_sh_wpkh(desc_key)?;

        // Convert both to string representations
        let public_descriptor_str = public_descriptor.to_string();
        let private_descriptor_str = private_descriptor.to_string_with_secret(&keymap);

        Ok((public_descriptor_str, private_descriptor_str))
    };

    let (external_pub, external_priv) = make_desc_key(0)?;
    let (internal_pub, internal_priv) = make_desc_key(1)?;

    Ok(serde_json::json!({
        "type": "bip49",
        "external": {
            "public": external_pub,
            "private": external_priv,
        },
        "internal": {
            "public": internal_pub,
            "private": internal_priv,
        },
        "fingerprint": fingerprint.to_string(),
        "network": network.to_string()
    }))
}

pub fn generate_bip44_descriptor_from_key(
    network: &Network,
    key: &str,
) -> Result<Value, anyhow::Error> {
    let secp = Secp256k1::new();
    let derivation_path: DerivationPath = "m/44h/1h/0h".parse()?;
    let xprv: Xpriv = key.parse().map_err(|e| anyhow!("Invalid xprv: {e}"))?;
    let fingerprint = xprv.fingerprint(&secp);

    let make_desc_key = |branch: u32| -> Result<(String, String)> {
        let branch_path: DerivationPath = DerivationPath::from_str(&format!("{branch}"))?;

        let desc_xprv = DescriptorXKey {
            origin: Some((fingerprint, derivation_path.clone())), // only account-level path
            xkey: xprv,
            derivation_path: branch_path, // just the change (0 for external, 1 for internal)
            wildcard: Wildcard::Unhardened,
        };

        let desc_secret = DescriptorSecretKey::XPrv(desc_xprv);

        // Use the BDK extract() to get both descriptor and keymap
        let (desc_key, keymap, _) =
            IntoDescriptorKey::<Segwitv0>::into_descriptor_key(desc_secret.clone())?
                .extract(&secp)?;

        // Create the public descriptor from the public key
        let public_descriptor = Descriptor::new_pkh(desc_key.clone())?;

        // Here, we need to ensure that `desc_secret` is a valid descriptor type
        // for the private descriptor; we must use DescriptorPublicKey
        let private_descriptor = Descriptor::new_pkh(desc_key)?;

        // Convert both to string representations
        let public_descriptor_str = public_descriptor.to_string();
        let private_descriptor_str = private_descriptor.to_string_with_secret(&keymap);

        Ok((public_descriptor_str, private_descriptor_str))
    };

    let (external_pub, external_priv) = make_desc_key(0)?;
    let (internal_pub, internal_priv) = make_desc_key(1)?;

    Ok(serde_json::json!({
        "type": "bip44",
        "external": {
            "public": external_pub,
            "private": external_priv,
        },
        "internal": {
            "public": internal_pub,
            "private": internal_priv,
        },
        "fingerprint": fingerprint.to_string(),
        "network": network.to_string()
    }))
}
