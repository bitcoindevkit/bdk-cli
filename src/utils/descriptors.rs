use bdk_wallet::keys::GeneratableKey;
use std::{str::FromStr, sync::Arc};

use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::{
    KeychainKind,
    bip39::{Language, Mnemonic},
    bitcoin::{
        Network,
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
use cli_table::{Cell, CellStruct, Style, Table};
use serde_json::{Value, json};

use crate::error::BDKCliError as Error;

pub fn generate_descriptors(desc_type: &str, key: &str, network: Network) -> Result<Value, Error> {
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
            Network::Bitcoin => 0u32,
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
    network: Network,
) -> Result<Value, Error> {
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

    Ok(json!({
        "public_descriptors": {
            "external": external_pub,
            "internal": internal_pub
        },
        "private_descriptors": {
            "external": external_priv,
            "internal": internal_priv
        },
        "fingerprint": fingerprint.to_string()
    }))
}

/// Generate descriptors from public key (xpub/tpub)
pub fn generate_public_descriptors(
    desc_type: &str,
    key: &str,
    derivation_path: &DerivationPath,
) -> Result<Value, Error> {
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

    Ok(json!({
        "public_descriptors": {
            "external": external_pub,
            "internal": internal_pub
        },
        "fingerprint": fingerprint.to_string()
    }))
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
    network: Network,
    desc_type: &str,
) -> Result<serde_json::Value, Error> {
    let mnemonic: GeneratedKey<Mnemonic, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English)).map_err(Error::BIP39Error)?;

    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed)?;

    let mut result = generate_descriptors(desc_type, &xprv.to_string(), network)?;
    result["mnemonic"] = json!(mnemonic.to_string());
    Ok(result)
}

/// Generate descriptors from existing mnemonic
pub fn generate_descriptor_from_mnemonic(
    mnemonic_str: &str,
    network: Network,
    desc_type: &str,
) -> Result<serde_json::Value, Error> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed)?;

    let mut result = generate_descriptors(desc_type, &xprv.to_string(), network)?;
    result["mnemonic"] = json!(mnemonic_str);
    Ok(result)
}

pub fn format_descriptor_output(result: &Value, pretty: bool) -> Result<String, Error> {
    if !pretty {
        return Ok(serde_json::to_string_pretty(result)?);
    }

    let mut rows: Vec<Vec<CellStruct>> = vec![];

    if let Some(desc_type) = result.get("type") {
        rows.push(vec![
            "Type".cell().bold(true),
            desc_type.as_str().unwrap_or("N/A").cell(),
        ]);
    }

    if let Some(finger_print) = result.get("fingerprint") {
        rows.push(vec![
            "Fingerprint".cell().bold(true),
            finger_print.as_str().unwrap_or("N/A").cell(),
        ]);
    }

    if let Some(network) = result.get("network") {
        rows.push(vec![
            "Network".cell().bold(true),
            network.as_str().unwrap_or("N/A").cell(),
        ]);
    }
    if let Some(multipath_desc) = result.get("multipath_descriptor") {
        rows.push(vec![
            "Multipart Descriptor".cell().bold(true),
            multipath_desc.as_str().unwrap_or("N/A").cell(),
        ]);
    }
    if let Some(pub_descs) = result.get("public_descriptors").and_then(|v| v.as_object()) {
        if let Some(ext) = pub_descs.get("external") {
            rows.push(vec![
                "External Public".cell().bold(true),
                ext.as_str().unwrap_or("N/A").cell(),
            ]);
        }
        if let Some(int) = pub_descs.get("internal") {
            rows.push(vec![
                "Internal Public".cell().bold(true),
                int.as_str().unwrap_or("N/A").cell(),
            ]);
        }
    }
    if let Some(priv_descs) = result
        .get("private_descriptors")
        .and_then(|v| v.as_object())
    {
        if let Some(ext) = priv_descs.get("external") {
            rows.push(vec![
                "External Private".cell().bold(true),
                ext.as_str().unwrap_or("N/A").cell(),
            ]);
        }
        if let Some(int) = priv_descs.get("internal") {
            rows.push(vec![
                "Internal Private".cell().bold(true),
                int.as_str().unwrap_or("N/A").cell(),
            ]);
        }
    }
    if let Some(mnemonic) = result.get("mnemonic") {
        rows.push(vec![
            "Mnemonic".cell().bold(true),
            mnemonic.as_str().unwrap_or("N/A").cell(),
        ]);
    }

    let table = rows
        .table()
        .display()
        .map_err(|e| Error::Generic(e.to_string()))?;

    Ok(format!("{table}"))
}
