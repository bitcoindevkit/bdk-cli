use std::str::FromStr;

use bdk_wallet::bitcoin::{
    XOnlyPublicKey,
    key::{Parity, rand},
    secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
};
use bdk_wallet::miniscript::Descriptor;

use crate::error::BDKCliError as Error;

/// The BIP-341 NUMS point `H`, x-only.
const NUMS_UNSPENDABLE_KEY_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub fn generate_unspendable_internal_key() -> Result<(XOnlyPublicKey, SecretKey), Error> {
    let r = SecretKey::new(&mut rand::thread_rng());
    let internal_key = derive_unspendable_internal_key(&r)?;
    Ok((internal_key, r))
}

/// Derive the unspendable internal key `H + rG` for the randomness factor `r`.
///
/// Using the NUMS point `H` verbatim is recognisable on chain, so it is randomised.
/// `H + rG` is unspendable too, since the discrete log of `H` is unknown.
/// See BIP-341.
pub fn derive_unspendable_internal_key(r: &SecretKey) -> Result<XOnlyPublicKey, Error> {
    let secp = Secp256k1::new();

    let nums_key = XOnlyPublicKey::from_str(NUMS_UNSPENDABLE_KEY_HEX)
        .map_err(|e| Error::Generic(format!("Invalid NUMS key: {e}")))?;
    let nums_point = PublicKey::from_x_only_public_key(nums_key, Parity::Even);

    let internal_key_point = nums_point
        .add_exp_tweak(&secp, &Scalar::from(*r))
        .map_err(|e| Error::Generic(format!("Failed to tweak NUMS key: {e}")))?;

    Ok(internal_key_point.x_only_public_key().0)
}

/// Check that the internal key of a `tr()` descriptor is the NUMS point tweaked by `r`.
// No caller until the CLI exposes verification.
#[allow(dead_code)]
pub fn verify_unspendable_internal_key(descriptor: &str, r: &SecretKey) -> Result<(), Error> {
    if derive_unspendable_internal_key(r)? != taproot_internal_key(descriptor)? {
        return Err(Error::UnspendableKeyMismatch);
    }

    Ok(())
}

/// Extract the internal key of a `tr()` descriptor.
#[allow(dead_code)]
fn taproot_internal_key(descriptor: &str) -> Result<XOnlyPublicKey, Error> {
    let descriptor = Descriptor::<String>::from_str(descriptor)
        .map_err(|e| Error::Generic(format!("Invalid descriptor: {e}")))?;

    match descriptor {
        Descriptor::Tr(tr) => XOnlyPublicKey::from_str(tr.internal_key())
            .map_err(|e| Error::Generic(format!("Invalid taproot internal key: {e}"))),
        _ => Err(Error::Generic(
            "Not a taproot descriptor, there is no internal key to verify".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `r` and the internal key it produced, from the output of `compile --type tr`.
    const R_HEX: &str = "69c00a610663904ebb0029001bc4f56f99774a0dc9d3b46e1a4bc50629df9a4b";
    const INTERNAL_KEY_HEX: &str =
        "c43c9c7a8b5a545fa49320124166499c0e1a092a991df1839800afb37693c5a8";
    const DESCRIPTOR: &str =
        "tr(c43c9c7a8b5a545fa49320124166499c0e1a092a991df1839800afb37693c5a8,pk(A))#qwt4mlqc";

    fn r() -> SecretKey {
        SecretKey::from_str(R_HEX).expect("test vector should be a valid secret key")
    }

    #[test]
    fn derives_the_key_the_command_used_to_derive() {
        let expected =
            XOnlyPublicKey::from_str(INTERNAL_KEY_HEX).expect("test vector should be a key");

        assert_eq!(
            derive_unspendable_internal_key(&r()).expect("derivation should succeed"),
            expected
        );
    }

    #[test]
    fn accepts_the_pair_compile_produced() {
        verify_unspendable_internal_key(DESCRIPTOR, &r()).expect("the pair should verify");
    }

    #[test]
    fn rejects_a_different_randomness_factor() {
        let other = SecretKey::from_slice(&[7u8; 32]).expect("7 repeated is a valid secret key");

        assert!(matches!(
            verify_unspendable_internal_key(DESCRIPTOR, &other),
            Err(Error::UnspendableKeyMismatch)
        ));
    }

    #[test]
    fn rejects_a_plain_nums_internal_key() {
        // `H` on its own is what the randomisation is meant to avoid: it is unspendable, but it
        // is not `H + rG` for any `r`, so verification has to reject it.
        let descriptor = format!("tr({NUMS_UNSPENDABLE_KEY_HEX},pk(A))");

        assert!(matches!(
            verify_unspendable_internal_key(&descriptor, &r()),
            Err(Error::UnspendableKeyMismatch)
        ));
    }

    #[test]
    fn rejects_a_descriptor_that_is_not_taproot() {
        assert!(matches!(
            verify_unspendable_internal_key("wsh(pk(A))", &r()),
            Err(Error::Generic(_))
        ));
    }
}
