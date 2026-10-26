use std::str::FromStr;

use bdk_wallet::bitcoin::{
    XOnlyPublicKey,
    key::{Parity, rand},
    secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
};

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

#[cfg(test)]
mod tests {
    use super::*;

    /// An `r` and the internal key it produced, from the output of `compile --type tr`.
    const R_HEX: &str = "69c00a610663904ebb0029001bc4f56f99774a0dc9d3b46e1a4bc50629df9a4b";
    const INTERNAL_KEY_HEX: &str =
        "c43c9c7a8b5a545fa49320124166499c0e1a092a991df1839800afb37693c5a8";

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
}
