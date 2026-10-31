//! NUT-13 Deterministic Secret and Blinding Factor derivation via BIP-32.
//!
//! Derivation paths:
//! - Secret:          `m/129372'/0'/{keyset_id_int}'/{counter}'/0` (hex-encoded 32 bytes)
//! - Blinding factor: `m/129372'/0'/{keyset_id_int}'/{counter}'/1` (32-byte `SecretKey`)

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use cashu_vault_protocol::BlindedMessage;
use zeroize::Zeroizing;

use crate::bdhke::blind_message;

const PURPOSE_CASHU: u32 = 129372;

/// Convert a hex keyset ID (`00...` or `01...`) to its NUT-13 31-bit integer index.
pub fn keyset_id_to_u32(keyset_id: &str) -> Result<u32, String> {
    if keyset_id.len() < 16 {
        return Err(format!("keyset_id '{keyset_id}' is shorter than 16 hex chars"));
    }
    let prefix = &keyset_id[..16];
    let raw = u64::from_str_radix(prefix, 16)
        .map_err(|e| format!("invalid hex in keyset_id '{keyset_id}': {e}"))?;
    let modulus = (1u64 << 31) - 1;
    Ok((raw % modulus) as u32)
}

/// Deterministic secret and blinding factor derived for `(keyset_id, counter)`.
#[derive(Clone)]
pub struct DerivedOutput {
    pub keyset_id: String,
    pub counter: u32,
    pub amount: u64,
    pub secret: Zeroizing<String>,
    pub r: SecretKey,
    pub blinded: BlindedMessage,
}

/// Derive the NUT-13 `(secret, r)` pair and construct its `BlindedMessage` (`B_`).
pub fn derive_blinded_output(
    app_seed: &[u8; 32],
    keyset_id: &str,
    counter: u32,
    amount: u64,
) -> Result<DerivedOutput, String> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, app_seed)
        .map_err(|e| format!("BIP-32 master key error: {e}"))?;
    let ks_int = keyset_id_to_u32(keyset_id)?;

    let base_path = [
        ChildNumber::from_hardened_idx(PURPOSE_CASHU).expect("valid hardened index"),
        ChildNumber::from_hardened_idx(0).expect("valid hardened index"),
        ChildNumber::from_hardened_idx(ks_int).expect("valid 31-bit index"),
        ChildNumber::from_hardened_idx(counter).map_err(|_| "counter exceeds 2^31-1".to_owned())?,
    ];

    let parent = master
        .derive_priv(&secp, &base_path)
        .map_err(|e| format!("BIP-32 derive_priv failed: {e}"))?;

    let secret_node = parent
        .derive_priv(
            &secp,
            &[ChildNumber::from_normal_idx(0).expect("valid normal index")],
        )
        .map_err(|e| format!("BIP-32 secret child failed: {e}"))?;
    let r_node = parent
        .derive_priv(
            &secp,
            &[ChildNumber::from_normal_idx(1).expect("valid normal index")],
        )
        .map_err(|e| format!("BIP-32 blinding factor child failed: {e}"))?;

    let secret_hex = Zeroizing::new(hex::encode(secret_node.private_key.secret_bytes()));
    let r = r_node.private_key;
    let b_ = blind_message(secret_hex.as_bytes(), &r)?;

    Ok(DerivedOutput {
        keyset_id: keyset_id.to_owned(),
        counter,
        amount,
        secret: secret_hex,
        r,
        blinded: BlindedMessage {
            amount,
            keyset_id: keyset_id.to_owned(),
            b_: hex::encode(b_.serialize()),
        },
    })
}
