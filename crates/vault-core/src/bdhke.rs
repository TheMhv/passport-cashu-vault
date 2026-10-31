//! NUT-00 BDHKE (`hash_to_curve`, `blind_message`, `unblind_signature`) and NUT-12 DLEQ proofs.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use cashu_vault_protocol::{BlindSignature, DleqProof, Proof, ProofDleq};

const DOMAIN_SEPARATOR: &[u8] = b"Secp256k1_HashToCurve_Cashu_";

/// NUT-00 `hash_to_curve(x: &[u8]) -> PublicKey`.
pub fn hash_to_curve(message: &[u8]) -> PublicKey {
    let mut engine = sha256::HashEngine::default();
    engine.input(DOMAIN_SEPARATOR);
    engine.input(message);
    let msg_hash = sha256::Hash::from_engine(engine).to_byte_array();

    for counter in 0u32..=u32::MAX {
        let mut c_engine = sha256::HashEngine::default();
        c_engine.input(&msg_hash);
        c_engine.input(&counter.to_le_bytes());
        let digest = sha256::Hash::from_engine(c_engine).to_byte_array();

        let mut candidate = [0u8; 33];
        candidate[0] = 0x02;
        candidate[1..].copy_from_slice(&digest);
        if let Ok(pk) = PublicKey::from_slice(&candidate) {
            return pk;
        }
    }
    unreachable!("secp256k1 hash_to_curve always finds a point within a few iterations")
}

/// NUT-00 blinding: `B_ = hash_to_curve(secret) + r * G`.
pub fn blind_message(secret: &[u8], r: &SecretKey) -> Result<PublicKey, String> {
    let secp = Secp256k1::new();
    let y = hash_to_curve(secret);
    let r_pub = PublicKey::from_secret_key(&secp, r);
    y.combine(&r_pub)
        .map_err(|e| format!("blind_message point addition failed: {e}"))
}

/// NUT-00 unblinding: `C = C_ - r * A`.
pub fn unblind_signature(
    c_: &PublicKey,
    r: &SecretKey,
    mint_pubkey_a: &PublicKey,
) -> Result<PublicKey, String> {
    let secp = Secp256k1::new();
    let scalar_r = Scalar::from(*r);
    let r_a = mint_pubkey_a
        .mul_tweak(&secp, &scalar_r)
        .map_err(|e| format!("r * A failed: {e}"))?;
    let neg_r_a = r_a.negate(&secp);
    c_.combine(&neg_r_a)
        .map_err(|e| format!("C_ - r*A failed: {e}"))
}

/// NUT-12 `hash_e(R1, R2, A, C_)`: SHA-256 over the concatenated uncompressed hex strings.
pub fn dleq_hash_e(
    r1: &PublicKey,
    r2: &PublicKey,
    a: &PublicKey,
    c_: &PublicKey,
) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    for pk in [r1, r2, a, c_] {
        let hex_uncompressed = hex::encode(pk.serialize_uncompressed());
        engine.input(hex_uncompressed.as_bytes());
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// NUT-12 DLEQ verification for a `BlindSignature`:
/// `R1 = s*G - e*A`, `R2 = s*B_ - e*C_`, check `e == dleq_hash_e(R1, R2, A, C_)`.
pub fn verify_dleq(
    b_: &PublicKey,
    c_: &PublicKey,
    mint_pubkey_a: &PublicKey,
    dleq: &DleqProof,
) -> Result<(), String> {
    let secp = Secp256k1::new();
    let e_bytes: [u8; 32] = hex::decode(&dleq.e)
        .map_err(|_| "invalid DLEQ e hex".to_owned())?
        .try_into()
        .map_err(|_| "DLEQ e must be 32 bytes".to_owned())?;
    let s_bytes: [u8; 32] = hex::decode(&dleq.s)
        .map_err(|_| "invalid DLEQ s hex".to_owned())?
        .try_into()
        .map_err(|_| "DLEQ s must be 32 bytes".to_owned())?;

    let e_key = SecretKey::from_slice(&e_bytes).map_err(|_| "invalid DLEQ scalar e".to_owned())?;
    let s_key = SecretKey::from_slice(&s_bytes).map_err(|_| "invalid DLEQ scalar s".to_owned())?;

    let e_scalar = Scalar::from(e_key);
    let s_scalar = Scalar::from(s_key);

    // R1 = s*G - e*A
    let s_g = PublicKey::from_secret_key(&secp, &s_key);
    let e_a = mint_pubkey_a
        .mul_tweak(&secp, &e_scalar)
        .map_err(|e| format!("DLEQ e*A failed: {e}"))?;
    let r1 = s_g
        .combine(&e_a.negate(&secp))
        .map_err(|e| format!("DLEQ R1 failed: {e}"))?;

    // R2 = s*B_ - e*C_
    let s_b = b_
        .mul_tweak(&secp, &s_scalar)
        .map_err(|e| format!("DLEQ s*B_ failed: {e}"))?;
    let e_c = c_
        .mul_tweak(&secp, &e_scalar)
        .map_err(|e| format!("DLEQ e*C_ failed: {e}"))?;
    let r2 = s_b
        .combine(&e_c.negate(&secp))
        .map_err(|e| format!("DLEQ R2 failed: {e}"))?;

    let expected_e = dleq_hash_e(&r1, &r2, mint_pubkey_a, c_);
    if expected_e != e_bytes {
        return Err("NUT-12 DLEQ proof verification failed".to_owned());
    }
    Ok(())
}

/// Verify an unblinded `Proof`'s NUT-12 `ProofDleq` against the mint's public key `A`.
pub fn verify_proof_dleq(proof: &Proof, mint_pubkey_a: &PublicKey) -> Result<(), String> {
    let dleq = proof
        .dleq
        .as_ref()
        .ok_or_else(|| "proof has no DLEQ attached".to_owned())?;
    let r_bytes: [u8; 32] = hex::decode(&dleq.r)
        .map_err(|_| "invalid proof DLEQ r hex".to_owned())?
        .try_into()
        .map_err(|_| "proof DLEQ r must be 32 bytes".to_owned())?;
    let r = SecretKey::from_slice(&r_bytes).map_err(|_| "invalid proof DLEQ scalar r".to_owned())?;
    let c_bytes = hex::decode(&proof.c).map_err(|_| "invalid proof C hex".to_owned())?;
    let c = PublicKey::from_slice(&c_bytes).map_err(|_| "invalid proof C point".to_owned())?;

    let secp = Secp256k1::new();
    let b_ = blind_message(proof.secret.as_bytes(), &r)?;
    let r_a = mint_pubkey_a
        .mul_tweak(&secp, &Scalar::from(r))
        .map_err(|e| format!("r*A failed: {e}"))?;
    let c_ = c
        .combine(&r_a)
        .map_err(|e| format!("C + r*A failed: {e}"))?;

    verify_dleq(
        &b_,
        &c_,
        mint_pubkey_a,
        &DleqProof {
            e: dleq.e.clone(),
            s: dleq.s.clone(),
        },
    )
}

/// Unblind a `BlindSignature` (verifying its NUT-12 DLEQ proof if present) into a `Proof`.
pub fn unblind_to_proof(
    sig: &BlindSignature,
    secret: &str,
    r: &SecretKey,
    mint_pubkey_a: &PublicKey,
) -> Result<Proof, String> {
    let c_bytes = hex::decode(&sig.c_).map_err(|_| "invalid C_ hex in BlindSignature".to_owned())?;
    let c_ = PublicKey::from_slice(&c_bytes).map_err(|_| "invalid C_ point".to_owned())?;
    let b_ = blind_message(secret.as_bytes(), r)?;

    let proof_dleq = if let Some(dleq) = &sig.dleq {
        verify_dleq(&b_, &c_, mint_pubkey_a, dleq)?;
        Some(ProofDleq {
            e: dleq.e.clone(),
            s: dleq.s.clone(),
            r: hex::encode(r.secret_bytes()),
        })
    } else {
        None
    };

    let c = unblind_signature(&c_, r, mint_pubkey_a)?;
    Ok(Proof {
        amount: sig.amount,
        keyset_id: sig.keyset_id.clone(),
        secret: secret.to_owned(),
        c: hex::encode(c.serialize()),
        dleq: proof_dleq,
    })
}
