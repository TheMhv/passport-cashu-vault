//! Cryptographic Cashu Mint implementation (`MockMint`) for tests, `vault-cli`, and offline demo mode.
//!
//! Uses real secp256k1 BDHKE (`C_ = k * B_`), NUT-02 keyset derivation, and NUT-12 DLEQ proofs.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::hashes::{hmac, sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use cashu_vault_protocol::{
    BlindSignature, BlindedMessage, DleqProof, KeysetInfo, MeltRequestPayload, MintRequestPayload,
    Proof, SwapRequestPayload,
};

use crate::bdhke::{dleq_hash_e, hash_to_curve};
use crate::keyset::{compute_input_fee, derive_keyset_id_v00, split_amount};

/// A real BDHKE + NUT-12 Cashu mint backed by deterministic secp256k1 keys.
#[derive(Clone)]
pub struct MockMint {
    pub url: String,
    pub keyset_id: String,
    pub input_fee_ppk: u64,
    secret_keys: BTreeMap<u64, SecretKey>,
    public_keys: BTreeMap<u64, PublicKey>,
    spent_secrets: BTreeSet<String>,
}

impl MockMint {
    /// Create a deterministic mint from a 32-byte seed and mint URL.
    pub fn new(mint_seed: &[u8; 32], url: &str, input_fee_ppk: u64) -> Self {
        let secp = Secp256k1::new();
        let mut secret_keys = BTreeMap::new();
        let mut public_keys = BTreeMap::new();

        for exp in 0..20u32 {
            let amount = 1u64 << exp;
            let mut engine = hmac::HmacEngine::<sha256::Hash>::new(mint_seed);
            engine.input(b"cashu-mock-mint-key/");
            engine.input(&amount.to_be_bytes());
            let bytes = hmac::Hmac::<sha256::Hash>::from_engine(engine).to_byte_array();
            let sk = SecretKey::from_slice(&bytes).expect("valid deterministic mint key");
            let pk = PublicKey::from_secret_key(&secp, &sk);
            secret_keys.insert(amount, sk);
            public_keys.insert(amount, pk);
        }

        let keyset_id = derive_keyset_id_v00(&public_keys);
        Self {
            url: url.to_owned(),
            keyset_id,
            input_fee_ppk,
            secret_keys,
            public_keys,
            spent_secrets: BTreeSet::new(),
        }
    }

    /// Export the mint's `KeysetInfo` (NUT-01 / NUT-02).
    pub fn keyset_info(&self) -> KeysetInfo {
        let keys = self
            .public_keys
            .iter()
            .map(|(&amt, pk)| (amt, hex::encode(pk.serialize())))
            .collect();
        KeysetInfo {
            id: self.keyset_id.clone(),
            unit: "sat".to_owned(),
            active: true,
            input_fee_ppk: self.input_fee_ppk,
            keys,
        }
    }

    /// Sign a single `BlindedMessage` with BDHKE (`C_ = k * B_`) and a NUT-12 DLEQ proof.
    pub fn sign_blinded(&self, blinded: &BlindedMessage) -> Result<BlindSignature, String> {
        if blinded.keyset_id != self.keyset_id {
            return Err(format!(
                "unknown keyset_id '{}', expected '{}'",
                blinded.keyset_id, self.keyset_id
            ));
        }
        let sk_k = self
            .secret_keys
            .get(&blinded.amount)
            .ok_or_else(|| format!("unsupported denomination {}", blinded.amount))?;
        let pk_a = self.public_keys.get(&blinded.amount).expect("matching pk");

        let b_bytes = hex::decode(&blinded.b_).map_err(|_| "invalid B_ hex".to_owned())?;
        let b_ = PublicKey::from_slice(&b_bytes).map_err(|_| "invalid B_ point".to_owned())?;

        let secp = Secp256k1::new();
        let c_ = b_
            .mul_tweak(&secp, &Scalar::from(*sk_k))
            .map_err(|e| format!("k * B_ failed: {e}"))?;

        // Deterministic nonce `p` for NUT-12 DLEQ proof:
        // R1 = p * G, R2 = p * B_, e = hash_e(R1, R2, A, C_), s = p + e * k
        let mut nonce_engine = hmac::HmacEngine::<sha256::Hash>::new(&sk_k.secret_bytes());
        nonce_engine.input(b"cashu-dleq-nonce/");
        nonce_engine.input(&b_.serialize());
        let p_bytes = hmac::Hmac::<sha256::Hash>::from_engine(nonce_engine).to_byte_array();
        let sk_p = SecretKey::from_slice(&p_bytes).expect("valid nonce scalar");

        let r1 = PublicKey::from_secret_key(&secp, &sk_p);
        let r2 = b_
            .mul_tweak(&secp, &Scalar::from(sk_p))
            .map_err(|e| format!("p * B_ failed: {e}"))?;

        let e_bytes = dleq_hash_e(&r1, &r2, pk_a, &c_);
        let sk_e = SecretKey::from_slice(&e_bytes).expect("valid e scalar");

        // s = p + e * k (mod n)
        let ek = sk_k
            .mul_tweak(&Scalar::from(sk_e))
            .map_err(|e| format!("e * k failed: {e}"))?;
        let sk_s = sk_p
            .add_tweak(&Scalar::from(ek))
            .map_err(|e| format!("p + e*k failed: {e}"))?;

        Ok(BlindSignature {
            amount: blinded.amount,
            keyset_id: self.keyset_id.clone(),
            c_: hex::encode(c_.serialize()),
            dleq: Some(DleqProof {
                e: hex::encode(e_bytes),
                s: hex::encode(sk_s.secret_bytes()),
            }),
        })
    }

    /// Verify a single unblinded `Proof` (`C == k * hash_to_curve(secret)`) and check double-spend.
    pub fn verify_proof(&self, proof: &Proof) -> Result<(), String> {
        if proof.keyset_id != self.keyset_id {
            return Err(format!("unknown keyset_id '{}'", proof.keyset_id));
        }
        if self.spent_secrets.contains(&proof.secret) {
            return Err("proof already spent at mint".to_owned());
        }
        let sk_k = self
            .secret_keys
            .get(&proof.amount)
            .ok_or_else(|| format!("unsupported proof amount {}", proof.amount))?;
        let secp = Secp256k1::new();
        let y = hash_to_curve(proof.secret.as_bytes());
        let expected_c = y
            .mul_tweak(&secp, &Scalar::from(*sk_k))
            .map_err(|e| format!("k * Y failed: {e}"))?;
        let c_bytes = hex::decode(&proof.c).map_err(|_| "invalid proof C hex".to_owned())?;
        let c = PublicKey::from_slice(&c_bytes).map_err(|_| "invalid proof C point".to_owned())?;
        if c != expected_c {
            return Err("invalid BDHKE proof signature C != k * Y".to_owned());
        }
        Ok(())
    }

    /// Process a NUT-04 Mint request (`MintRequestPayload`) and return `BlindSignature`s.
    pub fn process_mint(&self, req: &MintRequestPayload) -> Result<Vec<BlindSignature>, String> {
        let sum: u64 = req.outputs.iter().map(|o| o.amount).sum();
        if sum != req.amount {
            return Err(format!(
                "mint outputs sum ({sum}) != quote amount ({})",
                req.amount
            ));
        }
        req.outputs.iter().map(|o| self.sign_blinded(o)).collect()
    }

    /// Process a NUT-03 Swap request (`SwapRequestPayload`), marking inputs spent and signing outputs.
    pub fn process_swap(&mut self, req: &SwapRequestPayload) -> Result<Vec<BlindSignature>, String> {
        if req.inputs.is_empty() {
            return Err("swap has no inputs".to_owned());
        }
        let mut seen = BTreeSet::new();
        for proof in &req.inputs {
            if !seen.insert(proof.secret.clone()) {
                return Err("duplicate input proof in swap".to_owned());
            }
            self.verify_proof(proof)?;
        }
        let in_sum: u64 = req.inputs.iter().map(|p| p.amount).sum();
        let out_sum: u64 = req.outputs.iter().map(|o| o.amount).sum();
        let fee = compute_input_fee(req.inputs.len(), self.input_fee_ppk);
        if in_sum != out_sum + fee {
            return Err(format!(
                "swap unbalanced: inputs ({in_sum}) != outputs ({out_sum}) + fee ({fee})"
            ));
        }
        let sigs: Result<Vec<BlindSignature>, String> =
            req.outputs.iter().map(|o| self.sign_blinded(o)).collect();
        let sigs = sigs?;
        for proof in &req.inputs {
            self.spent_secrets.insert(proof.secret.clone());
        }
        Ok(sigs)
    }

    /// Process a NUT-05 Melt request (`MeltRequestPayload`), returning `(paid, change_signatures)`.
    /// `actual_ln_fee` is the actual routing fee charged (<= `req.fee_reserve`).
    pub fn process_melt(
        &mut self,
        req: &MeltRequestPayload,
        actual_ln_fee: u64,
    ) -> Result<Vec<BlindSignature>, String> {
        if actual_ln_fee > req.fee_reserve {
            return Err("actual_ln_fee exceeds fee_reserve".to_owned());
        }
        let mut seen = BTreeSet::new();
        for proof in &req.inputs {
            if !seen.insert(proof.secret.clone()) {
                return Err("duplicate input proof in melt".to_owned());
            }
            self.verify_proof(proof)?;
        }
        let in_sum: u64 = req.inputs.iter().map(|p| p.amount).sum();
        let input_fee = compute_input_fee(req.inputs.len(), self.input_fee_ppk);
        if in_sum < req.amount + req.fee_reserve + input_fee {
            return Err("melt inputs insufficient for amount + fee_reserve + input_fee".to_owned());
        }

        let change_amount = in_sum - req.amount - actual_ln_fee - input_fee;
        let change_parts = split_amount(change_amount);
        if change_parts.len() > req.outputs.len() {
            return Err(format!(
                "not enough blank outputs ({}) for change parts ({})",
                req.outputs.len(),
                change_parts.len()
            ));
        }

        let mut change_sigs = Vec::with_capacity(change_parts.len());
        for (amt, blank) in change_parts.into_iter().zip(req.outputs.iter()) {
            let assigned = BlindedMessage {
                amount: amt,
                keyset_id: blank.keyset_id.clone(),
                b_: blank.b_.clone(),
            };
            change_sigs.push(self.sign_blinded(&assigned)?);
        }

        for proof in &req.inputs {
            self.spent_secrets.insert(proof.secret.clone());
        }
        Ok(change_sigs)
    }
}
