//! Core Cashu cryptographic primitives for `cashu-vault` on Passport Prime.

pub mod bdhke;
pub mod keyset;
pub mod mock_mint;
pub mod nut13;

pub use bdhke::{
    blind_message, dleq_hash_e, hash_to_curve, unblind_signature, unblind_to_proof, verify_dleq,
    verify_proof_dleq,
};
pub use keyset::{
    blank_output_count, canonical_mint_url, compute_input_fee, derive_keyset_id_v00,
    parse_and_verify_keyset, select_exact_proofs, select_proofs_covering, split_amount,
};
pub use mock_mint::MockMint;
pub use nut13::{derive_blinded_output, keyset_id_to_u32, DerivedOutput};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nut00_hash_to_curve_known_vector() {
        // NUT-00 official test vector for message = 32 zero bytes (0000...0000 in hex)
        let msg = [0u8; 32];
        let y = hash_to_curve(&msg);
        assert_eq!(
            hex::encode(y.serialize()),
            "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"
        );
    }

    #[test]
    fn bdhke_nut12_nut13_and_mock_mint_end_to_end() {
        let app_seed = [0x42u8; 32];
        let mint_seed = [0x99u8; 32];
        let mint = MockMint::new(&mint_seed, "https://mint.cashu.space", 100);
        let ks_info = mint.keyset_info();
        let pubkeys = parse_and_verify_keyset(&ks_info).expect("valid keyset");

        // Derive NUT-13 output at counter 0 for 8 sats
        let derived = derive_blinded_output(&app_seed, &ks_info.id, 0, 8).expect("derive");
        let sig = mint.sign_blinded(&derived.blinded).expect("mint sign");

        let pk_8 = pubkeys.get(&8).expect("8 sat key");
        let proof =
            unblind_to_proof(&sig, &derived.secret, &derived.r, pk_8).expect("unblind + dleq");

        // Verify both BDHKE C == k*Y at the mint and NUT-12 ProofDleq offline
        mint.verify_proof(&proof).expect("mint verifies BDHKE proof");
        verify_proof_dleq(&proof, pk_8).expect("offline NUT-12 DLEQ verification");
    }

    #[test]
    fn canonical_url_and_split() {
        assert_eq!(
            canonical_mint_url("HTTPS://Mint.Example.com/Bitcoin/").unwrap(),
            "https://mint.example.com/Bitcoin"
        );
        assert_eq!(split_amount(13), vec![1, 4, 8]);
        assert_eq!(blank_output_count(0), 0);
        assert_eq!(blank_output_count(1), 1);
        assert_eq!(blank_output_count(7), 3);
    }
}
