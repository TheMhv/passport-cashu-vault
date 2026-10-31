//! NUT-01 / NUT-02 keyset verification, fee calculation, power-of-two splitting, and coin selection.

use std::collections::BTreeMap;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::PublicKey;
use cashu_vault_protocol::{KeysetInfo, Proof};

/// Normalize a mint URL (lowercase scheme and host, strip trailing `/`).
pub fn canonical_mint_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let (scheme, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| format!("mint URL '{raw}' is missing http:// or https://"))?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "https" && scheme_lower != "http" {
        return Err(format!("unsupported mint URL scheme '{scheme_lower}'"));
    }
    let (host, path) = match rest.split_once('/') {
        Some((h, p)) => (h.to_ascii_lowercase(), format!("/{}", p.trim_end_matches('/'))),
        None => (rest.to_ascii_lowercase(), String::new()),
    };
    if host.is_empty() {
        return Err("mint URL has an empty host".to_owned());
    }
    let clean_path = if path == "/" { String::new() } else { path };
    Ok(format!("{scheme_lower}://{host}{clean_path}"))
}

/// Compute the NUT-02 `00` keyset ID (`"00"` + first 7 bytes of SHA-256 over compressed pubkeys sorted by amount).
pub fn derive_keyset_id_v00(keys: &BTreeMap<u64, PublicKey>) -> String {
    let mut engine = sha256::HashEngine::default();
    for pk in keys.values() {
        engine.input(&pk.serialize());
    }
    let digest = sha256::Hash::from_engine(engine).to_byte_array();
    format!("00{}", hex::encode(&digest[..7]))
}

/// Parse and verify a `KeysetInfo`'s public keys and NUT-02 keyset ID.
pub fn parse_and_verify_keyset(info: &KeysetInfo) -> Result<BTreeMap<u64, PublicKey>, String> {
    if info.unit != "sat" {
        return Err(format!(
            "unsupported keyset unit '{}'; only 'sat' is supported",
            info.unit
        ));
    }
    if info.keys.is_empty() {
        return Err("keyset contains no keys".to_owned());
    }
    let mut parsed = BTreeMap::new();
    for (&amount, hex_pk) in &info.keys {
        if amount == 0 || !amount.is_power_of_two() {
            return Err(format!("keyset amount {amount} is not a power of two"));
        }
        let bytes = hex::decode(hex_pk)
            .map_err(|_| format!("invalid hex public key for amount {amount}"))?;
        let pk = PublicKey::from_slice(&bytes)
            .map_err(|_| format!("invalid secp256k1 public key for amount {amount}"))?;
        parsed.insert(amount, pk);
    }

    if info.id.starts_with("00") {
        let expected = derive_keyset_id_v00(&parsed);
        if info.id.to_ascii_lowercase() != expected {
            return Err(format!(
                "keyset ID mismatch: claimed '{}', derived '{expected}'",
                info.id
            ));
        }
    } else if !info.id.starts_with("01") || info.id.len() != 66 {
        return Err(format!("unsupported keyset ID format '{}'", info.id));
    }

    Ok(parsed)
}

/// NUT-02 input fee: `ceil(sum(input_fee_ppk) / 1000)`.
pub fn compute_input_fee(input_count: usize, input_fee_ppk: u64) -> u64 {
    if input_count == 0 || input_fee_ppk == 0 {
        return 0;
    }
    (input_count as u64 * input_fee_ppk).div_ceil(1000)
}

/// Split `amount` into ascending powers of two (`[1, 2, 4, 8, ...]`).
pub fn split_amount(mut amount: u64) -> Vec<u64> {
    let mut parts = Vec::new();
    let mut bit = 1u64;
    while amount > 0 {
        if amount & 1 == 1 {
            parts.push(bit);
        }
        amount >>= 1;
        bit = bit.saturating_mul(2);
    }
    parts
}

/// Number of blank change outputs needed for NUT-05 Melt overestimation change (`ceil(log2(max_change))`).
pub fn blank_output_count(max_change: u64) -> usize {
    if max_change == 0 {
        return 0;
    }
    (64 - max_change.leading_zeros()) as usize
}

/// Try to find an exact subset of `proofs` whose amounts sum to `target` (greedy largest-first DP).
pub fn select_exact_proofs(proofs: &[Proof], target: u64) -> Option<Vec<usize>> {
    if target == 0 {
        return None;
    }
    // Sort indices by amount descending for greedy power-of-two match first
    let mut indexed: Vec<(usize, u64)> = proofs
        .iter()
        .enumerate()
        .map(|(idx, p)| (idx, p.amount))
        .collect();
    indexed.sort_by_key(|b| std::cmp::Reverse(b.1));

    let mut remaining = target;
    let mut chosen = Vec::new();
    for &(idx, amt) in &indexed {
        if amt <= remaining {
            remaining -= amt;
            chosen.push(idx);
            if remaining == 0 {
                chosen.sort_unstable();
                return Some(chosen);
            }
        }
    }
    None
}

/// Select a subset of `proofs` sufficient to cover `target + input_fee(count, fee_ppk)`.
/// Returns `(selected_indices, total_selected_amount, input_fee)`.
pub fn select_proofs_covering(
    proofs: &[Proof],
    target: u64,
    fee_ppk: u64,
) -> Option<(Vec<usize>, u64, u64)> {
    if fee_ppk == 0 {
        if let Some(exact) = select_exact_proofs(proofs, target) {
            return Some((exact, target, 0));
        }
    }
    // Sort smallest-first or largest-first: largest-first minimizes input count (and therefore fees)
    let mut indexed: Vec<(usize, u64)> = proofs
        .iter()
        .enumerate()
        .map(|(idx, p)| (idx, p.amount))
        .collect();
    indexed.sort_by_key(|b| std::cmp::Reverse(b.1));

    let mut chosen = Vec::new();
    let mut sum = 0u64;
    for (idx, amt) in indexed {
        chosen.push(idx);
        sum += amt;
        let fee = compute_input_fee(chosen.len(), fee_ppk);
        if sum >= target + fee {
            chosen.sort_unstable();
            return Some((chosen, sum, fee));
        }
    }
    None
}
