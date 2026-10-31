//! NUT-00 `cashuA` (V3 JSON) and `cashuB` (V4 CBOR) token encoding and decoding.

use base64::alphabet::URL_SAFE as URL_SAFE_ALPHABET;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{Proof, ProofDleq};

fn default_unit() -> String {
    "sat".to_owned()
}

/// A decoded Cashu token (`cashuA` or `cashuB`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuToken {
    pub mint_url: String,
    pub unit: String,
    pub memo: Option<String>,
    pub proofs: Vec<Proof>,
}

// V3 (`cashuA`) JSON layout
#[derive(Serialize, Deserialize)]
struct TokenV3 {
    token: Vec<TokenV3Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TokenV3Entry {
    mint: String,
    proofs: Vec<Proof>,
}

// V4 (`cashuB`) CBOR layout per NUT-00
#[derive(Serialize, Deserialize)]
struct TokenV4 {
    #[serde(rename = "m")]
    mint: String,
    #[serde(rename = "u", default = "default_unit")]
    unit: String,
    #[serde(rename = "t")]
    tokens: Vec<TokenV4Keyset>,
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TokenV4Keyset {
    #[serde(rename = "i", with = "serde_bytes")]
    keyset_id: Vec<u8>,
    #[serde(rename = "p")]
    proofs: Vec<TokenV4Proof>,
}

#[derive(Serialize, Deserialize)]
struct TokenV4Proof {
    #[serde(rename = "a")]
    amount: u64,
    #[serde(rename = "s")]
    secret: String,
    #[serde(rename = "c", with = "serde_bytes")]
    c: Vec<u8>,
    #[serde(rename = "d", default, skip_serializing_if = "Option::is_none")]
    dleq: Option<TokenV4Dleq>,
}

#[derive(Serialize, Deserialize)]
struct TokenV4Dleq {
    #[serde(rename = "e", with = "serde_bytes")]
    e: Vec<u8>,
    #[serde(rename = "s", with = "serde_bytes")]
    s: Vec<u8>,
    #[serde(rename = "r", with = "serde_bytes")]
    r: Vec<u8>,
}

fn decode_b64_any(s: &str) -> Result<Vec<u8>, String> {
    // Strip whitespace, NUL bytes, and control chars (e.g. from QR scanner buffers),
    // and normalize standard base64 ('+', '/') to URL-safe base64 ('-', '_').
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    let unpadded = cleaned.trim_end_matches('=');
    let config = GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    let engine = GeneralPurpose::new(&URL_SAFE_ALPHABET, config);
    engine
        .decode(unpadded)
        .map_err(|e| format!("invalid base64 in token: {e}"))
}

impl CashuToken {
    /// Total value of all proofs in the token.
    pub fn total_amount(&self) -> u64 {
        self.proofs.iter().map(|p| p.amount).sum()
    }

    /// Extract a `cashuA...` or `cashuB...` token string from a NUT-16 `ur:bytes` payload
    /// (which may be a CBOR byte/text string wrapping the UTF-8 token, or raw UTF-8 bytes).
    pub fn extract_from_ur_bytes(data: &[u8]) -> Option<String> {
        if let Ok(bytes) = ciborium::from_reader::<serde_bytes::ByteBuf, _>(data) {
            if let Ok(s) = String::from_utf8(bytes.into_vec()) {
                let t = s.trim_matches(|c: char| c.is_whitespace() || c.is_control());
                if t.starts_with("cashu") || t.starts_with("CASHU") || t.starts_with("web+cashu") {
                    return Some(t.to_owned());
                }
            }
        }
        if let Ok(s) = ciborium::from_reader::<String, _>(data) {
            let t = s.trim_matches(|c: char| c.is_whitespace() || c.is_control());
            if t.starts_with("cashu") || t.starts_with("CASHU") || t.starts_with("web+cashu") {
                return Some(t.to_owned());
            }
        }
        if let Ok(s) = std::str::from_utf8(data) {
            let t = s.trim_matches(|c: char| c.is_whitespace() || c.is_control());
            if t.starts_with("cashu") || t.starts_with("CASHU") || t.starts_with("web+cashu") {
                return Some(t.to_owned());
            }
        }
        None
    }

    /// Encode as a V3 `cashuA...` token string.
    pub fn encode_v3(&self) -> Result<String, String> {
        let v3 = TokenV3 {
            token: vec![TokenV3Entry {
                mint: self.mint_url.clone(),
                proofs: self.proofs.clone(),
            }],
            unit: Some(self.unit.clone()),
            memo: self.memo.clone(),
        };
        let json = serde_json::to_vec(&v3).map_err(|e| e.to_string())?;
        Ok(format!("cashuA{}", URL_SAFE_NO_PAD.encode(json)))
    }

    /// Encode as a compact V4 `cashuB...` CBOR token string.
    pub fn encode_v4(&self) -> Result<String, String> {
        let mut by_keyset: Vec<(String, Vec<TokenV4Proof>)> = Vec::new();
        for proof in &self.proofs {
            let c_bytes = hex::decode(&proof.c)
                .map_err(|e| format!("invalid hex in proof C '{}': {e}", proof.c))?;
            let dleq = match &proof.dleq {
                Some(d) => Some(TokenV4Dleq {
                    e: hex::decode(&d.e).map_err(|e| format!("invalid dleq.e: {e}"))?,
                    s: hex::decode(&d.s).map_err(|e| format!("invalid dleq.s: {e}"))?,
                    r: hex::decode(&d.r).map_err(|e| format!("invalid dleq.r: {e}"))?,
                }),
                None => None,
            };
            let v4_proof = TokenV4Proof {
                amount: proof.amount,
                secret: proof.secret.clone(),
                c: c_bytes,
                dleq,
            };
            if let Some((_, list)) = by_keyset.iter_mut().find(|(id, _)| id == &proof.keyset_id) {
                list.push(v4_proof);
            } else {
                by_keyset.push((proof.keyset_id.clone(), vec![v4_proof]));
            }
        }
        let mut tokens = Vec::with_capacity(by_keyset.len());
        for (ks_hex, proofs) in by_keyset {
            let mut keyset_id = hex::decode(&ks_hex)
                .map_err(|e| format!("invalid keyset id hex '{ks_hex}': {e}"))?;
            // NUT-00 V4 (`cashuB`) uses the 8-byte ShortKeysetId (`00` + 7 bytes or `01` + first 7 bytes)
            if keyset_id.len() > 8 {
                keyset_id.truncate(8);
            }
            tokens.push(TokenV4Keyset { keyset_id, proofs });
        }
        let v4 = TokenV4 {
            mint: self.mint_url.clone(),
            unit: self.unit.clone(),
            tokens,
            memo: self.memo.clone(),
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&v4, &mut cbor).map_err(|e| format!("CBOR encode failed: {e}"))?;
        Ok(format!("cashuB{}", URL_SAFE_NO_PAD.encode(cbor)))
    }

    /// Decode either a `cashuA...` or `cashuB...` token (with optional `cashu:` URI prefix).
    pub fn decode(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim_matches(|c: char| c.is_whitespace() || c.is_control());
        let stripped = trimmed
            .strip_prefix("web+cashu://")
            .or_else(|| trimmed.strip_prefix("web+cashu:"))
            .or_else(|| trimmed.strip_prefix("cashu://"))
            .or_else(|| trimmed.strip_prefix("CASHU://"))
            .or_else(|| trimmed.strip_prefix("cashu:"))
            .or_else(|| trimmed.strip_prefix("CASHU:"))
            .unwrap_or(trimmed);

        if let Some(body) = stripped.strip_prefix("cashuA") {
            let bytes = decode_b64_any(body)?;
            let v3: TokenV3 =
                serde_json::from_slice(&bytes).map_err(|e| format!("invalid cashuA JSON: {e}"))?;
            let first = v3
                .token
                .into_iter()
                .next()
                .ok_or_else(|| "cashuA token has no entries".to_owned())?;
            if first.proofs.is_empty() {
                return Err("cashuA token has no proofs".to_owned());
            }
            Ok(Self {
                mint_url: first.mint,
                unit: v3.unit.unwrap_or_else(|| "sat".to_owned()),
                memo: v3.memo,
                proofs: first.proofs,
            })
        } else if let Some(body) = stripped.strip_prefix("cashuB") {
            let bytes = decode_b64_any(body)?;
            let v4: TokenV4 = ciborium::from_reader(bytes.as_slice()).map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("UnexpectedEof") {
                    format!(
                        "Truncated cashuB QR ({} chars / {}B decoded; full token is 200+ chars)",
                        stripped.len(),
                        bytes.len()
                    )
                } else {
                    format!("invalid cashuB CBOR ({}B): {e}", bytes.len())
                }
            })?;
            let mut proofs = Vec::new();
            for group in v4.tokens {
                let keyset_id = hex::encode(&group.keyset_id);
                for p in group.proofs {
                    let dleq = p.dleq.map(|d| ProofDleq {
                        e: hex::encode(d.e),
                        s: hex::encode(d.s),
                        r: hex::encode(d.r),
                    });
                    proofs.push(Proof {
                        amount: p.amount,
                        keyset_id: keyset_id.clone(),
                        secret: p.secret,
                        c: hex::encode(p.c),
                        dleq,
                    });
                }
            }
            if proofs.is_empty() {
                return Err("cashuB token has no proofs".to_owned());
            }
            Ok(Self {
                mint_url: v4.mint,
                unit: v4.unit,
                memo: v4.memo,
                proofs,
            })
        } else {
            Err("token must start with 'cashuA' or 'cashuB'".to_owned())
        }
    }
}
