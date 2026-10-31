//! Wire protocol and Cashu NUT data types for `cashu-vault` on Passport Prime.
//!
//! Covers:
//! - NUT-00 (`Proof`, `BlindedMessage`, `BlindSignature`, `CashuToken`)
//! - NUT-01 / NUT-02 (`KeysetInfo`, `MintKeyPair`)
//! - NUT-03 (`SwapPayload`: Receive, Swap, Send split)
//! - NUT-04 (`MintPayload`: Mint outputs for a quote)
//! - NUT-05 (`MeltPayload`: Melt inputs + blank change outputs for a Lightning quote)
//! - NUT-12 (`DleqProof`, `ProofDleq`)
//! - CBOR `RequestEnvelope` / `ResponseEnvelope` between host/phone relay and Passport Prime.

pub mod token;

pub use token::CashuToken;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;
pub const KEY_SCHEME: &str = "cashu-vault-nut13-v1";

/// NUT-12 DLEQ proof attached to a `BlindSignature` from the mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DleqProof {
    /// 32-byte scalar `e` as 64 lowercase hex characters.
    pub e: String,
    /// 32-byte scalar `s` as 64 lowercase hex characters.
    pub s: String,
}

/// NUT-12 DLEQ proof with blinding factor `r` attached to an unblinded `Proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofDleq {
    pub e: String,
    pub s: String,
    pub r: String,
}

/// NUT-00 unblinded Cashu `Proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub amount: u64,
    #[serde(rename = "id")]
    pub keyset_id: String,
    pub secret: String,
    #[serde(rename = "C")]
    pub c: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dleq: Option<ProofDleq>,
}

/// NUT-00 `BlindedMessage` sent to a mint in Mint (NUT-04), Swap (NUT-03), or Melt (NUT-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedMessage {
    pub amount: u64,
    #[serde(rename = "id")]
    pub keyset_id: String,
    #[serde(rename = "B_")]
    pub b_: String,
}

/// NUT-00 `BlindSignature` returned by a mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindSignature {
    pub amount: u64,
    #[serde(rename = "id")]
    pub keyset_id: String,
    #[serde(rename = "C_")]
    pub c_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dleq: Option<DleqProof>,
}

/// NUT-01 / NUT-02 keyset definition with per-amount compressed secp256k1 public keys (hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetInfo {
    pub id: String,
    pub unit: String,
    pub active: bool,
    pub input_fee_ppk: u64,
    /// Map from denomination (power of two) to 33-byte compressed public key (66 lowercase hex).
    pub keys: BTreeMap<u64, String>,
}

/// NUT-04 mint request payload ready to POST to `/v1/mint/bolt11`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintRequestPayload {
    pub op_id: String,
    pub mint_url: String,
    pub quote_id: String,
    pub amount: u64,
    pub outputs: Vec<BlindedMessage>,
}

/// NUT-03 swap request payload ready to POST to `/v1/swap`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapRequestPayload {
    pub op_id: String,
    pub mint_url: String,
    pub inputs: Vec<Proof>,
    pub outputs: Vec<BlindedMessage>,
    pub fee: u64,
}

/// NUT-05 melt request payload ready to POST to `/v1/melt/bolt11`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeltRequestPayload {
    pub op_id: String,
    pub mint_url: String,
    pub quote_id: String,
    pub invoice: String,
    pub amount: u64,
    pub fee_reserve: u64,
    pub input_fee: u64,
    pub inputs: Vec<Proof>,
    /// Blank outputs (`amount = 0` or power-of-two placeholders) for fee overestimation change.
    pub outputs: Vec<BlindedMessage>,
}

/// Summary of a configured mint stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintSummary {
    pub url: String,
    pub active_keyset_id: String,
    pub unit: String,
    pub balance_sats: u64,
    pub proof_count: usize,
}

/// Summary of the vault's status and balances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInfo {
    pub protocol_version: u8,
    pub key_scheme: String,
    pub total_balance_sats: u64,
    pub total_proofs: usize,
    pub mints: Vec<MintSummary>,
    pub pending_op: Option<String>,
}

/// A key-value row displayed on Passport Prime's trusted review screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRow {
    pub label: String,
    pub value: String,
}

/// Structured review screen shown on Passport Prime before approving an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewScreen {
    pub title: String,
    pub amount: String,
    pub rows: Vec<ReviewRow>,
    pub warnings: Vec<String>,
    pub require_pin: bool,
}

/// Request sent to `cashu-vault` (over QR/UR, simulator file bridge, or TCP link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub version: u8,
    pub request_id: u64,
    pub request: VaultRequest,
}

/// Operations supported by `cashu-vault`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultRequest {
    /// Query vault status, balances, and configured mints.
    GetInfo,
    /// Poll the result of a previously submitted request that required on-device approval.
    GetResult { request_id: u64 },
    /// Register or update a Cashu mint and its keyset (verified against NUT-02).
    AddMint {
        mint_url: String,
        keyset: KeysetInfo,
    },
    /// Remove a Cashu mint (and any stored proofs for it) from the vault.
    RemoveMint { mint_url: String },
    /// NUT-04 Mint: prepare deterministic blinded outputs on-device for a paid quote.
    PrepareMint {
        mint_url: String,
        quote_id: String,
        amount: u64,
    },
    /// NUT-04 Mint completion: unblind the mint's `BlindSignature`s, verify DLEQ, and store `Proof`s.
    CompleteMint {
        op_id: String,
        signatures: Vec<BlindSignature>,
    },
    /// NUT-03 Receive: decode a `cashuA`/`cashuB` token and prepare a Swap into fresh vault outputs.
    PrepareReceive { token: String },
    /// NUT-03 Swap: consolidate or split existing vault proofs into fresh blinded outputs.
    PrepareSwap {
        mint_url: String,
        /// Optional target amount to isolate as an exact proof subset; `None` consolidates all proofs.
        target_amount: Option<u64>,
    },
    /// NUT-03 Receive / Swap completion: unblind the mint's `BlindSignature`s and update vault proofs.
    CompleteSwap {
        op_id: String,
        signatures: Vec<BlindSignature>,
    },
    /// Send Cashu token: select exact vault proofs for `amount` and export a `cashuB` + `cashuA` token.
    SendToken {
        mint_url: String,
        amount: u64,
        memo: Option<String>,
    },
    /// NUT-05 Melt: verify invoice & quote, select input proofs, and prepare blank change outputs.
    PrepareMelt {
        mint_url: String,
        quote_id: String,
        invoice: String,
        amount: u64,
        fee_reserve: u64,
    },
    /// NUT-05 Melt completion: mark inputs spent and unblind any returned change `BlindSignature`s.
    CompleteMelt {
        op_id: String,
        paid: bool,
        change: Vec<BlindSignature>,
    },
}

/// Rejection reasons returned when a request cannot be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectCode {
    Malformed,
    UnsupportedVersion,
    Busy,
    NotFound,
    InvalidMint,
    InvalidKeyset,
    InsufficientFunds,
    ExactChangeRequired,
    InvalidToken,
    InvalidInvoice,
    InvalidSignature,
    UserDeclined,
    InternalError,
}

/// Response returned by `cashu-vault`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub version: u8,
    pub request_id: u64,
    pub response: VaultResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultResponse {
    /// Vault status and mint balances.
    Info(VaultInfo),
    /// The request is waiting on Passport Prime's screen for the user to approve or reject.
    PendingApproval { review_title: String },
    /// Mint added and keyset pinned.
    MintAdded {
        mint_url: String,
        keyset_id: String,
    },
    /// Mint removed from the vault.
    MintRemoved { mint_url: String },
    /// Blinded outputs ready for NUT-04 `/v1/mint/bolt11`.
    MintPrepared(MintRequestPayload),
    /// Proofs unblinded and added to the vault.
    MintCompleted {
        mint_url: String,
        added_sats: u64,
        new_balance_sats: u64,
    },
    /// Inputs and blinded outputs ready for NUT-03 `/v1/swap` (used by both Receive and Swap).
    SwapPrepared(SwapRequestPayload),
    /// Swap or Receive completed; new proofs unblinded and stored in the vault.
    SwapCompleted {
        mint_url: String,
        net_sats: u64,
        new_balance_sats: u64,
    },
    /// Spendable Cashu token exported from the vault.
    TokenSent {
        mint_url: String,
        amount: u64,
        token_v4: String,
        token_v3: String,
        new_balance_sats: u64,
    },
    /// Inputs and blank change outputs ready for NUT-05 `/v1/melt/bolt11`.
    MeltPrepared(MeltRequestPayload),
    /// Melt finalized (inputs spent or rolled back if unpaid, change unblinded).
    MeltCompleted {
        mint_url: String,
        paid: bool,
        change_sats: u64,
        new_balance_sats: u64,
    },
    /// Error / rejection response.
    Rejected {
        code: RejectCode,
        message: String,
    },
}

impl RequestEnvelope {
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| format!("CBOR encode failed: {e}"))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|e| format!("CBOR decode failed: {e}"))
    }
}

impl ResponseEnvelope {
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| format!("CBOR encode failed: {e}"))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|e| format!("CBOR decode failed: {e}"))
    }
}

#[derive(Serialize)]
struct Nut03SwapHttpRequest<'a> {
    inputs: &'a [Proof],
    outputs: &'a [BlindedMessage],
}

#[derive(Deserialize)]
struct SignaturesHttpResponse {
    signatures: Vec<BlindSignature>,
}

/// Encode a NUT-03 `/v1/swap` HTTP request body as JSON.
pub fn encode_swap_http_request(
    inputs: &[Proof],
    outputs: &[BlindedMessage],
) -> Result<String, String> {
    serde_json::to_string(&Nut03SwapHttpRequest { inputs, outputs })
        .map_err(|e| format!("failed to encode swap request JSON: {e}"))
}

/// Decode a NUT-03 `/v1/swap` HTTP response body from JSON.
pub fn decode_signatures_http_response(bytes: &[u8]) -> Result<Vec<BlindSignature>, String> {
    let resp: SignaturesHttpResponse = serde_json::from_slice(bytes).map_err(|e| {
        let body = String::from_utf8_lossy(bytes);
        format!("swap response error ({e}): {body}")
    })?;
    Ok(resp.signatures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_v3_and_v4_roundtrip() {
        let token = CashuToken {
            mint_url: "https://mint.example.com".to_owned(),
            unit: "sat".to_owned(),
            memo: Some("coffee".to_owned()),
            proofs: vec![
                Proof {
                    amount: 8,
                    keyset_id: "009a1f293253e41e".to_owned(),
                    secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                    c: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                        .to_owned(),
                    dleq: Some(ProofDleq {
                        e: "11".repeat(32),
                        s: "22".repeat(32),
                        r: "33".repeat(32),
                    }),
                },
                Proof {
                    amount: 2,
                    keyset_id: "009a1f293253e41e".to_owned(),
                    secret: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                        .to_owned(),
                    c: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
                        .to_owned(),
                    dleq: None,
                },
            ],
        };

        let v3 = token.encode_v3().expect("encode v3");
        assert!(v3.starts_with("cashuA"));
        let decoded_v3 = CashuToken::decode(&v3).expect("decode v3");
        assert_eq!(decoded_v3, token);

        let v4 = token.encode_v4().expect("encode v4");
        assert!(v4.starts_with("cashuB"));
        let decoded_v4 = CashuToken::decode(&v4).expect("decode v4");
        assert_eq!(decoded_v4, token);
        assert_eq!(decoded_v4.total_amount(), 10);

        // Verify URL-safe base64 with '_', trailing NUL byte '\0', padding '=', and URI prefixes decode cleanly
        assert!(v4.contains('_') || v4.contains('-'));
        let with_nul_and_pad = format!("cashu:{v4}==\0\0\n");
        let decoded_quirky = CashuToken::decode(&with_nul_and_pad).expect("decode quirky v4");
        assert_eq!(decoded_quirky, token);

        // Verify standard base64 ('+' and '/') also decodes cleanly
        let std_b64 = format!(
            "cashuB{}",
            v4.strip_prefix("cashuB")
                .unwrap()
                .replace('-', "+")
                .replace('_', "/")
        );
        let decoded_std = CashuToken::decode(&std_b64).expect("decode standard b64 v4");
        assert_eq!(decoded_std, token);
    }

    #[test]
    fn request_response_cbor_roundtrip() {
        let req = RequestEnvelope {
            version: PROTOCOL_VERSION,
            request_id: 42,
            request: VaultRequest::PrepareMint {
                mint_url: "https://mint.example.com".to_owned(),
                quote_id: "q-123".to_owned(),
                amount: 64,
            },
        };
        let bytes = req.to_cbor().expect("encode");
        let decoded = RequestEnvelope::from_cbor(&bytes).expect("decode");
        assert_eq!(decoded, req);
    }
}
