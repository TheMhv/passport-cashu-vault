//! Stateful Cashu Vault service for Passport Prime.
//!
//! Manages:
//! - Trusted mints and NUT-02 verified keysets
//! - NUT-13 deterministic counters and write-ahead pending operations
//! - Unblinded `Proof` storage in KeyOS `AppData`
//! - Trusted display review screens and PIN policy enforcement
//! - All 5 Cashu flows: Mint (NUT-04), Receive (NUT-03), Swap (NUT-03), Send (NUT-00), and Melt (NUT-05)

use std::collections::BTreeMap;

use cashu_vault_core::{
    blank_output_count, canonical_mint_url, compute_input_fee, derive_blinded_output,
    parse_and_verify_keyset, select_exact_proofs, select_proofs_covering, split_amount,
    unblind_to_proof, verify_proof_dleq, MockMint,
};
use cashu_vault_protocol::{
    BlindSignature, CashuToken, KeysetInfo, MeltRequestPayload, MintRequestPayload, MintSummary,
    Proof, RejectCode, RequestEnvelope, ResponseEnvelope, ReviewRow, ReviewScreen,
    SwapRequestPayload, VaultInfo, VaultRequest, VaultResponse, KEY_SCHEME, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const STATE_VERSION: u8 = 1;
pub const DEMO_MINT_URL: &str = "https://demo.cashu.vault";
const DEMO_MINT_SEED: [u8; 32] = [0xA5; 32];
const MAX_CACHED_RESULTS: usize = 12;
const MAX_HISTORY_ITEMS: usize = 20;

/// Platform hooks provided by Passport Prime or the simulator.
pub trait Platform {
    fn random_32(&mut self) -> [u8; 32];
    fn now_unix(&self) -> Option<u64>;
}

/// Durable storage hook (`os/fs` `AppData` on KeyOS, or in-memory for tests).
pub trait Storage {
    fn load(&mut self) -> Result<Option<Vec<u8>>, String>;
    fn store(&mut self, bytes: &[u8]) -> Result<(), String>;
}

/// User-configurable security policy on Passport Prime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPolicy {
    /// Require PIN for any send or melt at or above this amount in sats.
    pub pin_threshold_sats: u64,
    /// Require PIN for every send or melt regardless of amount.
    pub require_pin_always: bool,
    /// Require NUT-12 DLEQ verification on all incoming mint/swap signatures.
    pub verify_dleq: bool,
    /// Enable offline Demo Mint mode on device for standalone interactive testing.
    pub demo_mode: bool,
}

impl Default for VaultPolicy {
    fn default() -> Self {
        Self {
            pin_threshold_sats: 500,
            require_pin_always: false,
            verify_dleq: true,
            demo_mode: true,
        }
    }
}

/// A recorded activity item for the Vault UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub kind: String,
    pub amount_sats: u64,
    pub mint_url: String,
    pub summary: String,
}

/// Stored per-mint state in `cashu-vault-state.cbor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMint {
    pub url: String,
    pub active_keyset_id: String,
    pub keysets: BTreeMap<String, KeysetInfo>,
    /// Next NUT-13 deterministic counter per keyset ID.
    pub counters: BTreeMap<String, u32>,
    /// Unspent Cashu proofs held in the vault for this mint.
    pub proofs: Vec<Proof>,
}

impl StoredMint {
    pub fn balance_sats(&self) -> u64 {
        self.proofs.iter().map(|p| p.amount).sum()
    }

    pub fn next_counter(&self, keyset_id: &str) -> u32 {
        self.counters.get(keyset_id).copied().unwrap_or(0)
    }
}

/// Write-ahead record of a blinded output waiting for a `BlindSignature` from the mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOutputSpec {
    pub keyset_id: String,
    pub counter: u32,
    pub amount: u64,
}

/// An in-flight two-step operation (`Prepare*` -> `Complete*`) persisted across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingVaultOp {
    Mint {
        op_id: String,
        mint_url: String,
        quote_id: String,
        amount: u64,
        outputs: Vec<PendingOutputSpec>,
    },
    Swap {
        op_id: String,
        mint_url: String,
        is_receive: bool,
        input_secrets: Vec<String>,
        net_amount: u64,
        outputs: Vec<PendingOutputSpec>,
    },
    Melt {
        op_id: String,
        mint_url: String,
        quote_id: String,
        amount: u64,
        fee_reserve: u64,
        input_fee: u64,
        input_secrets: Vec<String>,
        blank_outputs: Vec<PendingOutputSpec>,
    },
}

impl PendingVaultOp {
    pub fn op_id(&self) -> &str {
        match self {
            Self::Mint { op_id, .. } | Self::Swap { op_id, .. } | Self::Melt { op_id, .. } => op_id,
        }
    }

    pub fn description(&self) -> String {
        match self {
            Self::Mint { amount, .. } => format!("Mint {amount} sat awaiting signatures"),
            Self::Swap {
                is_receive: true,
                net_amount,
                ..
            } => format!("Receive {net_amount} sat awaiting signatures"),
            Self::Swap {
                is_receive: false,
                net_amount,
                ..
            } => format!("Swap {net_amount} sat awaiting signatures"),
            Self::Melt { amount, .. } => format!("Melt {amount} sat awaiting settlement"),
        }
    }
}

/// Top-level durable CBOR state stored in `cashu-vault-state.cbor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultState {
    pub version: u8,
    pub mints: BTreeMap<String, StoredMint>,
    pub pending_op: Option<PendingVaultOp>,
    pub policy: VaultPolicy,
    pub history: Vec<HistoryEntry>,
    pub next_op_seq: u64,
    #[serde(default)]
    pub completed_results: Vec<(u64, ResponseEnvelope)>,
    #[serde(default)]
    pub keyset_counters: BTreeMap<String, u32>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            mints: BTreeMap::new(),
            pending_op: None,
            policy: VaultPolicy::default(),
            history: Vec::new(),
            next_op_seq: 1,
            completed_results: Vec::new(),
            keyset_counters: BTreeMap::new(),
        }
    }
}

/// A pending request waiting on Passport Prime's screen for the user to tap Approve or Reject.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub request_id: u64,
    pub request: VaultRequest,
    pub review: ReviewScreen,
    /// Whether this request was initiated interactively on device (so demo mode can auto-complete).
    pub interactive_demo_complete: bool,
}

/// Outcome of handling a `RequestEnvelope` or interactive request.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ServiceOutcome {
    /// Immediate CBOR reply (no user confirmation needed).
    Reply(Vec<u8>),
    /// Review screen must be shown on Passport Prime.
    NeedsApproval(PendingApproval),
}

/// Result of approving a `PendingApproval` on Passport Prime.
#[derive(Debug, Clone)]
pub struct ApprovedOutcome {
    pub reply_bytes: Vec<u8>,
    pub response: VaultResponse,
    /// Spendable `cashuB...` token string to display as a QR code on screen (for Send).
    pub show_token_qr: Option< Zeroizing<String> >,
    /// Notice text for the home screen.
    pub notice: String,
}

/// The stateful Cashu Vault service.
pub struct VaultService<S, P> {
    app_seed: Zeroizing<[u8; 32]>,
    storage: S,
    platform: P,
    state: VaultState,
    waiting: Option<PendingApproval>,
    demo_mint: MockMint,
}

impl<S: Storage, P: Platform> VaultService<S, P> {
    /// Open or initialize the vault from durable storage.
    pub fn open(app_seed: [u8; 32], mut storage: S, platform: P) -> Result<Self, String> {
        let state = match storage.load()? {
            Some(bytes) => {
                let loaded: VaultState = ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| format!("corrupt vault state CBOR: {e}"))?;
                if loaded.version != STATE_VERSION {
                    return Err(format!(
                        "unsupported vault state version {} (expected {STATE_VERSION})",
                        loaded.version
                    ));
                }
                loaded
            }
            None => VaultState::default(),
        };

        let demo_mint = MockMint::new(&DEMO_MINT_SEED, DEMO_MINT_URL, 0);
        let mut svc = Self {
            app_seed: Zeroizing::new(app_seed),
            storage,
            platform,
            state,
            waiting: None,
            demo_mint,
        };
        if svc.state.mints.is_empty() && svc.state.policy.demo_mode {
            svc.register_demo_mint_internal()?;
        }
        Ok(svc)
    }

    fn save(&mut self) -> Result<(), String> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&self.state, &mut bytes)
            .map_err(|e| format!("encoding vault state failed: {e}"))?;
        self.storage.store(&bytes)
    }

    fn record_history(&mut self, kind: &str, amount_sats: u64, mint_url: &str, summary: String) {
        self.state.history.insert(
            0,
            HistoryEntry {
                kind: kind.to_owned(),
                amount_sats,
                mint_url: mint_url.to_owned(),
                summary,
            },
        );
        if self.state.history.len() > MAX_HISTORY_ITEMS {
            self.state.history.truncate(MAX_HISTORY_ITEMS);
        }
    }

    fn cache_result(&mut self, request_id: u64, env: ResponseEnvelope) {
        self.state.completed_results.retain(|(id, _)| *id != request_id);
        self.state.completed_results.push((request_id, env));
        if self.state.completed_results.len() > MAX_CACHED_RESULTS {
            self.state.completed_results.remove(0);
        }
    }

    fn next_op_id(&mut self, prefix: &str) -> String {
        let seq = self.state.next_op_seq;
        self.state.next_op_seq = seq.saturating_add(1);
        let rand = self.platform.random_32();
        format!("{prefix}-{seq}-{}", hex::encode(&rand[..4]))
    }

    pub fn register_demo_mint_internal(&mut self) -> Result<(), String> {
        let ks = self.demo_mint.keyset_info();
        let mut keysets = BTreeMap::new();
        keysets.insert(ks.id.clone(), ks.clone());
        self.state.mints.entry(DEMO_MINT_URL.to_owned()).or_insert(StoredMint {
            url: DEMO_MINT_URL.to_owned(),
            active_keyset_id: ks.id,
            keysets,
            counters: BTreeMap::new(),
            proofs: Vec::new(),
        });
        self.save()
    }

    pub fn demo_mint_mut(&mut self) -> &mut MockMint {
        &mut self.demo_mint
    }

    pub fn policy(&self) -> &VaultPolicy {
        &self.state.policy
    }

    pub fn set_policy(&mut self, policy: VaultPolicy) -> Result<(), String> {
        let enable_demo = policy.demo_mode;
        self.state.policy = policy;
        if enable_demo && !self.state.mints.contains_key(DEMO_MINT_URL) {
            self.register_demo_mint_internal()?;
        } else if !enable_demo {
            self.state.mints.remove(DEMO_MINT_URL);
            self.save()?;
        } else {
            self.save()?;
        }
        Ok(())
    }

    /// Remove a mint directly (used by the Settings UI two-tap Forget button).
    pub fn remove_mint(&mut self, mint_url: &str) -> Result<(), String> {
        let url = canonical_mint_url(mint_url)?;
        let Some(removed) = self.state.mints.remove(&url) else {
            return Err(format!("mint '{url}' is not in the vault"));
        };
        for (ks_id, c) in removed.counters {
            let entry = self.state.keyset_counters.entry(ks_id).or_insert(0);
            *entry = (*entry).max(c);
        }
        if url == DEMO_MINT_URL {
            self.state.policy.demo_mode = false;
        }
        self.record_history("RemoveMint", 0, &url, format!("Removed mint {url}"));
        self.save()
    }

    pub fn history(&self) -> &[HistoryEntry] {
        &self.state.history
    }

    pub fn pending_approval(&self) -> Option<&PendingApproval> {
        self.waiting.as_ref()
    }

    pub fn info(&self) -> VaultInfo {
        let mut total_balance_sats = 0u64;
        let mut total_proofs = 0usize;
        let mut mints = Vec::new();
        for m in self.state.mints.values() {
            let bal = m.balance_sats();
            total_balance_sats += bal;
            total_proofs += m.proofs.len();
            mints.push(MintSummary {
                url: m.url.clone(),
                active_keyset_id: m.active_keyset_id.clone(),
                unit: "sat".to_owned(),
                balance_sats: bal,
                proof_count: m.proofs.len(),
            });
        }
        VaultInfo {
            protocol_version: PROTOCOL_VERSION,
            key_scheme: KEY_SCHEME.to_owned(),
            total_balance_sats,
            total_proofs,
            mints,
            pending_op: self.state.pending_op.as_ref().map(|op| op.description()),
        }
    }

    /// Mint a fresh external `cashuB` token from the built-in Demo Mint so the user can test
    /// scanning/receiving external tokens on-device or in simulator tests.
    pub fn create_demo_incoming_token(&mut self, amount: u64) -> Result<String, String> {
        let parts = split_amount(amount);
        if parts.is_empty() {
            return Err("amount must be > 0".to_owned());
        }
        let ks_info = self.demo_mint.keyset_info();
        let pubkeys = parse_and_verify_keyset(&ks_info)?;
        let external_seed = self.platform.random_32();
        let mut proofs = Vec::with_capacity(parts.len());
        for (idx, amt) in parts.into_iter().enumerate() {
            let derived = derive_blinded_output(&external_seed, &ks_info.id, idx as u32, amt)?;
            let sig = self.demo_mint.sign_blinded(&derived.blinded)?;
            let pk = pubkeys.get(&amt).ok_or("missing denomination key")?;
            let proof = unblind_to_proof(&sig, &derived.secret, &derived.r, pk)?;
            proofs.push(proof);
        }
        let token = CashuToken {
            mint_url: DEMO_MINT_URL.to_owned(),
            unit: "sat".to_owned(),
            memo: Some("Demo incoming token".to_owned()),
            proofs,
        };
        token.encode_v4()
    }

    fn reply_bytes(request_id: u64, response: VaultResponse) -> Vec<u8> {
        ResponseEnvelope {
            version: PROTOCOL_VERSION,
            request_id,
            response,
        }
        .to_cbor()
        .expect("ResponseEnvelope CBOR serialization never fails")
    }

    fn reject_bytes(request_id: u64, code: RejectCode, message: impl Into<String>) -> Vec<u8> {
        Self::reply_bytes(
            request_id,
            VaultResponse::Rejected {
                code,
                message: message.into(),
            },
        )
    }

    /// Handle raw CBOR request bytes from QR/UR, File Bridge, or TCP Link.
    pub fn handle(&mut self, raw: &[u8]) -> ServiceOutcome {
        let env = match RequestEnvelope::from_cbor(raw) {
            Ok(env) => env,
            Err(e) => {
                return ServiceOutcome::Reply(Self::reject_bytes(
                    0,
                    RejectCode::Malformed,
                    format!("malformed CBOR request: {e}"),
                ))
            }
        };
        if env.version != PROTOCOL_VERSION {
            return ServiceOutcome::Reply(Self::reject_bytes(
                env.request_id,
                RejectCode::UnsupportedVersion,
                format!("unsupported protocol version {}", env.version),
            ));
        }
        self.handle_envelope(env, false)
    }

    /// Start an interactive operation directly from Passport Prime's touchscreen UI.
    pub fn start_interactive(&mut self, request: VaultRequest) -> Result<PendingApproval, String> {
        let req_id = self.state.next_op_seq;
        self.state.next_op_seq = req_id.saturating_add(1);
        let env = RequestEnvelope {
            version: PROTOCOL_VERSION,
            request_id: req_id,
            request,
        };
        match self.handle_envelope(env, true) {
            ServiceOutcome::NeedsApproval(pending) => Ok(pending),
            ServiceOutcome::Reply(bytes) => {
                let resp = ResponseEnvelope::from_cbor(&bytes)?;
                match resp.response {
                    VaultResponse::Rejected { message, .. } => Err(message),
                    other => Err(format!("unexpected immediate response: {other:?}")),
                }
            }
        }
    }

    pub fn handle_envelope(
        &mut self,
        env: RequestEnvelope,
        interactive_demo: bool,
    ) -> ServiceOutcome {
        let req_id = env.request_id;

        // Replay cached result if already completed
        if let Some((_, cached)) = self
            .state
            .completed_results
            .iter()
            .find(|(id, _)| *id == req_id)
        {
            return ServiceOutcome::Reply(cached.to_cbor().expect("cached CBOR"));
        }

        match env.request {
            VaultRequest::GetInfo => {
                ServiceOutcome::Reply(Self::reply_bytes(req_id, VaultResponse::Info(self.info())))
            }
            VaultRequest::GetResult { request_id } => {
                if let Some((_, cached)) = self
                    .state
                    .completed_results
                    .iter()
                    .find(|(id, _)| *id == request_id)
                {
                    return ServiceOutcome::Reply(cached.to_cbor().expect("cached CBOR"));
                }
                if let Some(waiting) = &self.waiting {
                    if waiting.request_id == request_id {
                        return ServiceOutcome::Reply(Self::reply_bytes(
                            req_id,
                            VaultResponse::PendingApproval {
                                review_title: waiting.review.title.clone(),
                            },
                        ));
                    }
                }
                ServiceOutcome::Reply(Self::reject_bytes(
                    req_id,
                    RejectCode::NotFound,
                    format!("no result found for request {request_id}"),
                ))
            }
            VaultRequest::CompleteMint { op_id, signatures } => {
                let resp = match self.complete_mint(&op_id, &signatures) {
                    Ok(r) => r,
                    Err((code, msg)) => VaultResponse::Rejected { code, message: msg },
                };
                ServiceOutcome::Reply(Self::reply_bytes(req_id, resp))
            }
            VaultRequest::CompleteSwap { op_id, signatures } => {
                let resp = match self.complete_swap(&op_id, &signatures) {
                    Ok(r) => r,
                    Err((code, msg)) => VaultResponse::Rejected { code, message: msg },
                };
                ServiceOutcome::Reply(Self::reply_bytes(req_id, resp))
            }
            VaultRequest::CompleteMelt {
                op_id,
                paid,
                change,
            } => {
                let resp = match self.complete_melt(&op_id, paid, &change) {
                    Ok(r) => r,
                    Err((code, msg)) => VaultResponse::Rejected { code, message: msg },
                };
                ServiceOutcome::Reply(Self::reply_bytes(req_id, resp))
            }
            other => {
                if self.waiting.is_some() {
                    return ServiceOutcome::Reply(Self::reject_bytes(
                        req_id,
                        RejectCode::Busy,
                        "another review is currently on Passport Prime's screen",
                    ));
                }
                // If retrying PrepareMint for the exact same already-approved (mint_url, quote_id, amount)
                // after a NUT-13 counter collision on the mint, jump the counter and reply immediately
                // without prompting on screen a second time.
                if !interactive_demo {
                    if let (
                        VaultRequest::PrepareMint {
                            mint_url,
                            quote_id,
                            amount,
                        },
                        Some(PendingVaultOp::Mint {
                            mint_url: prev_url,
                            quote_id: prev_quote,
                            amount: prev_amt,
                            ..
                        }),
                    ) = (&other, &self.state.pending_op)
                    {
                        if let Ok(url) = canonical_mint_url(mint_url) {
                            if &url == prev_url && quote_id == prev_quote && amount == prev_amt {
                                if let Some(mint) = self.state.mints.get_mut(&url) {
                                    let ks_id = mint.active_keyset_id.clone();
                                    let bumped = mint.next_counter(&ks_id).saturating_add(16);
                                    mint.counters.insert(ks_id.clone(), bumped);
                                    self.state.keyset_counters.insert(ks_id, bumped);
                                }
                                match self.execute_approved(&other, false) {
                                    Ok((response, _, _)) => {
                                        let env = ResponseEnvelope {
                                            version: PROTOCOL_VERSION,
                                            request_id: req_id,
                                            response,
                                        };
                                        let bytes = env.to_cbor().expect("CBOR encode");
                                        self.cache_result(req_id, env);
                                        let _ = self.save();
                                        return ServiceOutcome::Reply(bytes);
                                    }
                                    Err(msg) => {
                                        return ServiceOutcome::Reply(Self::reject_bytes(
                                            req_id,
                                            RejectCode::InternalError,
                                            msg,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                match self.build_review(&other) {
                    Ok(review) => {
                        let pending = PendingApproval {
                            request_id: req_id,
                            request: other,
                            review,
                            interactive_demo_complete: interactive_demo,
                        };
                        self.waiting = Some(pending.clone());
                        ServiceOutcome::NeedsApproval(pending)
                    }
                    Err((code, msg)) => ServiceOutcome::Reply(Self::reject_bytes(req_id, code, msg)),
                }
            }
        }
    }

    fn requires_pin(&self, outflow_sats: u64) -> bool {
        if self.state.policy.require_pin_always {
            return true;
        }
        outflow_sats >= self.state.policy.pin_threshold_sats
    }

    fn build_review(&self, req: &VaultRequest) -> Result<ReviewScreen, (RejectCode, String)> {
        match req {
            VaultRequest::AddMint { mint_url, keyset } => {
                let url = canonical_mint_url(mint_url)
                    .map_err(|e| (RejectCode::InvalidMint, e))?;
                parse_and_verify_keyset(keyset)
                    .map_err(|e| (RejectCode::InvalidKeyset, e))?;
                let is_update = self.state.mints.contains_key(&url);
                Ok(ReviewScreen {
                    title: if is_update {
                        "Update Cashu Mint".to_owned()
                    } else {
                        "Add Cashu Mint".to_owned()
                    },
                    amount: format!("{} denominations", keyset.keys.len()),
                    rows: vec![
                        ReviewRow {
                            label: "Mint URL".to_owned(),
                            value: url,
                        },
                        ReviewRow {
                            label: "Keyset ID".to_owned(),
                            value: keyset.id.clone(),
                        },
                        ReviewRow {
                            label: "Input fee".to_owned(),
                            value: format!("{} ppk", keyset.input_fee_ppk),
                        },
                    ],
                    warnings: vec![
                        "Mint keys are pinned on trust-on-first-use.".to_owned(),
                    ],
                    require_pin: false,
                })
            }
            VaultRequest::RemoveMint { mint_url } => {
                let url = canonical_mint_url(mint_url)
                    .map_err(|e| (RejectCode::InvalidMint, e))?;
                let mint = self.state.mints.get(&url).ok_or_else(|| {
                    (
                        RejectCode::InvalidMint,
                        format!("mint '{url}' is not in the vault"),
                    )
                })?;
                let bal = mint.balance_sats();
                let mut warnings = Vec::new();
                if bal > 0 {
                    warnings.push(format!(
                        "This mint still holds {bal} sat ({} proofs) in the vault!",
                        mint.proofs.len()
                    ));
                }
                Ok(ReviewScreen {
                    title: "Remove Cashu Mint".to_owned(),
                    amount: format!("{bal} sat"),
                    rows: vec![
                        ReviewRow {
                            label: "Mint URL".to_owned(),
                            value: url,
                        },
                        ReviewRow {
                            label: "Stored proofs".to_owned(),
                            value: format!("{} proofs ({bal} sat)", mint.proofs.len()),
                        },
                    ],
                    warnings,
                    require_pin: bal > 0 && self.requires_pin(bal),
                })
            }
            VaultRequest::PrepareMint {
                mint_url,
                quote_id,
                amount,
            } => {
                if *amount == 0 {
                    return Err((
                        RejectCode::Malformed,
                        "mint amount must be greater than zero".to_owned(),
                    ));
                }
                let url = canonical_mint_url(mint_url)
                    .map_err(|e| (RejectCode::InvalidMint, e))?;
                let mint = self.state.mints.get(&url).ok_or_else(|| {
                    (
                        RejectCode::InvalidMint,
                        format!("mint '{url}' is not registered in vault"),
                    )
                })?;
                let parts = split_amount(*amount);
                Ok(ReviewScreen {
                    title: "Mint Cashu Tokens".to_owned(),
                    amount: format!("+{amount} sat"),
                    rows: vec![
                        ReviewRow {
                            label: "Mint".to_owned(),
                            value: url,
                        },
                        ReviewRow {
                            label: "Quote ID".to_owned(),
                            value: quote_id.clone(),
                        },
                        ReviewRow {
                            label: "Keyset".to_owned(),
                            value: mint.active_keyset_id.clone(),
                        },
                        ReviewRow {
                            label: "Blinded notes".to_owned(),
                            value: format!("{} notes (NUT-13)", parts.len()),
                        },
                    ],
                    warnings: Vec::new(),
                    require_pin: false,
                })
            }
            VaultRequest::PrepareReceive { token } => {
                let decoded = CashuToken::decode(token)
                    .map_err(|e| (RejectCode::InvalidToken, e))?;
                let url = canonical_mint_url(&decoded.mint_url)
                    .map_err(|e| (RejectCode::InvalidMint, e))?;
                let mint = self.state.mints.get(&url).ok_or_else(|| {
                    (
                        RejectCode::InvalidMint,
                        format!("token mint '{url}' is not registered in vault"),
                    )
                })?;
                let ks = mint
                    .keysets
                    .get(&mint.active_keyset_id)
                    .ok_or_else(|| (RejectCode::InvalidKeyset, "missing active keyset".to_owned()))?;
                let total = decoded.total_amount();
                let fee = compute_input_fee(decoded.proofs.len(), ks.input_fee_ppk);
                if total <= fee {
                    return Err((
                        RejectCode::InsufficientFunds,
                        format!("token amount ({total} sat) does not cover swap fee ({fee} sat)"),
                    ));
                }
                let net = total - fee;
                let mut rows = vec![
                    ReviewRow {
                        label: "Mint".to_owned(),
                        value: url,
                    },
                    ReviewRow {
                        label: "Token proofs".to_owned(),
                        value: format!("{} proofs ({total} sat)", decoded.proofs.len()),
                    },
                    ReviewRow {
                        label: "Swap fee".to_owned(),
                        value: format!("{fee} sat"),
                    },
                    ReviewRow {
                        label: "Net received".to_owned(),
                        value: format!("{net} sat"),
                    },
                ];
                if let Some(memo) = &decoded.memo {
                    if !memo.is_empty() {
                        rows.push(ReviewRow {
                            label: "Memo".to_owned(),
                            value: memo.clone(),
                        });
                    }
                }
                Ok(ReviewScreen {
                    title: "Receive Cashu Token".to_owned(),
                    amount: format!("+{net} sat"),
                    rows,
                    warnings: Vec::new(),
                    require_pin: false,
                })
            }
            VaultRequest::PrepareSwap {
                mint_url,
                target_amount,
            } => {
                let url = canonical_mint_url(mint_url)
                    .map_err(|e| (RejectCode::InvalidMint, e))?;
                let mint = self.state.mints.get(&url).ok_or_else(|| {
                    (
                        RejectCode::InvalidMint,
                        format!("mint '{url}' is not registered"),
                    )
                })?;
                if mint.proofs.is_empty() {
                    return Err((
                        RejectCode::InsufficientFunds,
                        "vault holds no proofs for this mint".to_owned(),
                    ));
                }
                let ks = mint
                    .keysets
                    .get(&mint.active_keyset_id)
                    .ok_or_else(|| (RejectCode::InvalidKeyset, "missing active keyset".to_owned()))?;

                let (selected_indices, in_sum, fee) = match target_amount {
                    Some(target) => {
                        if *target == 0 {
                            return Err((
                                RejectCode::Malformed,
                                "swap target amount must be > 0".to_owned(),
                            ));
                        }
                        select_proofs_covering(&mint.proofs, *target, ks.input_fee_ppk).ok_or_else(
                            || {
                                (
                                    RejectCode::InsufficientFunds,
                                    format!(
                                        "insufficient balance ({}) for swap target {target} sat + fee",
                                        mint.balance_sats()
                                    ),
                                )
                            },
                        )?
                    }
                    None => {
                        let all: Vec<usize> = (0..mint.proofs.len()).collect();
                        let sum = mint.balance_sats();
                        let f = compute_input_fee(all.len(), ks.input_fee_ppk);
                        if sum <= f {
                            return Err((
                                RejectCode::InsufficientFunds,
                                "balance does not cover consolidation swap fee".to_owned(),
                            ));
                        }
                        (all, sum, f)
                    }
                };
                let net = in_sum - fee;
                let mode_str = match target_amount {
                    Some(t) => format!("Split for {t} sat (+ {} sat change)", net - t),
                    None => format!("Consolidate {} proofs", selected_indices.len()),
                };
                Ok(ReviewScreen {
                    title: "Swap Cashu Proofs".to_owned(),
                    amount: format!("{net} sat"),
                    rows: vec![
                        ReviewRow {
                            label: "Mint".to_owned(),
                            value: url,
                        },
                        ReviewRow {
                            label: "Operation".to_owned(),
                            value: mode_str,
                        },
                        ReviewRow {
                            label: "Inputs".to_owned(),
                            value: format!("{} proofs ({in_sum} sat)", selected_indices.len()),
                        },
                        ReviewRow {
                            label: "Swap fee".to_owned(),
                            value: format!("{fee} sat"),
                        },
                    ],
                    warnings: Vec::new(),
                    require_pin: self.requires_pin(fee),
                })
            }
            VaultRequest::SendToken {
                mint_url,
                amount,
                memo,
            } => {
                if *amount == 0 {
                    return Err((
                        RejectCode::Malformed,
                        "send amount must be greater than zero".to_owned(),
                    ));
                }
                let url = canonical_mint_url(mint_url)
                    .map_err(|e| (RejectCode::InvalidMint, e))?;
                let mint = self.state.mints.get(&url).ok_or_else(|| {
                    (
                        RejectCode::InvalidMint,
                        format!("mint '{url}' is not registered"),
                    )
                })?;
                if mint.balance_sats() < *amount {
                    return Err((
                        RejectCode::InsufficientFunds,
                        format!(
                            "insufficient balance ({} sat) to send {amount} sat",
                            mint.balance_sats()
                        ),
                    ));
                }
                // Check if exact proofs exist or if demo mode can auto-swap first
                let exact = select_exact_proofs(&mint.proofs, *amount);
                if exact.is_none() && url != DEMO_MINT_URL {
                    return Err((
                        RejectCode::ExactChangeRequired,
                        format!(
                            "no exact proof combination for {amount} sat; run Swap with target {amount} sat first"
                        ),
                    ));
                }
                let mut rows = vec![
                    ReviewRow {
                        label: "Mint".to_owned(),
                        value: url,
                    },
                    ReviewRow {
                        label: "Amount leaving".to_owned(),
                        value: format!("{amount} sat"),
                    },
                    ReviewRow {
                        label: "Format".to_owned(),
                        value: "cashuB (V4 CBOR) + QR".to_owned(),
                    },
                ];
                if let Some(m) = memo {
                    if !m.is_empty() {
                        rows.push(ReviewRow {
                            label: "Memo".to_owned(),
                            value: m.clone(),
                        });
                    }
                }
                Ok(ReviewScreen {
                    title: "Send Cashu Token".to_owned(),
                    amount: format!("-{amount} sat"),
                    rows,
                    warnings: vec![
                        "Anyone who scans the resulting Cashu token QR can spend these sats."
                            .to_owned(),
                    ],
                    require_pin: self.requires_pin(*amount),
                })
            }
            VaultRequest::PrepareMelt {
                mint_url,
                quote_id,
                invoice,
                amount,
                fee_reserve,
            } => {
                if *amount == 0 {
                    return Err((
                        RejectCode::InvalidInvoice,
                        "melt amount must be greater than zero".to_owned(),
                    ));
                }
                let url = canonical_mint_url(mint_url)
                    .map_err(|e| (RejectCode::InvalidMint, e))?;
                let mint = self.state.mints.get(&url).ok_or_else(|| {
                    (
                        RejectCode::InvalidMint,
                        format!("mint '{url}' is not registered"),
                    )
                })?;
                let ks = mint
                    .keysets
                    .get(&mint.active_keyset_id)
                    .ok_or_else(|| (RejectCode::InvalidKeyset, "missing active keyset".to_owned()))?;

                let target = amount.saturating_add(*fee_reserve);
                let (selected, in_sum, input_fee) =
                    select_proofs_covering(&mint.proofs, target, ks.input_fee_ppk).ok_or_else(
                        || {
                            (
                                RejectCode::InsufficientFunds,
                                format!(
                                    "insufficient balance ({} sat) for melt ({amount} + {fee_reserve} reserve + fee)",
                                    mint.balance_sats()
                                ),
                            )
                        },
                    )?;

                let invoice_preview = if invoice.len() > 24 {
                    format!("{}...{}", &invoice[..12], &invoice[invoice.len() - 8..])
                } else {
                    invoice.clone()
                };

                Ok(ReviewScreen {
                    title: "Melt to Lightning".to_owned(),
                    amount: format!("-{amount} sat"),
                    rows: vec![
                        ReviewRow {
                            label: "Mint".to_owned(),
                            value: url,
                        },
                        ReviewRow {
                            label: "Invoice".to_owned(),
                            value: invoice_preview,
                        },
                        ReviewRow {
                            label: "Quote ID".to_owned(),
                            value: quote_id.clone(),
                        },
                        ReviewRow {
                            label: "LN fee reserve".to_owned(),
                            value: format!("{fee_reserve} sat"),
                        },
                        ReviewRow {
                            label: "Mint input fee".to_owned(),
                            value: format!("{input_fee} sat"),
                        },
                        ReviewRow {
                            label: "Inputs locked".to_owned(),
                            value: format!("{} proofs ({in_sum} sat)", selected.len()),
                        },
                    ],
                    warnings: vec![
                        format!(
                            "Up to {in_sum} sat is sent to the mint; unused fee reserve returns as blinded change."
                        ),
                    ],
                    require_pin: self.requires_pin(in_sum),
                })
            }
            _ => Err((RejectCode::Malformed, "request does not use review".to_owned())),
        }
    }

    /// Reject the currently waiting approval on Passport Prime's screen.
    pub fn reject(&mut self) -> Option<Vec<u8>> {
        let pending = self.waiting.take()?;
        let env = ResponseEnvelope {
            version: PROTOCOL_VERSION,
            request_id: pending.request_id,
            response: VaultResponse::Rejected {
                code: RejectCode::UserDeclined,
                message: "declined on Passport Prime".to_owned(),
            },
        };
        let bytes = env.to_cbor().expect("CBOR encode");
        self.cache_result(pending.request_id, env);
        let _ = self.save();
        Some(bytes)
    }

    /// Approve the currently waiting request on Passport Prime's screen.
    pub fn approve(&mut self, pin_verified: bool) -> Result<ApprovedOutcome, String> {
        let pending = self
            .waiting
            .take()
            .ok_or_else(|| "no request waiting for approval".to_owned())?;

        if pending.review.require_pin && !pin_verified {
            self.waiting = Some(pending);
            return Err("PIN verification is required for this operation".to_owned());
        }

        let (mut response, show_token_qr, mut notice) =
            self.execute_approved(&pending.request, pending.interactive_demo_complete)?;

        // If initiated interactively on device against the Demo Mint, auto-complete the mint roundtrip
        // so the user immediately gets the unblinded proofs in their vault!
        if pending.interactive_demo_complete {
            match response.clone() {
                VaultResponse::MintPrepared(req) if req.mint_url == DEMO_MINT_URL => {
                    let sigs = self.demo_mint.process_mint(&req)?;
                    response = self
                        .complete_mint(&req.op_id, &sigs)
                        .map_err(|(_, msg)| msg)?;
                    if let VaultResponse::MintCompleted { added_sats, .. } = &response {
                        notice = format!("Minted +{added_sats} sat into vault");
                    }
                }
                VaultResponse::SwapPrepared(req) if req.mint_url == DEMO_MINT_URL => {
                    let sigs = self.demo_mint.process_swap(&req)?;
                    response = self
                        .complete_swap(&req.op_id, &sigs)
                        .map_err(|(_, msg)| msg)?;
                    if let VaultResponse::SwapCompleted { net_sats, .. } = &response {
                        notice = format!("Completed swap ({net_sats} sat)");
                    }
                }
                VaultResponse::MeltPrepared(req) if req.mint_url == DEMO_MINT_URL => {
                    let change_sigs = self.demo_mint.process_melt(&req, 0)?;
                    response = self
                        .complete_melt(&req.op_id, true, &change_sigs)
                        .map_err(|(_, msg)| msg)?;
                    if let VaultResponse::MeltCompleted { change_sats, .. } = &response {
                        notice = format!(
                            "Melted {} sat (returned {change_sats} sat change)",
                            req.amount
                        );
                    }
                }
                _ => {}
            }
        }

        let env = ResponseEnvelope {
            version: PROTOCOL_VERSION,
            request_id: pending.request_id,
            response: response.clone(),
        };
        let reply_bytes = env.to_cbor().expect("CBOR encode");
        self.cache_result(pending.request_id, env);
        self.save()?;

        Ok(ApprovedOutcome {
            reply_bytes,
            response,
            show_token_qr,
            notice,
        })
    }

    fn execute_approved(
        &mut self,
        req: &VaultRequest,
        _interactive_demo: bool,
    ) -> Result<(VaultResponse, Option<Zeroizing<String>>, String), String> {
        match req {
            VaultRequest::AddMint { mint_url, keyset } => {
                let url = canonical_mint_url(mint_url)?;
                parse_and_verify_keyset(keyset)?;
                let ks_id = keyset.id.clone();
                let saved_counter = self.state.keyset_counters.get(&ks_id).copied().unwrap_or(0);
                let entry = self.state.mints.entry(url.clone()).or_insert_with(|| StoredMint {
                    url: url.clone(),
                    active_keyset_id: ks_id.clone(),
                    keysets: BTreeMap::new(),
                    counters: BTreeMap::new(),
                    proofs: Vec::new(),
                });
                entry.active_keyset_id = ks_id.clone();
                entry.keysets.insert(ks_id.clone(), keyset.clone());
                if saved_counter > entry.next_counter(&ks_id) {
                    entry.counters.insert(ks_id.clone(), saved_counter);
                }
                self.record_history("AddMint", 0, &url, format!("Added mint {url} ({ks_id})"));
                self.save()?;
                Ok((
                    VaultResponse::MintAdded {
                        mint_url: url.clone(),
                        keyset_id: ks_id,
                    },
                    None,
                    format!("Added mint {url}"),
                ))
            }
            VaultRequest::RemoveMint { mint_url } => {
                let url = canonical_mint_url(mint_url)?;
                self.remove_mint(&url)?;
                Ok((
                    VaultResponse::MintRemoved {
                        mint_url: url.clone(),
                    },
                    None,
                    format!("Removed mint {url}"),
                ))
            }
            VaultRequest::PrepareMint {
                mint_url,
                quote_id,
                amount,
            } => {
                let url = canonical_mint_url(mint_url)?;
                let op_id = self.next_op_id("mint");
                let mint = self
                    .state
                    .mints
                    .get_mut(&url)
                    .ok_or_else(|| "mint not found".to_owned())?;
                let ks_id = mint.active_keyset_id.clone();
                let mut counter = mint.next_counter(&ks_id);

                let parts = split_amount(*amount);
                let mut blinded_outputs = Vec::with_capacity(parts.len());
                let mut specs = Vec::with_capacity(parts.len());

                for amt in parts {
                    let derived = derive_blinded_output(&self.app_seed, &ks_id, counter, amt)?;
                    blinded_outputs.push(derived.blinded);
                    specs.push(PendingOutputSpec {
                        keyset_id: ks_id.clone(),
                        counter,
                        amount: amt,
                    });
                    counter = counter.saturating_add(1);
                }

                // Write-ahead counter update
                mint.counters.insert(ks_id.clone(), counter);
                self.state.keyset_counters.insert(ks_id, counter);
                self.state.pending_op = Some(PendingVaultOp::Mint {
                    op_id: op_id.clone(),
                    mint_url: url.clone(),
                    quote_id: quote_id.clone(),
                    amount: *amount,
                    outputs: specs,
                });
                self.save()?;

                let payload = MintRequestPayload {
                    op_id,
                    mint_url: url,
                    quote_id: quote_id.clone(),
                    amount: *amount,
                    outputs: blinded_outputs,
                };
                Ok((
                    VaultResponse::MintPrepared(payload),
                    None,
                    format!("Prepared NUT-04 mint for {amount} sat"),
                ))
            }
            VaultRequest::PrepareReceive { token } => {
                let mut decoded = CashuToken::decode(token)?;
                let url = canonical_mint_url(&decoded.mint_url)?;
                let op_id = self.next_op_id("recv");
                let mint = self
                    .state
                    .mints
                    .get_mut(&url)
                    .ok_or_else(|| "mint not found".to_owned())?;
                // Expand V4 ShortKeysetId (8 bytes / 16 hex chars) to the full v01 keyset ID (33 bytes / 66 hex chars)
                for proof in &mut decoded.proofs {
                    if !mint.keysets.contains_key(&proof.keyset_id) {
                        if let Some(full_id) = mint
                            .keysets
                            .keys()
                            .find(|k| k.starts_with(&proof.keyset_id))
                            .cloned()
                        {
                            proof.keyset_id = full_id;
                        }
                    }
                }
                let ks_id = mint.active_keyset_id.clone();
                let ks = mint
                    .keysets
                    .get(&ks_id)
                    .ok_or_else(|| "active keyset missing".to_owned())?;
                let fee = compute_input_fee(decoded.proofs.len(), ks.input_fee_ppk);
                let total = decoded.total_amount();
                if total <= fee {
                    return Err("token amount does not cover input fee".to_owned());
                }
                let net = total - fee;
                let parts = split_amount(net);
                let mut counter = mint.next_counter(&ks_id);
                let mut blinded_outputs = Vec::with_capacity(parts.len());
                let mut specs = Vec::with_capacity(parts.len());

                for amt in parts {
                    let derived = derive_blinded_output(&self.app_seed, &ks_id, counter, amt)?;
                    blinded_outputs.push(derived.blinded);
                    specs.push(PendingOutputSpec {
                        keyset_id: ks_id.clone(),
                        counter,
                        amount: amt,
                    });
                    counter = counter.saturating_add(1);
                }

                mint.counters.insert(ks_id.clone(), counter);
                self.state.keyset_counters.insert(ks_id, counter);
                self.state.pending_op = Some(PendingVaultOp::Swap {
                    op_id: op_id.clone(),
                    mint_url: url.clone(),
                    is_receive: true,
                    input_secrets: Vec::new(),
                    net_amount: net,
                    outputs: specs,
                });
                self.save()?;

                let payload = SwapRequestPayload {
                    op_id,
                    mint_url: url,
                    inputs: decoded.proofs,
                    outputs: blinded_outputs,
                    fee,
                };
                Ok((
                    VaultResponse::SwapPrepared(payload),
                    None,
                    format!("Prepared NUT-03 receive swap for {net} sat"),
                ))
            }
            VaultRequest::PrepareSwap {
                mint_url,
                target_amount,
            } => {
                let url = canonical_mint_url(mint_url)?;
                let op_id = self.next_op_id("swap");
                let mint = self
                    .state
                    .mints
                    .get_mut(&url)
                    .ok_or_else(|| "mint not found".to_owned())?;
                let ks_id = mint.active_keyset_id.clone();
                let ks = mint
                    .keysets
                    .get(&ks_id)
                    .ok_or_else(|| "active keyset missing".to_owned())?;

                let (selected_indices, in_sum, fee) = match target_amount {
                    Some(target) => select_proofs_covering(&mint.proofs, *target, ks.input_fee_ppk)
                        .ok_or_else(|| "insufficient funds for swap".to_owned())?,
                    None => {
                        let all: Vec<usize> = (0..mint.proofs.len()).collect();
                        let sum = mint.balance_sats();
                        let f = compute_input_fee(all.len(), ks.input_fee_ppk);
                        (all, sum, f)
                    }
                };
                let net = in_sum - fee;
                let output_parts = match target_amount {
                    Some(target) => {
                        let mut p = split_amount(*target);
                        p.extend(split_amount(net - *target));
                        p.sort_unstable();
                        p
                    }
                    None => split_amount(net),
                };

                let inputs: Vec<Proof> = selected_indices
                    .iter()
                    .map(|&idx| mint.proofs[idx].clone())
                    .collect();
                let input_secrets: Vec<String> = inputs.iter().map(|p| p.secret.clone()).collect();

                let mut counter = mint.next_counter(&ks_id);
                let mut blinded_outputs = Vec::with_capacity(output_parts.len());
                let mut specs = Vec::with_capacity(output_parts.len());

                for amt in output_parts {
                    let derived = derive_blinded_output(&self.app_seed, &ks_id, counter, amt)?;
                    blinded_outputs.push(derived.blinded);
                    specs.push(PendingOutputSpec {
                        keyset_id: ks_id.clone(),
                        counter,
                        amount: amt,
                    });
                    counter = counter.saturating_add(1);
                }

                mint.counters.insert(ks_id.clone(), counter);
                self.state.keyset_counters.insert(ks_id, counter);
                self.state.pending_op = Some(PendingVaultOp::Swap {
                    op_id: op_id.clone(),
                    mint_url: url.clone(),
                    is_receive: false,
                    input_secrets,
                    net_amount: net,
                    outputs: specs,
                });
                self.save()?;

                let payload = SwapRequestPayload {
                    op_id,
                    mint_url: url,
                    inputs,
                    outputs: blinded_outputs,
                    fee,
                };
                Ok((
                    VaultResponse::SwapPrepared(payload),
                    None,
                    format!("Prepared NUT-03 swap ({net} sat)"),
                ))
            }
            VaultRequest::SendToken {
                mint_url,
                amount,
                memo,
            } => {
                let url = canonical_mint_url(mint_url)?;
                // If exact denominations don't exist yet and this is the Demo Mint, perform an automatic
                // target split swap first so interactive sends always succeed cleanly!
                let need_auto_split = {
                    let mint = self
                        .state
                        .mints
                        .get(&url)
                        .ok_or_else(|| "mint not found".to_owned())?;
                    select_exact_proofs(&mint.proofs, *amount).is_none()
                };
                if need_auto_split && url == DEMO_MINT_URL {
                    let (swap_resp, _, _) = self.execute_approved(
                        &VaultRequest::PrepareSwap {
                            mint_url: url.clone(),
                            target_amount: Some(*amount),
                        },
                        true,
                    )?;
                    if let VaultResponse::SwapPrepared(swap_req) = swap_resp {
                        let sigs = self.demo_mint.process_swap(&swap_req)?;
                        self.complete_swap(&swap_req.op_id, &sigs)
                            .map_err(|(_, m)| m)?;
                    }
                }

                let mint = self
                    .state
                    .mints
                    .get_mut(&url)
                    .ok_or_else(|| "mint not found".to_owned())?;
                let indices = select_exact_proofs(&mint.proofs, *amount).ok_or_else(|| {
                    format!("no exact proof combination for {amount} sat; swap first")
                })?;

                let mut send_proofs = Vec::with_capacity(indices.len());
                // Remove in reverse index order to preserve earlier indices
                for &idx in indices.iter().rev() {
                    send_proofs.push(mint.proofs.remove(idx));
                }
                send_proofs.reverse();
                let new_balance_sats = mint.balance_sats();

                let cashu_token = CashuToken {
                    mint_url: url.clone(),
                    unit: "sat".to_owned(),
                    memo: memo.clone(),
                    proofs: send_proofs,
                };
                let token_v4 = cashu_token.encode_v4()?;
                let token_v3 = cashu_token.encode_v3()?;

                self.record_history(
                    "Send",
                    *amount,
                    &url,
                    format!("Sent {amount} sat token"),
                );
                self.save()?;

                Ok((
                    VaultResponse::TokenSent {
                        mint_url: url,
                        amount: *amount,
                        token_v4: token_v4.clone(),
                        token_v3,
                        new_balance_sats,
                    },
                    Some(Zeroizing::new(token_v4)),
                    format!("Exported {amount} sat Cashu token"),
                ))
            }
            VaultRequest::PrepareMelt {
                mint_url,
                quote_id,
                invoice,
                amount,
                fee_reserve,
            } => {
                let url = canonical_mint_url(mint_url)?;
                let op_id = self.next_op_id("melt");
                let mint = self
                    .state
                    .mints
                    .get_mut(&url)
                    .ok_or_else(|| "mint not found".to_owned())?;
                let ks_id = mint.active_keyset_id.clone();
                let ks = mint
                    .keysets
                    .get(&ks_id)
                    .ok_or_else(|| "active keyset missing".to_owned())?;

                let target = amount.saturating_add(*fee_reserve);
                let (selected_indices, in_sum, input_fee) =
                    select_proofs_covering(&mint.proofs, target, ks.input_fee_ppk)
                        .ok_or_else(|| "insufficient funds for melt".to_owned())?;

                let inputs: Vec<Proof> = selected_indices
                    .iter()
                    .map(|&idx| mint.proofs[idx].clone())
                    .collect();
                let input_secrets: Vec<String> = inputs.iter().map(|p| p.secret.clone()).collect();

                let max_change = in_sum.saturating_sub(*amount + input_fee);
                let num_blanks = blank_output_count(max_change);
                let mut counter = mint.next_counter(&ks_id);
                let mut blank_messages = Vec::with_capacity(num_blanks);
                let mut blank_specs = Vec::with_capacity(num_blanks);

                for _ in 0..num_blanks {
                    // NUT-05 / NUT-08 blank change outputs have amount = 0; the mint assigns power-of-two amounts to returned change signatures
                    let derived = derive_blinded_output(&self.app_seed, &ks_id, counter, 0)?;
                    blank_messages.push(derived.blinded);
                    blank_specs.push(PendingOutputSpec {
                        keyset_id: ks_id.clone(),
                        counter,
                        amount: 0,
                    });
                    counter = counter.saturating_add(1);
                }

                mint.counters.insert(ks_id.clone(), counter);
                self.state.keyset_counters.insert(ks_id, counter);
                self.state.pending_op = Some(PendingVaultOp::Melt {
                    op_id: op_id.clone(),
                    mint_url: url.clone(),
                    quote_id: quote_id.clone(),
                    amount: *amount,
                    fee_reserve: *fee_reserve,
                    input_fee,
                    input_secrets,
                    blank_outputs: blank_specs,
                });
                self.save()?;

                let payload = MeltRequestPayload {
                    op_id,
                    mint_url: url,
                    quote_id: quote_id.clone(),
                    invoice: invoice.clone(),
                    amount: *amount,
                    fee_reserve: *fee_reserve,
                    input_fee,
                    inputs,
                    outputs: blank_messages,
                };
                Ok((
                    VaultResponse::MeltPrepared(payload),
                    None,
                    format!("Prepared NUT-05 melt for {amount} sat"),
                ))
            }
            _ => Err("unsupported request in execute_approved".to_owned()),
        }
    }

    fn unblind_batch(
        &self,
        mint: &StoredMint,
        specs: &[PendingOutputSpec],
        signatures: &[BlindSignature],
    ) -> Result<Vec<Proof>, (RejectCode, String)> {
        if signatures.len() != specs.len() {
            return Err((
                RejectCode::InvalidSignature,
                format!(
                    "expected {} blind signatures, received {}",
                    specs.len(),
                    signatures.len()
                ),
            ));
        }

        let mut proofs = Vec::with_capacity(specs.len());
        for (spec, sig) in specs.iter().zip(signatures.iter()) {
            let ks = mint.keysets.get(&spec.keyset_id).ok_or_else(|| {
                (
                    RejectCode::InvalidKeyset,
                    format!("unknown keyset '{}'", spec.keyset_id),
                )
            })?;
            let pubkeys =
                parse_and_verify_keyset(ks).map_err(|e| (RejectCode::InvalidKeyset, e))?;
            let pk_a = pubkeys.get(&sig.amount).ok_or_else(|| {
                (
                    RejectCode::InvalidSignature,
                    format!("missing mint key for amount {}", sig.amount),
                )
            })?;
            if self.state.policy.verify_dleq && sig.dleq.is_none() {
                return Err((
                    RejectCode::InvalidSignature,
                    "policy requires NUT-12 DLEQ proof on BlindSignature".to_owned(),
                ));
            }
            let derived =
                derive_blinded_output(&self.app_seed, &spec.keyset_id, spec.counter, sig.amount)
                    .map_err(|e| (RejectCode::InternalError, e))?;
            let mut proof = unblind_to_proof(sig, &derived.secret, &derived.r, pk_a)
                .map_err(|e| (RejectCode::InvalidSignature, e))?;
            // Ensure the stored proof always carries the full canonical keyset ID (e.g. 66-hex-char v01 ID)
            proof.keyset_id = spec.keyset_id.clone();
            if self.state.policy.verify_dleq {
                verify_proof_dleq(&proof, pk_a)
                    .map_err(|e| (RejectCode::InvalidSignature, e))?;
            }
            proofs.push(proof);
        }
        Ok(proofs)
    }

    pub fn complete_mint(
        &mut self,
        op_id: &str,
        signatures: &[BlindSignature],
    ) -> Result<VaultResponse, (RejectCode, String)> {
        let pending = self.state.pending_op.clone().ok_or_else(|| {
            (
                RejectCode::NotFound,
                "no pending operation in vault".to_owned(),
            )
        })?;
        let PendingVaultOp::Mint {
            op_id: expected_id,
            mint_url,
            amount,
            outputs,
            ..
        } = pending
        else {
            return Err((
                RejectCode::NotFound,
                "pending operation is not a Mint".to_owned(),
            ));
        };
        if expected_id != op_id {
            return Err((
                RejectCode::NotFound,
                format!("op_id mismatch: expected '{expected_id}', got '{op_id}'"),
            ));
        }

        let new_proofs = {
            let mint = self.state.mints.get(&mint_url).ok_or_else(|| {
                (
                    RejectCode::InvalidMint,
                    format!("unknown mint '{mint_url}'"),
                )
            })?;
            self.unblind_batch(mint, &outputs, signatures)?
        };

        let added_sats: u64 = new_proofs.iter().map(|p| p.amount).sum();
        if added_sats != amount {
            return Err((
                RejectCode::InvalidSignature,
                format!("unblinded sum ({added_sats}) != expected mint amount ({amount})"),
            ));
        }

        let mint = self.state.mints.get_mut(&mint_url).expect("mint exists");
        mint.proofs.extend(new_proofs);
        let new_balance_sats = mint.balance_sats();
        self.state.pending_op = None;
        self.record_history(
            "Mint",
            added_sats,
            &mint_url,
            format!("Minted +{added_sats} sat"),
        );
        self.save().map_err(|e| (RejectCode::InternalError, e))?;

        Ok(VaultResponse::MintCompleted {
            mint_url,
            added_sats,
            new_balance_sats,
        })
    }

    pub fn complete_swap(
        &mut self,
        op_id: &str,
        signatures: &[BlindSignature],
    ) -> Result<VaultResponse, (RejectCode, String)> {
        let pending = self.state.pending_op.clone().ok_or_else(|| {
            (
                RejectCode::NotFound,
                "no pending operation in vault".to_owned(),
            )
        })?;
        let PendingVaultOp::Swap {
            op_id: expected_id,
            mint_url,
            is_receive,
            input_secrets,
            net_amount,
            outputs,
        } = pending
        else {
            return Err((
                RejectCode::NotFound,
                "pending operation is not a Swap/Receive".to_owned(),
            ));
        };
        if expected_id != op_id {
            return Err((
                RejectCode::NotFound,
                format!("op_id mismatch: expected '{expected_id}', got '{op_id}'"),
            ));
        }

        let new_proofs = {
            let mint = self.state.mints.get(&mint_url).ok_or_else(|| {
                (
                    RejectCode::InvalidMint,
                    format!("unknown mint '{mint_url}'"),
                )
            })?;
            self.unblind_batch(mint, &outputs, signatures)?
        };

        let net_sats: u64 = new_proofs.iter().map(|p| p.amount).sum();
        if net_sats != net_amount {
            return Err((
                RejectCode::InvalidSignature,
                format!("unblinded swap sum ({net_sats}) != expected ({net_amount})"),
            ));
        }

        let mint = self.state.mints.get_mut(&mint_url).expect("mint exists");
        if !input_secrets.is_empty() {
            mint.proofs
                .retain(|p| !input_secrets.iter().any(|s| s == &p.secret));
        }
        mint.proofs.extend(new_proofs);
        let new_balance_sats = mint.balance_sats();
        self.state.pending_op = None;

        let kind = if is_receive { "Receive" } else { "Swap" };
        let summary = if is_receive {
            format!("Received +{net_sats} sat")
        } else {
            format!("Swapped {net_sats} sat into fresh proofs")
        };
        self.record_history(kind, net_sats, &mint_url, summary);
        self.save().map_err(|e| (RejectCode::InternalError, e))?;

        Ok(VaultResponse::SwapCompleted {
            mint_url,
            net_sats,
            new_balance_sats,
        })
    }

    /// Re-derive blinded outputs with an advanced NUT-13 counter (`+16`) for a pending swap/receive
    /// when a mint reports a duplicate output collision.
    pub fn reblind_pending_swap(
        &mut self,
        mut req: SwapRequestPayload,
    ) -> Result<SwapRequestPayload, String> {
        let mint = self
            .state
            .mints
            .get_mut(&req.mint_url)
            .ok_or_else(|| "mint not found".to_owned())?;
        let ks_id = mint.active_keyset_id.clone();
        let mut counter = mint.next_counter(&ks_id).saturating_add(16);
        let mut blinded_outputs = Vec::with_capacity(req.outputs.len());
        let mut specs = Vec::with_capacity(req.outputs.len());

        for out in &req.outputs {
            let derived = derive_blinded_output(&self.app_seed, &ks_id, counter, out.amount)?;
            blinded_outputs.push(derived.blinded);
            specs.push(PendingOutputSpec {
                keyset_id: ks_id.clone(),
                counter,
                amount: out.amount,
            });
            counter = counter.saturating_add(1);
        }

        mint.counters.insert(ks_id.clone(), counter);
        self.state.keyset_counters.insert(ks_id, counter);
        if let Some(PendingVaultOp::Swap { outputs, .. }) = &mut self.state.pending_op {
            *outputs = specs;
        }
        self.save()?;
        req.outputs = blinded_outputs;
        Ok(req)
    }

    pub fn complete_melt(
        &mut self,
        op_id: &str,
        paid: bool,
        change: &[BlindSignature],
    ) -> Result<VaultResponse, (RejectCode, String)> {
        let pending = self.state.pending_op.clone().ok_or_else(|| {
            (
                RejectCode::NotFound,
                "no pending operation in vault".to_owned(),
            )
        })?;
        let PendingVaultOp::Melt {
            op_id: expected_id,
            mint_url,
            amount,
            input_secrets,
            blank_outputs,
            ..
        } = pending
        else {
            return Err((
                RejectCode::NotFound,
                "pending operation is not a Melt".to_owned(),
            ));
        };
        if expected_id != op_id {
            return Err((
                RejectCode::NotFound,
                format!("op_id mismatch: expected '{expected_id}', got '{op_id}'"),
            ));
        }

        if !paid {
            // Lightning payment failed at mint; keep input proofs in vault and clear pending_op
            self.state.pending_op = None;
            self.save().map_err(|e| (RejectCode::InternalError, e))?;
            let new_balance_sats = self
                .state
                .mints
                .get(&mint_url)
                .map(|m| m.balance_sats())
                .unwrap_or(0);
            return Ok(VaultResponse::MeltCompleted {
                mint_url,
                paid: false,
                change_sats: 0,
                new_balance_sats,
            });
        }

        if change.len() > blank_outputs.len() {
            return Err((
                RejectCode::InvalidSignature,
                "more change signatures returned than blank outputs provided".to_owned(),
            ));
        }

        let used_specs = &blank_outputs[..change.len()];
        let change_proofs = {
            let mint = self.state.mints.get(&mint_url).ok_or_else(|| {
                (
                    RejectCode::InvalidMint,
                    format!("unknown mint '{mint_url}'"),
                )
            })?;
            self.unblind_batch(mint, used_specs, change)?
        };
        let change_sats: u64 = change_proofs.iter().map(|p| p.amount).sum();

        let mint = self.state.mints.get_mut(&mint_url).expect("mint exists");
        mint.proofs
            .retain(|p| !input_secrets.iter().any(|s| s == &p.secret));
        mint.proofs.extend(change_proofs);
        let new_balance_sats = mint.balance_sats();
        self.state.pending_op = None;

        self.record_history(
            "Melt",
            amount,
            &mint_url,
            format!("Melted -{amount} sat via Lightning"),
        );
        self.save().map_err(|e| (RejectCode::InternalError, e))?;

        Ok(VaultResponse::MeltCompleted {
            mint_url,
            paid: true,
            change_sats,
            new_balance_sats,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemStorage(Option<Vec<u8>>);

    impl Storage for MemStorage {
        fn load(&mut self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.clone())
        }
        fn store(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.0 = Some(bytes.to_vec());
            Ok(())
        }
    }

    struct TestPlatform(u8);
    impl Platform for TestPlatform {
        fn random_32(&mut self) -> [u8; 32] {
            self.0 = self.0.wrapping_add(1);
            [self.0; 32]
        }
        fn now_unix(&self) -> Option<u64> {
            Some(1_760_000_000)
        }
    }

    #[test]
    fn full_lifecycle_mint_receive_swap_send_melt() {
        let seed = [0x11u8; 32];
        let mut svc = VaultService::open(seed, MemStorage::default(), TestPlatform(1))
            .expect("open service");

        // 1. Mint 100 sats interactively (auto-completes against Demo Mint)
        let pending = svc
            .start_interactive(VaultRequest::PrepareMint {
                mint_url: DEMO_MINT_URL.to_owned(),
                quote_id: "q-mint-100".to_owned(),
                amount: 100,
            })
            .expect("start mint");
        assert_eq!(pending.review.title, "Mint Cashu Tokens");
        let out = svc.approve(false).expect("approve mint");
        assert!(matches!(
            out.response,
            VaultResponse::MintCompleted {
                added_sats: 100,
                new_balance_sats: 100,
                ..
            }
        ));
        assert_eq!(svc.info().total_balance_sats, 100);

        // 2. Receive a 25 sat external cashuB token
        let incoming_token = svc
            .create_demo_incoming_token(25)
            .expect("create demo token");
        let pending = svc
            .start_interactive(VaultRequest::PrepareReceive {
                token: incoming_token,
            })
            .expect("start receive");
        assert_eq!(pending.review.title, "Receive Cashu Token");
        let out = svc.approve(false).expect("approve receive");
        assert!(matches!(
            out.response,
            VaultResponse::SwapCompleted {
                net_sats: 25,
                new_balance_sats: 125,
                ..
            }
        ));
        assert_eq!(svc.info().total_balance_sats, 125);

        // 3. Swap proofs (consolidate / split)
        let pending = svc
            .start_interactive(VaultRequest::PrepareSwap {
                mint_url: DEMO_MINT_URL.to_owned(),
                target_amount: Some(30),
            })
            .expect("start swap");
        assert_eq!(pending.review.title, "Swap Cashu Proofs");
        let out = svc.approve(false).expect("approve swap");
        assert!(matches!(
            out.response,
            VaultResponse::SwapCompleted {
                new_balance_sats: 125,
                ..
            }
        ));

        // 4. Send 30 sats (exports cashuB + cashuA token and verifies it with Demo Mint)
        let pending = svc
            .start_interactive(VaultRequest::SendToken {
                mint_url: DEMO_MINT_URL.to_owned(),
                amount: 30,
                memo: Some("for Bob".to_owned()),
            })
            .expect("start send");
        assert_eq!(pending.review.title, "Send Cashu Token");
        let out = svc.approve(true).expect("approve send");
        let sent_qr = out.show_token_qr.expect("token QR returned");
        let decoded_sent = CashuToken::decode(&sent_qr).expect("decode sent cashuB");
        assert_eq!(decoded_sent.total_amount(), 30);
        for p in &decoded_sent.proofs {
            svc.demo_mint_mut().verify_proof(p).expect("mint verifies sent proof");
        }
        assert_eq!(svc.info().total_balance_sats, 95);

        // 5. Melt 40 sats (+ 5 sat fee reserve) to a Lightning invoice
        let pending = svc
            .start_interactive(VaultRequest::PrepareMelt {
                mint_url: DEMO_MINT_URL.to_owned(),
                quote_id: "q-melt-40".to_owned(),
                invoice: "lnbc400n1p0demoinvoice".to_owned(),
                amount: 40,
                fee_reserve: 5,
            })
            .expect("start melt");
        assert_eq!(pending.review.title, "Melt to Lightning");
        let out = svc.approve(true).expect("approve melt");
        assert!(matches!(
            out.response,
            VaultResponse::MeltCompleted {
                paid: true,
                new_balance_sats: 55,
                ..
            }
        ));
        assert_eq!(svc.info().total_balance_sats, 55);
    }
}
