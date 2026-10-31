//! Host companion CLI & real HTTP Cashu Mint relay for `cashu-vault` on Passport Prime.
//!
//! By default talks to the public Cashu testnet mint (`https://testnut.cashu.space`), or any
//! mint URL passed via `--mint <url>` / `CASHU_MINT_URL`. Pass `--mock` for the offline mock mint.

use std::collections::BTreeMap;
use std::env;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cashu_vault_core::{
    canonical_mint_url, derive_blinded_output, parse_and_verify_keyset, split_amount,
    unblind_to_proof, MockMint,
};
use cashu_vault_protocol::{
    BlindSignature, BlindedMessage, CashuToken, KeysetInfo, Proof, RequestEnvelope,
    ResponseEnvelope, VaultRequest, VaultResponse, PROTOCOL_VERSION,
};
use cashu_vault_transport::bridge::Bridge;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const DEFAULT_TESTNET_MINT: &str = "https://testnut.cashu.space";
const MOCK_MINT_SEED: [u8; 32] = [0x77; 32];
const TIMEOUT: Duration = Duration::from_secs(90);

/// HTTP client for a real NUT-01..NUT-05 Cashu mint (Nutshell / CDK).
struct HttpMintClient {
    base_url: String,
}

#[derive(Deserialize)]
struct KeysetsResponse {
    keysets: Vec<KeysetMeta>,
}

#[derive(Deserialize)]
struct KeysetMeta {
    id: String,
    unit: String,
    active: bool,
    #[serde(default)]
    input_fee_ppk: u64,
}

#[derive(Deserialize)]
struct KeysResponse {
    keysets: Vec<KeysetKeys>,
}

#[derive(Deserialize)]
struct KeysetKeys {
    id: String,
    unit: String,
    keys: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct MintQuoteResponse {
    quote: String,
    request: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    paid: Option<bool>,
}

#[derive(Deserialize)]
struct SignaturesResponse {
    signatures: Vec<BlindSignature>,
}

#[derive(Debug, Deserialize)]
struct MeltQuoteResponse {
    quote: String,
    amount: u64,
    fee_reserve: u64,
}

#[derive(Debug, Deserialize)]
struct MeltBolt11Response {
    #[serde(default)]
    state: String,
    #[serde(default)]
    paid: Option<bool>,
    #[serde(default)]
    change: Vec<BlindSignature>,
}

#[derive(Serialize)]
struct PostMintBolt11<'a> {
    quote: &'a str,
    outputs: &'a [BlindedMessage],
}

#[derive(Serialize)]
struct PostSwap<'a> {
    inputs: &'a [Proof],
    outputs: &'a [BlindedMessage],
}

#[derive(Serialize)]
struct PostMeltBolt11<'a> {
    quote: &'a str,
    inputs: &'a [Proof],
    outputs: &'a [BlindedMessage],
}

impl HttpMintClient {
    fn new(url: &str) -> Result<Self, String> {
        Ok(Self {
            base_url: canonical_mint_url(url)?,
        })
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let url = format!("{}{path}", self.base_url);
        let out = Command::new("curl")
            .args(["-4", "-sS", "--max-time", "20", &url])
            .output()
            .map_err(|e| format!("failed to run curl: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "GET {url} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        serde_json::from_slice(&out.stdout).map_err(|e| {
            format!(
                "GET {url} invalid JSON ({e}): {}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, String> {
        let url = format!("{}{path}", self.base_url);
        let payload = serde_json::to_string(body).map_err(|e| e.to_string())?;
        let out = Command::new("curl")
            .args([
                "-4",
                "-sS",
                "--max-time",
                "30",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &payload,
                &url,
            ])
            .output()
            .map_err(|e| format!("failed to run curl: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "POST {url} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        serde_json::from_slice(&out.stdout).map_err(|e| {
            format!(
                "POST {url} error ({e}): {}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    /// Fetch the active `sat` keyset (`KeysetInfo`) from `/v1/keysets` and `/v1/keys`.
    fn fetch_active_sat_keyset(&self) -> Result<KeysetInfo, String> {
        let meta: KeysetsResponse = self.get_json("/v1/keysets")?;
        let active_sat = meta
            .keysets
            .into_iter()
            .find(|k| k.unit == "sat" && k.active)
            .ok_or_else(|| format!("no active 'sat' keyset found at {}", self.base_url))?;

        let keys_resp: KeysResponse = self.get_json("/v1/keys")?;
        let ks_keys = keys_resp
            .keysets
            .into_iter()
            .find(|k| k.id == active_sat.id || (k.unit == "sat" && k.id.starts_with(&active_sat.id[..16])))
            .ok_or_else(|| format!("keys for keyset {} not found in /v1/keys", active_sat.id))?;

        let mut keys = BTreeMap::new();
        for (amt_str, pk_hex) in ks_keys.keys {
            if let Ok(amt) = amt_str.parse::<u64>() {
                keys.insert(amt, pk_hex);
            }
        }
        Ok(KeysetInfo {
            id: active_sat.id,
            unit: "sat".to_owned(),
            active: true,
            input_fee_ppk: active_sat.input_fee_ppk,
            keys,
        })
    }

    /// Create a NUT-04 mint quote (`POST /v1/mint/quote/bolt11`) and wait until it is paid.
    fn create_and_wait_mint_quote(&self, amount: u64) -> Result<String, String> {
        let quote: MintQuoteResponse = self.post_json(
            "/v1/mint/quote/bolt11",
            &json!({ "amount": amount, "unit": "sat" }),
        )?;
        println!("Created mint quote '{}' for {amount} sat.", quote.quote);
        if quote.state == "PAID" || quote.paid == Some(true) {
            println!("Quote is already PAID (FakeWallet / testnet mint).");
            return Ok(quote.quote);
        }
        self.wait_mint_quote_response(quote)
    }

    /// Check an existing NUT-04 mint quote (`GET /v1/mint/quote/bolt11/{quote_id}`) and wait until paid.
    fn wait_existing_mint_quote(&self, quote_id: &str) -> Result<String, String> {
        let status: MintQuoteResponse =
            self.get_json(&format!("/v1/mint/quote/bolt11/{quote_id}"))?;
        if status.state == "ISSUED" {
            return Err(format!("mint quote '{quote_id}' has already been issued"));
        }
        if status.state == "PAID" || status.paid == Some(true) {
            println!("Existing quote '{quote_id}' is PAID and ready to mint.");
            return Ok(status.quote);
        }
        self.wait_mint_quote_response(status)
    }

    fn wait_mint_quote_response(&self, quote: MintQuoteResponse) -> Result<String, String> {
        println!("Pay this Lightning invoice to continue:\n  {}\n", quote.request);
        println!(
            "Waiting for invoice payment (if interrupted, resume with: vault-cli --mint {} mint <sats> {})...",
            self.base_url, quote.quote
        );
        for _ in 0..60 {
            std::thread::sleep(Duration::from_secs(2));
            let status: MintQuoteResponse =
                self.get_json(&format!("/v1/mint/quote/bolt11/{}", quote.quote))?;
            if status.state == "PAID" || status.paid == Some(true) {
                println!("Invoice PAID!");
                return Ok(quote.quote);
            }
        }
        Err(format!(
            "timed out waiting for Lightning invoice to be paid (quote_id: {})",
            quote.quote
        ))
    }

    /// Post blinded outputs to `POST /v1/mint/bolt11`.
    fn post_mint(&self, quote_id: &str, outputs: &[BlindedMessage]) -> Result<Vec<BlindSignature>, String> {
        let resp: SignaturesResponse = self.post_json(
            "/v1/mint/bolt11",
            &PostMintBolt11 {
                quote: quote_id,
                outputs,
            },
        )?;
        Ok(resp.signatures)
    }

    /// Post inputs and blinded outputs to `POST /v1/swap`.
    fn post_swap(&self, inputs: &[Proof], outputs: &[BlindedMessage]) -> Result<Vec<BlindSignature>, String> {
        let mut normalized_inputs = inputs.to_vec();
        // If any input proof carries a V4 8-byte ShortKeysetId for a v01 keyset (16 hex chars starting with "01"),
        // expand it to the full 66-hex-char v01 keyset ID expected by CDK's /v1/swap endpoint.
        if normalized_inputs
            .iter()
            .any(|p| p.keyset_id.starts_with("01") && p.keyset_id.len() == 16)
        {
            let meta: KeysetsResponse = self.get_json("/v1/keysets")?;
            for proof in &mut normalized_inputs {
                if proof.keyset_id.starts_with("01") && proof.keyset_id.len() == 16 {
                    if let Some(ks) = meta
                        .keysets
                        .iter()
                        .find(|k| k.id.starts_with(&proof.keyset_id))
                    {
                        proof.keyset_id = ks.id.clone();
                    }
                }
            }
        }
        let resp: SignaturesResponse = self.post_json(
            "/v1/swap",
            &PostSwap {
                inputs: &normalized_inputs,
                outputs,
            },
        )?;
        Ok(resp.signatures)
    }

    /// Create a NUT-05 melt quote (`POST /v1/melt/quote/bolt11`).
    fn create_melt_quote(&self, invoice: &str) -> Result<MeltQuoteResponse, String> {
        self.post_json(
            "/v1/melt/quote/bolt11",
            &json!({ "request": invoice, "unit": "sat" }),
        )
    }

    /// Execute a NUT-05 melt (`POST /v1/melt/bolt11`).
    fn post_melt(
        &self,
        quote_id: &str,
        inputs: &[Proof],
        outputs: &[BlindedMessage],
    ) -> Result<(bool, Vec<BlindSignature>), String> {
        let resp: MeltBolt11Response = self.post_json(
            "/v1/melt/bolt11",
            &PostMeltBolt11 {
                quote: quote_id,
                inputs,
                outputs,
            },
        )?;
        let paid = resp.state == "PAID" || resp.paid == Some(true);
        Ok((paid, resp.change))
    }
}

fn is_duplicate_output_error(err: &str) -> bool {
    // CDK maps database::Error::Duplicate on blind_signature(blinded_message) PK collision
    // to code 20006 ("Invoice already paid or pending"); standard NUT-00 codes for duplicate
    // outputs are 11003 ("Outputs already signed") and 11004 ("Outputs are pending").
    err.contains("20006")
        || err.contains("11003")
        || err.contains("11004")
        || err.contains("Outputs already signed")
        || err.contains("Outputs are pending")
        || err.contains("Invoice already paid or pending")
}

fn next_req_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
}

fn exchange(bridge: &Bridge, request: VaultRequest) -> Result<VaultResponse, String> {
    let req_id = next_req_id();
    let env = RequestEnvelope {
        version: PROTOCOL_VERSION,
        request_id: req_id,
        request,
    };
    let bytes = env.to_cbor()?;
    bridge
        .submit(&bytes)
        .map_err(|e| format!("bridge submit failed: {e}"))?;
    println!("-> Sent request #{req_id} to Passport Prime (tap Approve on the simulator/device screen)...");
    let reply_bytes = bridge
        .wait_response(req_id, TIMEOUT)
        .map_err(|e| format!("bridge wait failed: {e}"))?
        .ok_or_else(|| "timed out waiting for response from Passport Prime".to_owned())?;
    let resp = ResponseEnvelope::from_cbor(&reply_bytes)?;
    if let VaultResponse::Rejected { code, message } = &resp.response {
        return Err(format!("rejected by Passport Prime ({code:?}): {message}"));
    }
    Ok(resp.response)
}

fn mint_mock_external_token(mint: &MockMint, amount: u64) -> Result<String, String> {
    let ks = mint.keyset_info();
    let pubkeys = parse_and_verify_keyset(&ks)?;
    let sender_seed = [0x33u8; 32];
    let parts = split_amount(amount);
    let mut proofs = Vec::with_capacity(parts.len());
    for (idx, amt) in parts.into_iter().enumerate() {
        let derived = derive_blinded_output(&sender_seed, &ks.id, idx as u32 + 500, amt)?;
        let sig = mint.sign_blinded(&derived.blinded)?;
        let pk = pubkeys.get(&amt).ok_or("missing key")?;
        proofs.push(unblind_to_proof(&sig, &derived.secret, &derived.r, pk)?);
    }
    CashuToken {
        mint_url: mint.url.clone(),
        unit: "sat".to_owned(),
        memo: Some("External token".to_owned()),
        proofs,
    }
    .encode_v4()
}

fn main() -> Result<(), String> {
    let mut raw_args: Vec<String> = env::args().skip(1).collect();
    let mut use_mock = false;
    let mut mint_url = env::var("CASHU_MINT_URL").unwrap_or_else(|_| DEFAULT_TESTNET_MINT.to_owned());

    // Parse flags `--mock` and `--mint <url>`
    let mut positional = Vec::new();
    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--mock" => {
                use_mock = true;
                i += 1;
            }
            "--mint" => {
                let url = raw_args
                    .get(i + 1)
                    .ok_or_else(|| "--mint requires a URL argument".to_owned())?
                    .clone();
                mint_url = url;
                i += 2;
            }
            other => {
                positional.push(other.to_owned());
                i += 1;
            }
        }
    }
    raw_args = positional;
    let cmd = raw_args.first().map(String::as_str).unwrap_or("help");

    let bridge = Bridge::from_env();
    bridge
        .create()
        .map_err(|e| format!("cannot create bridge dir: {e}"))?;
    if bridge.pinned_app_seed()?.is_none() {
        use std::io::Read;
        let mut seed = [0u8; 32];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut seed).is_ok() {
                let _ = bridge.pin_app_seed(&seed);
                println!(
                    "Pinned a new unique simulator seed at {} (restart `foundation sim` if it is already running so it picks up the new seed).",
                    bridge.seed_file().display()
                );
            }
        }
    }

    let mint_url = canonical_mint_url(&mint_url)?;
    let mut mock_mint = MockMint::new(&MOCK_MINT_SEED, &mint_url, 0);
    let http_mint = HttpMintClient::new(&mint_url)?;

    match cmd {
        "info" => {
            let resp = exchange(&bridge, VaultRequest::GetInfo)?;
            println!("{resp:#?}");
        }
        "add-mint" => {
            let keyset = if use_mock {
                mock_mint.keyset_info()
            } else {
                println!("Fetching active 'sat' keyset from {mint_url}...");
                http_mint.fetch_active_sat_keyset()?
            };
            println!(
                "Fetched keyset {} ({} denominations, fee={} ppk)",
                keyset.id,
                keyset.keys.len(),
                keyset.input_fee_ppk
            );
            let resp = exchange(
                &bridge,
                VaultRequest::AddMint {
                    mint_url: mint_url.clone(),
                    keyset,
                },
            )?;
            println!("{resp:#?}");
        }
        "remove-mint" => {
            let target_url = raw_args
                .get(1)
                .cloned()
                .unwrap_or_else(|| mint_url.clone());
            let resp = exchange(
                &bridge,
                VaultRequest::RemoveMint {
                    mint_url: target_url,
                },
            )?;
            println!("{resp:#?}");
        }
        "mint" => {
            let amount: u64 = raw_args
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(64);
            let existing_quote = raw_args.get(2).map(String::as_str);
            let quote_id = if use_mock {
                existing_quote
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("mock-quote-{amount}"))
            } else if let Some(qid) = existing_quote {
                http_mint.wait_existing_mint_quote(qid)?
            } else {
                http_mint.create_and_wait_mint_quote(amount)?
            };

            let mut attempt = 1usize;
            let (op_id, sigs) = loop {
                let prep = exchange(
                    &bridge,
                    VaultRequest::PrepareMint {
                        mint_url: mint_url.clone(),
                        quote_id: quote_id.clone(),
                        amount,
                    },
                )?;
                let VaultResponse::MintPrepared(req) = prep else {
                    return Err(format!("unexpected response: {prep:?}"));
                };
                if use_mock {
                    let sigs = mock_mint.process_mint(&req)?;
                    break (req.op_id, sigs);
                }
                println!(
                    "Posting {} blinded outputs to {mint_url}/v1/mint/bolt11...",
                    req.outputs.len()
                );
                match http_mint.post_mint(&quote_id, &req.outputs) {
                    Ok(sigs) => break (req.op_id, sigs),
                    Err(err) if is_duplicate_output_error(&err) && attempt < 32 => {
                        println!(
                            "Mint rejected blinded outputs as already used (NUT-13 counter collision on mint, attempt {attempt}/32)."
                        );
                        println!(
                            "Advancing vault NUT-13 counter and requesting fresh outputs for paid quote '{quote_id}'..."
                        );
                        attempt += 1;
                    }
                    Err(err) => {
                        return Err(format!(
                            "{err}\n(Note: quote '{quote_id}' is paid; you can retry claiming it with: cargo run -p cashu-vault-cli -- --mint {mint_url} mint {amount} {quote_id})"
                        ));
                    }
                }
            };
            let done = exchange(
                &bridge,
                VaultRequest::CompleteMint {
                    op_id,
                    signatures: sigs,
                },
            )?;
            println!("{done:#?}");
        }
        "receive" => {
            let arg = raw_args
                .get(1)
                .ok_or_else(|| "usage: vault-cli receive <cashuA.../cashuB... token>".to_owned())?;
            let token_str = if arg.starts_with("cashu") {
                arg.to_owned()
            } else if use_mock {
                let amt: u64 = arg.parse().map_err(|_| "expected token or sat amount")?;
                mint_mock_external_token(&mock_mint, amt)?
            } else {
                return Err("for a real mint, pass a 'cashuA...' or 'cashuB...' token string".to_owned());
            };
            let mut attempt = 1usize;
            let (op_id, sigs) = loop {
                let prep = exchange(
                    &bridge,
                    VaultRequest::PrepareReceive {
                        token: token_str.clone(),
                    },
                )?;
                let VaultResponse::SwapPrepared(req) = prep else {
                    return Err(format!("unexpected response: {prep:?}"));
                };
                if use_mock {
                    let sigs = mock_mint.process_swap(&req)?;
                    break (req.op_id, sigs);
                }
                let client = HttpMintClient::new(&req.mint_url)?;
                println!(
                    "Swapping {} input proofs into {} fresh vault outputs at {}...",
                    req.inputs.len(),
                    req.outputs.len(),
                    req.mint_url
                );
                match client.post_swap(&req.inputs, &req.outputs) {
                    Ok(sigs) => break (req.op_id, sigs),
                    Err(err) if is_duplicate_output_error(&err) && attempt < 8 => {
                        println!(
                            "Mint rejected blinded outputs as already used (NUT-13 counter collision on mint, attempt {attempt}/8). Retrying with next counter..."
                        );
                        attempt += 1;
                    }
                    Err(err) => return Err(err),
                }
            };
            let done = exchange(
                &bridge,
                VaultRequest::CompleteSwap {
                    op_id,
                    signatures: sigs,
                },
            )?;
            println!("{done:#?}");
        }
        "swap" => {
            let target: Option<u64> = raw_args.get(1).and_then(|s| s.parse().ok());
            let mut attempt = 1usize;
            let (op_id, sigs) = loop {
                let prep = exchange(
                    &bridge,
                    VaultRequest::PrepareSwap {
                        mint_url: mint_url.clone(),
                        target_amount: target,
                    },
                )?;
                let VaultResponse::SwapPrepared(req) = prep else {
                    return Err(format!("unexpected response: {prep:?}"));
                };
                if use_mock {
                    let sigs = mock_mint.process_swap(&req)?;
                    break (req.op_id, sigs);
                }
                println!("Posting swap to {mint_url}/v1/swap...");
                match http_mint.post_swap(&req.inputs, &req.outputs) {
                    Ok(sigs) => break (req.op_id, sigs),
                    Err(err) if is_duplicate_output_error(&err) && attempt < 8 => {
                        println!(
                            "Mint rejected blinded outputs as already used (NUT-13 counter collision on mint, attempt {attempt}/8). Retrying with next counter..."
                        );
                        attempt += 1;
                    }
                    Err(err) => return Err(err),
                }
            };
            let done = exchange(
                &bridge,
                VaultRequest::CompleteSwap {
                    op_id,
                    signatures: sigs,
                },
            )?;
            println!("{done:#?}");
        }
        "send" => {
            let amount: u64 = raw_args
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(16);
            let memo = raw_args.get(2).cloned();
            let resp = exchange(
                &bridge,
                VaultRequest::SendToken {
                    mint_url: mint_url.clone(),
                    amount,
                    memo,
                },
            )?;
            if let VaultResponse::TokenSent {
                token_v4,
                token_v3,
                new_balance_sats,
                ..
            } = &resp
            {
                println!("Exported {amount} sat token! Remaining balance: {new_balance_sats} sat");
                println!("cashuB (V4): {token_v4}");
                println!("cashuA (V3): {token_v3}");
            } else {
                println!("{resp:#?}");
            }
        }
        "melt" => {
            let arg1 = raw_args.get(1).map(String::as_str).unwrap_or("16");
            let (invoice, quote_id, amount, fee_reserve) = if use_mock {
                let amt: u64 = arg1.parse().unwrap_or(16);
                let reserve: u64 = raw_args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2);
                (
                    format!("lnbc{}0n1p0mockinvoice", amt),
                    format!("mock-melt-{amt}"),
                    amt,
                    reserve,
                )
            } else if arg1.starts_with("lnbc") || arg1.starts_with("lntb") || arg1.starts_with("lnbcrt") {
                let q = http_mint.create_melt_quote(arg1)?;
                (arg1.to_owned(), q.quote, q.amount, q.fee_reserve)
            } else {
                // Convenient helper on FakeWallet mints (like testnut.cashu.space):
                // request a mint quote for `<amt>` sat just to get a valid BOLT11 invoice string!
                let amt: u64 = arg1.parse().map_err(|_| "pass a BOLT11 invoice or a sat amount (for FakeWallet testnet mints)")?;
                let dummy: MintQuoteResponse = http_mint.post_json(
                    "/v1/mint/quote/bolt11",
                    &json!({ "amount": amt, "unit": "sat" }),
                )?;
                let q = http_mint.create_melt_quote(&dummy.request)?;
                (dummy.request, q.quote, q.amount, q.fee_reserve)
            };

            let prep = exchange(
                &bridge,
                VaultRequest::PrepareMelt {
                    mint_url: mint_url.clone(),
                    quote_id: quote_id.clone(),
                    invoice,
                    amount,
                    fee_reserve,
                },
            )?;
            let VaultResponse::MeltPrepared(req) = prep else {
                return Err(format!("unexpected response: {prep:?}"));
            };
            let (paid, change_sigs) = if use_mock {
                (true, mock_mint.process_melt(&req, 0)?)
            } else {
                println!("Posting melt to {mint_url}/v1/melt/bolt11...");
                http_mint.post_melt(&quote_id, &req.inputs, &req.outputs)?
            };
            let done = exchange(
                &bridge,
                VaultRequest::CompleteMelt {
                    op_id: req.op_id,
                    paid,
                    change: change_sigs,
                },
            )?;
            println!("{done:#?}");
        }
        _ => {
            println!("Usage: vault-cli [--mint <url>] [--mock] <command> [args]");
            println!("Default mint: {DEFAULT_TESTNET_MINT}");
            println!();
            println!("Commands:");
            println!("  info                        Query vault status and balances");
            println!("  add-mint                    Fetch & register the mint's active 'sat' keyset");
            println!("  remove-mint [mint_url]      Remove a mint from the vault");
            println!("  mint [sats] [quote_id]      Create quote (or claim paid quote_id) & mint tokens (NUT-04)");
            println!("  receive <cashu_token>       Swap an external cashuA/cashuB token into vault (NUT-03)");
            println!("  swap [target_sats]          Consolidate or split proofs in vault (NUT-03)");
            println!("  send [sats] [memo]          Export spendable cashuB/cashuA token from vault");
            println!("  melt <bolt11_or_sats>       Melt vault proofs to pay a Lightning invoice (NUT-05)");
        }
    }
    Ok(())
}
