//! End-to-end simulator driver for `cashu-vault` on Passport Prime.
//!
//! Exercises:
//! 1. AddMint (`https://mint.cashu.space`) + on-screen review & tap approval
//! 2. NUT-04 Mint (64 sats) + on-screen review & tap approval + unblinding & DLEQ check
//! 3. NUT-03 Receive (25 sat external `cashuB` token) + on-screen review & tap approval
//! 4. NUT-03 Swap (split for 20 sat send) + on-screen review & tap approval
//! 5. Send (20 sat token) + on-screen review & tap approval + reading `cashuB` QR from screen
//! 6. NUT-05 Melt (30 sat invoice + 4 sat fee reserve) + on-screen review & tap approval + change unblinding

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use cashu_vault_core::{
    derive_blinded_output, parse_and_verify_keyset, split_amount, unblind_to_proof, MockMint,
};
use cashu_vault_protocol::{
    CashuToken, RequestEnvelope, ResponseEnvelope, VaultRequest, VaultResponse, PROTOCOL_VERSION,
};
use cashu_vault_simdrive::{read_qr, Screen, APPROVE, DONE};
use cashu_vault_transport::bridge::Bridge;

const MINT_URL: &str = "https://mint.cashu.space";
const MINT_SEED: [u8; 32] = [0x55; 32];
const TIMEOUT: Duration = Duration::from_secs(20);

fn submit_and_approve(
    bridge: &Bridge,
    screen: &mut Screen,
    req_id: u64,
    request: VaultRequest,
    expected_title: &str,
    shot_name: &str,
) -> Result<VaultResponse, String> {
    screen.clear_logs()?;
    let env = RequestEnvelope {
        version: PROTOCOL_VERSION,
        request_id: req_id,
        request,
    };
    bridge
        .submit(&env.to_cbor()?)
        .map_err(|e| format!("submit #{req_id}: {e}"))?;

    screen.wait_for_log(&format!("review on screen: {expected_title}"))?;
    std::thread::sleep(Duration::from_millis(300));
    screen.shot(shot_name)?;
    screen.tap(APPROVE)?;

    let reply = bridge
        .wait_response(req_id, TIMEOUT)
        .map_err(|e| format!("wait #{req_id}: {e}"))?
        .ok_or_else(|| format!("timeout waiting for #{req_id}"))?;
    Ok(ResponseEnvelope::from_cbor(&reply)?.response)
}

fn submit_immediate(
    bridge: &Bridge,
    req_id: u64,
    request: VaultRequest,
) -> Result<VaultResponse, String> {
    let env = RequestEnvelope {
        version: PROTOCOL_VERSION,
        request_id: req_id,
        request,
    };
    bridge
        .submit(&env.to_cbor()?)
        .map_err(|e| format!("submit #{req_id}: {e}"))?;
    let reply = bridge
        .wait_response(req_id, TIMEOUT)
        .map_err(|e| format!("wait #{req_id}: {e}"))?
        .ok_or_else(|| format!("timeout waiting for #{req_id}"))?;
    Ok(ResponseEnvelope::from_cbor(&reply)?.response)
}

fn main() -> Result<(), String> {
    let drive = env::var_os("PASSPORT_DRIVE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("foundation-passport-drive"));
    let shots = env::var_os("SHOTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/sim-shots"));

    let bridge = Bridge::from_env();
    bridge
        .create()
        .map_err(|e| format!("bridge create: {e}"))?;
    bridge
        .clear_queues()
        .map_err(|e| format!("bridge clear: {e}"))?;

    let mut screen = Screen::new(drive, shots)?;
    screen.shot("home")?;

    let mut mint = MockMint::new(&MINT_SEED, MINT_URL, 0);

    // 1. AddMint
    println!("[1/6] Adding mint {MINT_URL}...");
    let resp = submit_and_approve(
        &bridge,
        &mut screen,
        1,
        VaultRequest::AddMint {
            mint_url: MINT_URL.to_owned(),
            keyset: mint.keyset_info(),
        },
        "Add Cashu Mint",
        "review-add-mint",
    )?;
    assert!(matches!(resp, VaultResponse::MintAdded { .. }));

    // 2. Mint 64 sats (NUT-04)
    println!("[2/6] Minting 64 sats (NUT-04)...");
    let prep = submit_and_approve(
        &bridge,
        &mut screen,
        2,
        VaultRequest::PrepareMint {
            mint_url: MINT_URL.to_owned(),
            quote_id: "q-mint-64".to_owned(),
            amount: 64,
        },
        "Mint Cashu Tokens",
        "review-mint",
    )?;
    let VaultResponse::MintPrepared(mint_req) = prep else {
        return Err(format!("expected MintPrepared, got {prep:?}"));
    };
    let mint_sigs = mint.process_mint(&mint_req)?;
    let done = submit_immediate(
        &bridge,
        3,
        VaultRequest::CompleteMint {
            op_id: mint_req.op_id,
            signatures: mint_sigs,
        },
    )?;
    assert!(matches!(
        done,
        VaultResponse::MintCompleted {
            added_sats: 64,
            new_balance_sats: 64,
            ..
        }
    ));

    // 3. Receive 25 sat external cashuB token (NUT-03)
    println!("[3/6] Receiving 25 sat cashuB token (NUT-03)...");
    let ks_info = mint.keyset_info();
    let pubkeys = parse_and_verify_keyset(&ks_info)?;
    let ext_seed = [0x88u8; 32];
    let mut ext_proofs = Vec::new();
    for (idx, amt) in split_amount(25).into_iter().enumerate() {
        let derived = derive_blinded_output(&ext_seed, &ks_info.id, idx as u32 + 100, amt)?;
        let sig = mint.sign_blinded(&derived.blinded)?;
        let pk = pubkeys.get(&amt).ok_or("missing key")?;
        ext_proofs.push(unblind_to_proof(&sig, &derived.secret, &derived.r, pk)?);
    }
    let incoming_token = CashuToken {
        mint_url: MINT_URL.to_owned(),
        unit: "sat".to_owned(),
        memo: Some("Incoming 25 sat".to_owned()),
        proofs: ext_proofs,
    }
    .encode_v4()?;

    let prep_recv = submit_and_approve(
        &bridge,
        &mut screen,
        4,
        VaultRequest::PrepareReceive {
            token: incoming_token,
        },
        "Receive Cashu Token",
        "review-receive",
    )?;
    let VaultResponse::SwapPrepared(recv_req) = prep_recv else {
        return Err(format!("expected SwapPrepared, got {prep_recv:?}"));
    };
    let recv_sigs = mint.process_swap(&recv_req)?;
    let done_recv = submit_immediate(
        &bridge,
        5,
        VaultRequest::CompleteSwap {
            op_id: recv_req.op_id,
            signatures: recv_sigs,
        },
    )?;
    assert!(matches!(
        done_recv,
        VaultResponse::SwapCompleted {
            net_sats: 25,
            new_balance_sats: 89,
            ..
        }
    ));

    // 4. Swap proofs to isolate 20 sat (NUT-03)
    println!("[4/6] Swapping proofs for 20 sat target (NUT-03)...");
    let prep_swap = submit_and_approve(
        &bridge,
        &mut screen,
        6,
        VaultRequest::PrepareSwap {
            mint_url: MINT_URL.to_owned(),
            target_amount: Some(20),
        },
        "Swap Cashu Proofs",
        "review-swap",
    )?;
    let VaultResponse::SwapPrepared(swap_req) = prep_swap else {
        return Err(format!("expected SwapPrepared, got {prep_swap:?}"));
    };
    let swap_sigs = mint.process_swap(&swap_req)?;
    let done_swap = submit_immediate(
        &bridge,
        7,
        VaultRequest::CompleteSwap {
            op_id: swap_req.op_id,
            signatures: swap_sigs,
        },
    )?;
    assert!(matches!(
        done_swap,
        VaultResponse::SwapCompleted {
            new_balance_sats: 89,
            ..
        }
    ));

    // 5. Send 20 sat token + decode QR from simulator screen!
    println!("[5/6] Sending 20 sat token & reading cashuB QR off screen...");
    screen.clear_logs()?;
    let send_resp = submit_and_approve(
        &bridge,
        &mut screen,
        8,
        VaultRequest::SendToken {
            mint_url: MINT_URL.to_owned(),
            amount: 20,
            memo: Some("Alice".to_owned()),
        },
        "Send Cashu Token",
        "review-send",
    )?;
    let VaultResponse::TokenSent {
        amount: 20,
        token_v4,
        new_balance_sats: 69,
        ..
    } = send_resp
    else {
        return Err(format!("expected TokenSent, got {send_resp:?}"));
    };
    screen.wait_for_log("result on screen: Scan Cashu Token")?;
    std::thread::sleep(Duration::from_millis(300));
    let qr_shot = screen.shot("result-send-qr")?;
    let scanned_qr = read_qr(&qr_shot)?;
    assert_eq!(scanned_qr, token_v4);
    let decoded_qr = CashuToken::decode(&scanned_qr)?;
    assert_eq!(decoded_qr.total_amount(), 20);
    for proof in &decoded_qr.proofs {
        mint.verify_proof(proof)?;
    }
    screen.tap(DONE)?;
    screen.wait_for_log("home on screen")?;

    // 6. Melt 30 sat (+ 4 sat fee reserve, 1 sat actual LN fee -> 3 sat change) (NUT-05)
    println!("[6/6] Melting 30 sat to Lightning invoice (NUT-05)...");
    let prep_melt = submit_and_approve(
        &bridge,
        &mut screen,
        9,
        VaultRequest::PrepareMelt {
            mint_url: MINT_URL.to_owned(),
            quote_id: "q-melt-30".to_owned(),
            invoice: "lnbc300n1p0cashuvault".to_owned(),
            amount: 30,
            fee_reserve: 4,
        },
        "Melt to Lightning",
        "review-melt",
    )?;
    let VaultResponse::MeltPrepared(melt_req) = prep_melt else {
        return Err(format!("expected MeltPrepared, got {prep_melt:?}"));
    };
    let change_sigs = mint.process_melt(&melt_req, 1)?;
    let done_melt = submit_immediate(
        &bridge,
        10,
        VaultRequest::CompleteMelt {
            op_id: melt_req.op_id,
            paid: true,
            change: change_sigs,
        },
    )?;
    assert!(matches!(
        done_melt,
        VaultResponse::MeltCompleted {
            paid: true,
            new_balance_sats: 38,
            ..
        }
    ));

    std::thread::sleep(Duration::from_millis(300));
    screen.shot("final-home")?;
    println!("ALL 6 E2E STEPS PASSED! Final vault balance: 38 sat.");
    Ok(())
}
