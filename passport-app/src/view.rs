//! Synchronizes `VaultService` state with the Slint UI.

use cashu_vault_service::{PendingApproval, Platform, Storage, VaultPolicy, VaultService};
use slint_keyos_platform::slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::{AppWindow, Callbacks, MintRow, ReviewRow, Screen};

pub const DEFAULT_PIN_THRESHOLD_SATS: u64 = 500;

pub fn refresh_home<S: Storage, P: Platform>(ui: &AppWindow, vault: &VaultService<S, P>) {
    let info = vault.info();
    let callbacks = ui.global::<Callbacks>();
    callbacks.set_balance_sats(format!("{} sat", info.total_balance_sats).into());
    let summary = match &info.pending_op {
        Some(pending) => format!("{} proofs · {pending}", info.total_proofs),
        None => format!(
            "{} proof{} across {} mint{}",
            info.total_proofs,
            if info.total_proofs == 1 { "" } else { "s" },
            info.mints.len(),
            if info.mints.len() == 1 { "" } else { "s" }
        ),
    };
    callbacks.set_proof_summary(summary.into());

    let rows: Vec<MintRow> = info
        .mints
        .into_iter()
        .map(|m| MintRow {
            name: m.url.into(),
            detail: format!(
                "{} sat · {} proof{} · keyset {}",
                m.balance_sats,
                m.proof_count,
                if m.proof_count == 1 { "" } else { "s" },
                &m.active_keyset_id[..m.active_keyset_id.len().min(12)]
            )
            .into(),
        })
        .collect();
    callbacks.set_mints(ModelRc::new(VecModel::from(rows)));
}

pub fn show_review(ui: &AppWindow, pending: &PendingApproval) {
    let review = &pending.review;
    let callbacks = ui.global::<Callbacks>();
    callbacks.set_review_title(review.title.clone().into());
    callbacks.set_review_amount(review.amount.clone().into());
    let rows: Vec<ReviewRow> = review
        .rows
        .iter()
        .map(|r| ReviewRow {
            label: r.label.clone().into(),
            value: r.value.clone().into(),
        })
        .collect();
    callbacks.set_review_rows(ModelRc::new(VecModel::from(rows)));
    let warnings: Vec<SharedString> = review.warnings.iter().map(|w| w.clone().into()).collect();
    callbacks.set_review_warnings(ModelRc::new(VecModel::from(warnings)));
    callbacks.set_review_needs_pin(review.require_pin);
}

pub fn show_screen(ui: &AppWindow, screen: &Screen) {
    let callbacks = ui.global::<Callbacks>();
    callbacks.set_result_title(screen.title.clone().into());
    callbacks.set_result_message(screen.message.clone().into());
    callbacks.set_result_frames(screen.frames.clone());
    callbacks.set_result_secret(screen.secret);
    callbacks.set_result_has_next(screen.has_next);
}

pub fn load_settings(ui: &AppWindow, policy: &VaultPolicy) {
    let callbacks = ui.global::<Callbacks>();
    callbacks.set_setting_pin(policy.pin_threshold_sats < u64::MAX);
    callbacks.set_setting_verify_dleq(policy.verify_dleq);
    callbacks.set_setting_demo_mode(policy.demo_mode);
    callbacks.set_setting_summary(
        format!(
            "Key scheme: cashu-vault-nut13-v1 (BIP-32 m/129372'/0'). PIN threshold: {} sats.",
            if policy.pin_threshold_sats == u64::MAX {
                "off".to_owned()
            } else {
                policy.pin_threshold_sats.to_string()
            }
        )
        .into(),
    );
}

pub fn policy_from_settings(ui: &AppWindow, current: &VaultPolicy) -> VaultPolicy {
    let callbacks = ui.global::<Callbacks>();
    VaultPolicy {
        pin_threshold_sats: if callbacks.get_setting_pin() {
            DEFAULT_PIN_THRESHOLD_SATS
        } else {
            u64::MAX
        },
        require_pin_always: current.require_pin_always,
        verify_dleq: callbacks.get_setting_verify_dleq(),
        demo_mode: callbacks.get_setting_demo_mode(),
    }
}
