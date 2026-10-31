//! Simulator file bridge (`$CASHU_VAULT_SIM_DIR` or `~/.cashu-vault-sim`).

#[cfg(not(keyos))]
mod hosted {
    use std::cell::RefCell;
    use std::process::Command;
    use std::rc::Rc;
    use std::time::Duration;

    use cashu_vault_protocol::{
        decode_signatures_http_response, encode_swap_http_request, BlindSignature, BlindedMessage,
        Proof,
    };
    use cashu_vault_transport::bridge::Bridge;
    use slint_keyos_platform::slint::{Timer, TimerMode, Weak};

    use crate::{App, AppWindow, Channel};

    const POLL: Duration = Duration::from_millis(200);

    pub fn pinned_app_seed() -> Result<Option<[u8; 32]>, String> {
        Bridge::from_env().pinned_app_seed()
    }

    pub fn pin_app_seed(seed: &[u8; 32]) -> Result<(), String> {
        Bridge::from_env()
            .pin_app_seed(seed)
            .map_err(|e| e.to_string())
    }

    pub fn take_reset() -> bool {
        Bridge::from_env().take_reset()
    }

    pub fn post_swap_http(
        mint_url: &str,
        inputs: &[Proof],
        outputs: &[BlindedMessage],
    ) -> Result<Vec<BlindSignature>, String> {
        let body = encode_swap_http_request(inputs, outputs)?;
        let url = format!("{}/v1/swap", mint_url.trim_end_matches('/'));
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
                &body,
                &url,
            ])
            .output()
            .map_err(|e| format!("failed to run curl for POST {url}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "curl POST {url} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        decode_signatures_http_response(&out.stdout)
    }

    pub fn is_duplicate_output_error(err: &str) -> bool {
        err.contains("\"code\":20006")
            || err.contains("\"code\": 20006")
            || err.contains("Invoice already paid")
            || err.contains("\"code\":11003")
            || err.contains("\"code\": 11003")
            || err.contains("Outputs already signed")
            || err.contains("\"code\":11004")
            || err.contains("\"code\": 11004")
            || err.contains("Outputs are pending")
    }

    pub fn start(ui: Weak<AppWindow>, app: Rc<RefCell<App>>) -> Option<Timer> {
        let bridge = Bridge::from_env();
        if let Err(error) = bridge.create() {
            log::error!(
                "simulator bridge disabled: cannot create {}: {error}",
                bridge.root().display()
            );
            return None;
        }
        log::info!("simulator bridge watching {}", bridge.inbox().display());
        let timer = Timer::default();
        timer.start(TimerMode::Repeated, POLL, move || {
            let Some(ui) = ui.upgrade() else { return };
            if app.borrow().busy() {
                return;
            }
            match bridge.take_request() {
                Ok(Some(bytes)) => crate::handle_message(&ui, &app, &bytes, Channel::Bridge),
                Ok(None) => {}
                Err(error) => log::warn!("simulator bridge: cannot take request: {error}"),
            }
        });
        Some(timer)
    }

    pub fn write_reply(reply: &[u8]) {
        if let Err(error) = Bridge::from_env().write_response(reply) {
            log::error!("simulator bridge: cannot write answer: {error}");
        }
    }

    pub fn save_last_scanned_qr(raw: &str) {
        let bridge = Bridge::from_env();
        let path = bridge.root().join("last-scanned-qr.txt");
        let _ = std::fs::write(path, raw.as_bytes());
    }
}

#[cfg(not(keyos))]
pub use hosted::{
    is_duplicate_output_error, pin_app_seed, pinned_app_seed, post_swap_http, save_last_scanned_qr,
    start, take_reset, write_reply,
};

#[cfg(keyos)]
pub fn start(
    _ui: slint_keyos_platform::slint::Weak<crate::AppWindow>,
    _app: std::rc::Rc<std::cell::RefCell<crate::App>>,
) -> Option<slint_keyos_platform::slint::Timer> {
    None
}

#[cfg(keyos)]
pub fn write_reply(_reply: &[u8]) {
    log::error!("the simulator bridge does not exist on the device");
}
