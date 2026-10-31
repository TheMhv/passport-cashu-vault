//! Cashu Vault for Passport Prime.
//!
//! Supports all five Cashu operations on Passport Prime:
//! - Mint (NUT-04): deterministic NUT-13 blinding on device + DLEQ verification & unblinding
//! - Receive (NUT-03): scan `cashuA`/`cashuB` tokens and swap into deterministic vault proofs
//! - Swap (NUT-03): consolidate or split vault proofs
//! - Send (NUT-00): export spendable `cashuB` / `cashuA` tokens as QR codes on screen
//! - Melt (NUT-05): verify Lightning invoice & fee reserve, lock inputs + blank change outputs

mod bridge;
mod device;
mod qr;
mod theme;
mod view;

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use cashu_vault_protocol::{CashuToken, VaultRequest, VaultResponse};
use cashu_vault_service::{PendingApproval, ServiceOutcome, VaultService, DEMO_MINT_URL};
use gui_permissions::GuiPermissions;
use slint_keyos_platform::{
    app_ui2,
    gui_server_api::{
        navigation::{
            lockscreen::VerifyPinOptions,
            qrscanner::{MatchedQrResult, ScanQrOptions, ScanQrResult},
        },
        InputMessage,
    },
    navigation::{open_qr_scanner, verify_pin},
    slint::{ComponentHandle, ModelRc, SharedString, Timer},
};
use zeroize::Zeroizing;

app_ui2!("Cashu Vault");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Qr,
    Bridge,
    Interactive,
}

pub struct Screen {
    pub title: String,
    pub message: String,
    pub frames: ModelRc<SharedString>,
    pub secret: bool,
    pub has_next: bool,
}

pub struct App {
    pub vault: VaultService<device::AppDataStorage, device::DevicePlatform>,
    pub waiting: Option<Channel>,
    pub showing_result: bool,
    pub screens: VecDeque<Screen>,
    pub bridge: Option<Timer>,
}

impl App {
    pub fn busy(&self) -> bool {
        self.waiting.is_some() || self.showing_result
    }
}

fn navigate_home(ui: &AppWindow) {
    ui.global::<Navigate>().invoke_main_page(NavigateOptions {
        replace: true,
        animate: Animate::None,
    });
    log::info!("home on screen");
}

fn set_status(ui: &AppWindow, status: &str) {
    ui.global::<Callbacks>().set_status(status.into());
}

fn set_notice(ui: &AppWindow, notice: &str) {
    let callbacks = ui.global::<Callbacks>();
    callbacks.set_status(SharedString::new());
    callbacks.set_notice(notice.into());
}

fn show_pending_review(ui: &AppWindow, app: &Rc<RefCell<App>>, pending: &PendingApproval, channel: Channel) {
    app.borrow_mut().waiting = Some(channel);
    set_notice(ui, "");
    view::show_review(ui, pending);
    ui.global::<Navigate>().invoke_review_page(NavigateOptions {
        replace: false,
        animate: Animate::None,
    });
    log::info!("review on screen: {}", pending.review.title);
}

pub fn handle_message(ui: &AppWindow, app: &Rc<RefCell<App>>, bytes: &[u8], channel: Channel) {
    let outcome = app.borrow_mut().vault.handle(bytes);
    match outcome {
        ServiceOutcome::Reply(reply) => deliver(ui, app, channel, reply, None, None),
        ServiceOutcome::NeedsApproval(pending) => show_pending_review(ui, app, &pending, channel),
    }
}

fn deliver(
    ui: &AppWindow,
    app: &Rc<RefCell<App>>,
    channel: Channel,
    reply: Vec<u8>,
    show_token: Option<Zeroizing<String>>,
    decided: Option<&str>,
) {
    let mut screens = VecDeque::new();
    if let Some(token) = show_token {
        screens.push_back(Screen {
            title: "Scan Cashu Token".to_owned(),
            message: "Scan with any Cashu wallet (Minibits, Cashu.me, Nutshell, CDK).".to_owned(),
            frames: qr::static_frame(&token),
            secret: true,
            has_next: false,
        });
    }
    match channel {
        Channel::Qr => screens.push_back(Screen {
            title: "Answer for Relay".to_owned(),
            message: "Scan this animated QR code with your companion wallet or relay.".to_owned(),
            frames: qr::response_frames(&reply),
            secret: false,
            has_next: false,
        }),
        Channel::Bridge => bridge::write_reply(&reply),
        Channel::Interactive => {}
    }

    view::refresh_home(ui, &app.borrow().vault);
    if let Some(decided) = decided {
        set_notice(ui, decided);
    }

    let count = screens.len();
    for (index, screen) in screens.iter_mut().enumerate() {
        screen.has_next = index + 1 < count;
    }
    let first = screens.pop_front();
    {
        let mut app = app.borrow_mut();
        app.screens = screens;
        app.showing_result = first.is_some();
    }
    match first {
        Some(screen) => {
            view::show_screen(ui, &screen);
            ui.global::<Navigate>().invoke_result_page(NavigateOptions {
                replace: true,
                animate: Animate::None,
            });
            log::info!("result on screen: {}", screen.title);
        }
        None if decided.is_some() => navigate_home(ui),
        None => {}
    }
}

fn active_mint_url(app: &Rc<RefCell<App>>) -> String {
    app.borrow()
        .vault
        .info()
        .mints
        .first()
        .map(|m| m.url.clone())
        .unwrap_or_else(|| DEMO_MINT_URL.to_owned())
}

fn start_interactive_request(ui: &AppWindow, app: &Rc<RefCell<App>>, request: VaultRequest) {
    let res = app.borrow_mut().vault.start_interactive(request);
    match res {
        Ok(pending) => show_pending_review(ui, app, &pending, Channel::Interactive),
        Err(err) => set_status(ui, &err),
    }
}

fn action_mint(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let mint_url = active_mint_url(app);
    start_interactive_request(
        ui,
        app,
        VaultRequest::PrepareMint {
            mint_url,
            quote_id: "quote-on-device-64".to_owned(),
            amount: 64,
        },
    );
}

fn action_receive(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let demo_mode = app.borrow().vault.policy().demo_mode;
    if demo_mode {
        let token = match app.borrow_mut().vault.create_demo_incoming_token(25) {
            Ok(t) => t,
            Err(e) => {
                set_status(ui, &e);
                return;
            }
        };
        start_interactive_request(ui, app, VaultRequest::PrepareReceive { token });
    } else {
        scan_request(ui, app);
    }
}

fn action_swap(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let mint_url = active_mint_url(app);
    start_interactive_request(
        ui,
        app,
        VaultRequest::PrepareSwap {
            mint_url,
            target_amount: None,
        },
    );
}

fn action_send(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let mint_url = active_mint_url(app);
    let bal = app.borrow().vault.info().total_balance_sats;
    let amount = if bal > 0 && bal < 16 { bal } else { 16 };
    start_interactive_request(
        ui,
        app,
        VaultRequest::SendToken {
            mint_url,
            amount,
            memo: Some("Sent from Passport Prime".to_owned()),
        },
    );
}

fn action_melt(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let mint_url = active_mint_url(app);
    start_interactive_request(
        ui,
        app,
        VaultRequest::PrepareMelt {
            mint_url,
            quote_id: "melt-quote-20".to_owned(),
            invoice: "lnbc200n1p0passportvault".to_owned(),
            amount: 20,
            fee_reserve: 2,
        },
    );
}

fn scan_request(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let options = ScanQrOptions {
        header_title: "Scan Cashu Token or Request".into(),
        message: "Show a cashuA/cashuB token QR or a Cashu Vault request.".into(),
        ..ScanQrOptions::default()
    };
    let scan = match open_qr_scanner::<GuiPermissions>(options) {
        Ok(Some(scan)) => scan,
        Ok(None) => return,
        Err(error) => {
            set_status(ui, &format!("Scanner unavailable: {error:?}"));
            return;
        }
    };
    match scan {
        ScanQrResult::Ur2 { ur_type, data, .. } => {
            if ur_type.eq_ignore_ascii_case("bytes") {
                if let Some(token) = CashuToken::extract_from_ur_bytes(&data) {
                    #[cfg(not(keyos))]
                    bridge::save_last_scanned_qr(&token);
                    start_interactive_request(ui, app, VaultRequest::PrepareReceive { token });
                    return;
                }
            }
            match qr::request_payload(&ur_type, data) {
                Ok(bytes) => handle_message(ui, app, &bytes, Channel::Qr),
                Err(message) => set_status(ui, &message),
            }
        }
        ScanQrResult::Qr { data, .. } => {
            let text = String::from_utf8_lossy(&data);
            let trimmed = text.trim_matches(|c: char| c.is_whitespace() || c.is_control());
            #[cfg(not(keyos))]
            bridge::save_last_scanned_qr(trimmed);
            if trimmed.starts_with("cashu")
                || trimmed.starts_with("CASHU")
                || trimmed.starts_with("web+cashu")
            {
                start_interactive_request(
                    ui,
                    app,
                    VaultRequest::PrepareReceive {
                        token: trimmed.to_owned(),
                    },
                );
            } else {
                set_status(ui, "Unrecognized QR code: expected cashu token or UR request.");
            }
        }
        _ => {}
    }
}

fn approve(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let require_pin = match app.borrow().vault.pending_approval() {
        Some(pending) => pending.review.require_pin,
        None => return,
    };
    let pin_verified = if require_pin {
        let result = verify_pin::<GuiPermissions>(VerifyPinOptions {
            title: Some("Confirm with your PIN".into()),
            want_security_words: false,
        });
        match result {
            Ok(result) if result.success => true,
            Ok(_) => return,
            Err(error) => {
                set_status(ui, &format!("PIN check unavailable: {error:?}"));
                return;
            }
        }
    } else {
        false
    };

    #[allow(unused_mut)]
    let mut channel = app.borrow().waiting.unwrap_or(Channel::Interactive);
    let approved = app.borrow_mut().vault.approve(pin_verified);
    match approved {
        Ok(mut outcome) => {
            app.borrow_mut().waiting = None;
            if channel == Channel::Interactive {
                if let VaultResponse::SwapPrepared(mut req) = outcome.response.clone() {
                    if req.mint_url != DEMO_MINT_URL {
                        #[cfg(not(keyos))]
                        {
                            let mut swap_res =
                                bridge::post_swap_http(&req.mint_url, &req.inputs, &req.outputs);
                            for _ in 0..16 {
                                match &swap_res {
                                    Err(err) if bridge::is_duplicate_output_error(err) => {
                                        match app.borrow_mut().vault.reblind_pending_swap(req.clone()) {
                                            Ok(new_req) => {
                                                req = new_req;
                                                swap_res = bridge::post_swap_http(
                                                    &req.mint_url,
                                                    &req.inputs,
                                                    &req.outputs,
                                                );
                                            }
                                            Err(e) => {
                                                swap_res = Err(e);
                                                break;
                                            }
                                        }
                                    }
                                    _ => break,
                                }
                            }
                            match swap_res {
                                Ok(sigs) => {
                                    match app.borrow_mut().vault.complete_swap(&req.op_id, &sigs) {
                                        Ok(VaultResponse::SwapCompleted { net_sats, .. }) => {
                                            outcome.notice =
                                                format!("Received +{net_sats} sat into vault");
                                        }
                                        Ok(_) => {}
                                        Err((_, msg)) => {
                                            view::refresh_home(ui, &app.borrow().vault);
                                            set_status(ui, &format!("Swap failed: {msg}"));
                                            navigate_home(ui);
                                            return;
                                        }
                                    }
                                }
                                Err(err) => {
                                    view::refresh_home(ui, &app.borrow().vault);
                                    set_status(ui, &format!("Mint swap failed: {err}"));
                                    navigate_home(ui);
                                    return;
                                }
                            }
                        }
                        #[cfg(keyos)]
                        {
                            channel = Channel::Qr;
                        }
                    }
                }
            }
            deliver(
                ui,
                app,
                channel,
                outcome.reply_bytes,
                outcome.show_token_qr,
                Some(&outcome.notice),
            );
        }
        Err(error) => set_status(ui, &format!("Not approved: {error}")),
    }
}

fn reject(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let channel = app.borrow().waiting.unwrap_or(Channel::Interactive);
    let title = app
        .borrow()
        .vault
        .pending_approval()
        .map(|p| p.review.title.clone());
    let rejected = app.borrow_mut().vault.reject();
    app.borrow_mut().waiting = None;
    if let Some(reply) = rejected {
        let decided = format!("Declined: {}", title.unwrap_or_default());
        deliver(ui, app, channel, reply, None, Some(&decided));
    }
}

fn next_screen(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let next = app.borrow_mut().screens.pop_front();
    match next {
        Some(screen) => {
            view::show_screen(ui, &screen);
            log::info!("result on screen: {}", screen.title);
        }
        None => leave_results(ui, app),
    }
}

fn leave_results(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    ui.global::<Callbacks>()
        .set_result_frames(ModelRc::default());
    let mut app = app.borrow_mut();
    app.screens.clear();
    app.showing_result = false;
    drop(app);
    navigate_home(ui);
}

fn scan_next(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    leave_results(ui, app);
    scan_request(ui, app);
}

fn settings_changed(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    let policy = view::policy_from_settings(ui, app.borrow().vault.policy());
    let saved = app.borrow_mut().vault.set_policy(policy);
    match saved {
        Ok(()) => {
            view::load_settings(ui, app.borrow().vault.policy());
            view::refresh_home(ui, &app.borrow().vault);
        }
        Err(error) => set_status(ui, &format!("Settings not saved: {error}")),
    }
}

fn forget_mint(ui: &AppWindow, app: &Rc<RefCell<App>>, index: i32) {
    let callbacks = ui.global::<Callbacks>();
    if callbacks.get_forget_armed() != index {
        callbacks.set_forget_armed(index);
        return;
    }
    callbacks.set_forget_armed(-1);
    let mint_url = usize::try_from(index)
        .ok()
        .and_then(|idx| app.borrow().vault.info().mints.get(idx).map(|m| m.url.clone()));
    let Some(mint_url) = mint_url else {
        return;
    };
    let removed = app.borrow_mut().vault.remove_mint(&mint_url);
    match removed {
        Ok(()) => {
            view::load_settings(ui, app.borrow().vault.policy());
            view::refresh_home(ui, &app.borrow().vault);
            set_notice(ui, &format!("Removed mint {mint_url}"));
        }
        Err(error) => set_status(ui, &format!("Could not remove mint: {error}")),
    }
}

fn launcher_request(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let matched = MatchedQrResult::from_slice(bytes)
        .ok_or_else(|| "Could not read Launcher QR result.".to_owned())?;
    match matched.scan_result {
        ScanQrResult::Ur2 { ur_type, data, .. } => qr::request_payload(&ur_type, data),
        _ => Err("Not a Cashu Vault UR request.".to_owned()),
    }
}

fn open(ui: &AppWindow) -> Option<Rc<RefCell<App>>> {
    let seed = match device::app_seed() {
        Ok(seed) => Zeroizing::new(seed),
        Err(error) => {
            log::error!("{error}");
            set_status(
                ui,
                "Cannot read app seed. Reopen and allow access to the seed.",
            );
            return None;
        }
    };

    #[cfg(not(keyos))]
    if bridge::take_reset() {
        match device::AppDataStorage.wipe() {
            Ok(()) => log::warn!("simulator: wiped stored vault state"),
            Err(error) => log::error!("simulator: {error}"),
        }
    }

    let vault = match VaultService::open(*seed, device::AppDataStorage, device::DevicePlatform) {
        Ok(vault) => vault,
        Err(error) => {
            log::error!("cannot open vault: {error}");
            set_status(ui, &format!("Cannot open vault: {error}"));
            return None;
        }
    };
    drop(seed);

    let app = Rc::new(RefCell::new(App {
        vault,
        waiting: None,
        showing_result: false,
        screens: VecDeque::new(),
        bridge: None,
    }));
    view::refresh_home(ui, &app.borrow().vault);
    view::load_settings(ui, app.borrow().vault.policy());
    let bridge = bridge::start(ui.as_weak(), app.clone());
    app.borrow_mut().bridge = bridge;
    log::info!("vault open");
    Some(app)
}

const OPEN_DELAY: Duration = Duration::from_millis(100);
type Slot = Rc<OnceCell<Rc<RefCell<App>>>>;

fn when_open(
    ui: &AppWindow,
    slot: &Slot,
    action: fn(&AppWindow, &Rc<RefCell<App>>),
) -> impl Fn() + 'static {
    let (ui, slot) = (ui.as_weak(), slot.clone());
    move || {
        if let (Some(ui), Some(app)) = (ui.upgrade(), slot.get()) {
            action(&ui, app);
        }
    }
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Cashu Vault starting");

    theme::init(&ui);
    ui.global::<Utils>()
        .on_qrcode(slint_keyos_platform::qrcode::render);

    let slot: Slot = Rc::default();
    let callbacks = ui.global::<Callbacks>();
    callbacks.on_action_mint(when_open(&ui, &slot, action_mint));
    callbacks.on_action_receive(when_open(&ui, &slot, action_receive));
    callbacks.on_action_swap(when_open(&ui, &slot, action_swap));
    callbacks.on_action_send(when_open(&ui, &slot, action_send));
    callbacks.on_action_melt(when_open(&ui, &slot, action_melt));
    callbacks.on_scan_request(when_open(&ui, &slot, scan_request));
    callbacks.on_approve(when_open(&ui, &slot, approve));
    callbacks.on_reject(when_open(&ui, &slot, reject));
    callbacks.on_next(when_open(&ui, &slot, next_screen));
    callbacks.on_scan_next(when_open(&ui, &slot, scan_next));
    callbacks.on_settings_changed(when_open(&ui, &slot, settings_changed));
    callbacks.on_forget_mint({
        let (ui, slot) = (ui.as_weak(), slot.clone());
        move |index| {
            if let (Some(ui), Some(app)) = (ui.upgrade(), slot.get()) {
                forget_mint(&ui, app, index);
            }
        }
    });

    let launched: Rc<RefCell<Option<Vec<u8>>>> = Rc::default();
    let opening = Rc::new(Cell::new(false));
    cx.set_input_handler({
        let gui = cx.gui.clone();
        let ui = ui.as_weak();
        move |input| {
            let Some(window) = ui.upgrade() else { return };
            match input.msg {
                InputMessage::Visible if slot.get().is_none() && !opening.get() => {
                    opening.set(true);
                    let (ui, slot, launched, opening) =
                        (ui.clone(), slot.clone(), launched.clone(), opening.clone());
                    Timer::single_shot(OPEN_DELAY, move || {
                        let Some(ui) = ui.upgrade() else { return };
                        let Some(app) = open(&ui) else {
                            opening.set(false);
                            return;
                        };
                        let _ = slot.set(app.clone());
                        let request = launched.borrow_mut().take();
                        if let Some(request) = request {
                            handle_message(&ui, &app, &request, Channel::Qr);
                        }
                    });
                }
                InputMessage::NavigationFocused => {
                    let Ok(Some(bytes)) = gui.navigate_pending() else {
                        return;
                    };
                    match (launcher_request(&bytes), slot.get()) {
                        (Ok(request), Some(app)) => {
                            handle_message(&window, app, &request, Channel::Qr)
                        }
                        (Ok(request), None) => *launched.borrow_mut() = Some(request),
                        (Err(message), _) => set_status(&window, &message),
                    }
                }
                _ => {}
            }
        }
    });

    ui.run().expect("UI running");
}
