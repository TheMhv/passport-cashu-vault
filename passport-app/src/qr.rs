//! Animated UR QR and static `cashuB` QR frame helpers.

use cashu_vault_transport::ur::{self, UR_TYPE_REQUEST, UR_TYPE_RESPONSE};
use slint_keyos_platform::slint::{ModelRc, SharedString, VecModel};

pub fn request_payload(ur_type: &str, data: Vec<u8>) -> Result<Vec<u8>, String> {
    ur::scanned_message(UR_TYPE_REQUEST, ur_type, data)
}

fn model(frames: Vec<String>) -> ModelRc<SharedString> {
    let frames: Vec<SharedString> = frames.into_iter().map(SharedString::from).collect();
    ModelRc::new(VecModel::from(frames))
}

pub fn response_frames(reply: &[u8]) -> ModelRc<SharedString> {
    model(ur::encode(UR_TYPE_RESPONSE, reply))
}

pub fn static_frame(text: &str) -> ModelRc<SharedString> {
    model(vec![text.to_owned()])
}
