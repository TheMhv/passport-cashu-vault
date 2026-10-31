//! Transports for `cashu-vault`: animated UR QR codes and the simulator file bridge.

pub mod bridge;
pub mod ur;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ur_single_and_multipart_roundtrip() {
        let msg = vec![0x42u8; 640];
        let parts = ur::encode(ur::UR_TYPE_RESPONSE, &msg);
        assert!(parts.len() > 1);
        let mut decoder = ur::PartDecoder::new(ur::UR_TYPE_RESPONSE);
        let mut recovered = None;
        for part in &parts {
            if let Some(done) = decoder.receive(part).expect("valid UR part") {
                recovered = Some(done);
                break;
            }
        }
        assert_eq!(recovered.expect("decoded"), msg);
    }
}
