//! Animated UR QR codes (`cashu-vault-req` and `cashu-vault-res`) for Passport Prime.

use foundation_ur::bytewords::{self, Style};
use foundation_ur::fountain::part::Part;
use foundation_ur::{Decoder, Encoder, UR};

pub const UR_TYPE_REQUEST: &str = "cashu-vault-req";
pub const UR_TYPE_RESPONSE: &str = "cashu-vault-res";
pub const MAX_PART_CHARS: usize = 300;
pub const MAX_MESSAGE_SIZE: usize = 65_536;
const MAX_SEQUENCE: usize = 1_000;

/// Encode a CBOR message into one or more looping uppercase UR frames sized for Passport Prime's screen.
pub fn encode(ur_type: &str, message: &[u8]) -> Vec<String> {
    if message.is_empty() {
        return vec![foundation_ur::to_string(ur_type, message).to_ascii_uppercase()];
    }
    let fragment_len = foundation_ur::max_fragment_len(ur_type, MAX_SEQUENCE, MAX_PART_CHARS);
    let mut encoder = Encoder::new();
    encoder.start(ur_type, message, fragment_len);
    (0..encoder.sequence_count())
        .map(|_| encoder.next_part().to_string().to_ascii_uppercase())
        .collect()
}

/// Validate a reassembled UR payload from KeyOS's scanner.
pub fn scanned_message(expected: &str, ur_type: &str, data: Vec<u8>) -> Result<Vec<u8>, String> {
    if !ur_type.eq_ignore_ascii_case(expected) {
        return Err(format!("expected UR type '{expected}', got '{ur_type}'"));
    }
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(format!(
            "UR payload size {} exceeds limit {MAX_MESSAGE_SIZE}",
            data.len()
        ));
    }
    Ok(data)
}

/// Multi-part UR fountain decoder for the host/phone side.
pub struct PartDecoder {
    expected: String,
    decoder: Decoder,
}

impl PartDecoder {
    pub fn new(expected: &str) -> Self {
        Self {
            expected: expected.to_owned(),
            decoder: Decoder::default(),
        }
    }

    pub fn receive(&mut self, part: &str) -> Result<Option<Vec<u8>>, String> {
        let text = part.trim().to_ascii_lowercase();
        let ur = UR::parse(&text).map_err(|e| format!("invalid UR: {e:?}"))?;
        if ur.as_type() != self.expected {
            return Err(format!(
                "expected UR type '{}', got '{}'",
                self.expected,
                ur.as_type()
            ));
        }
        let encoded = ur
            .as_bytewords()
            .ok_or_else(|| "UR has no payload".to_owned())?;
        let payload = bytewords::decode(encoded, Style::Minimal)
            .map_err(|e| format!("bytewords decode error: {e:?}"))?;
        if ur.is_single_part() {
            return Ok(Some(payload));
        }
        let header: Part<'_> =
            minicbor::decode(&payload).map_err(|e| format!("part header error: {e}"))?;
        if header.message_length > MAX_MESSAGE_SIZE {
            return Err("UR message too large".to_owned());
        }
        self.decoder
            .receive(UR::MultiPartDeserialized {
                ur_type: ur.as_type(),
                fragment: header,
            })
            .map_err(|e| format!("fountain receive error: {e:?}"))?;
        if !self.decoder.is_complete() {
            return Ok(None);
        }
        let msg = self
            .decoder
            .message()
            .map_err(|e| format!("fountain message error: {e:?}"))?
            .ok_or_else(|| "complete UR has empty message".to_owned())?;
        Ok(Some(msg.to_vec()))
    }
}
