//! Control frame payloads (MASK_OFFER / ACK / HEALTH / BACKOFF).

use bytes::{BufMut, Bytes, BytesMut};

use crate::frame::{bodies, CtrlType, Frame};

pub fn mask_offer(profile_id: &str, pack_hash_hex: &str) -> Frame {
    let mut b = BytesMut::new();
    put_str(&mut b, profile_id);
    put_str(&mut b, pack_hash_hex);
    bodies::control(CtrlType::MaskOffer as u16, &b)
}

pub fn mask_ack(profile_id: &str, applied: bool) -> Frame {
    let mut b = BytesMut::new();
    put_str(&mut b, profile_id);
    b.put_u8(if applied { 1 } else { 0 });
    bodies::control(CtrlType::MaskAck as u16, &b)
}

pub fn health(rtt_ms: u32, loss_permille: u16) -> Frame {
    let mut b = BytesMut::new();
    b.put_u32(rtt_ms);
    b.put_u16(loss_permille);
    bodies::control(CtrlType::Health as u16, &b)
}

pub fn backoff(ms: u32, reason: u16) -> Frame {
    let mut b = BytesMut::new();
    b.put_u32(ms);
    b.put_u16(reason);
    bodies::control(CtrlType::Backoff as u16, &b)
}

pub fn parse_ctrl(frame: &Frame) -> Option<(CtrlType, Bytes)> {
    if frame.body.len() < 2 {
        return None;
    }
    let t = u16::from_be_bytes(frame.body[0..2].try_into().ok()?);
    let ctrl = match t {
        1 => CtrlType::Caps,
        2 => CtrlType::MaskOffer,
        3 => CtrlType::MaskAck,
        4 => CtrlType::Health,
        5 => CtrlType::Backoff,
        6 => CtrlType::Rekey,
        7 => CtrlType::Close,
        8 => CtrlType::Ticket,
        _ => return None,
    };
    Some((ctrl, frame.body.slice(2..)))
}

pub fn parse_mask_offer(payload: &[u8]) -> Option<(String, String)> {
    let (a, rest) = take_str(payload)?;
    let (b, _) = take_str(rest)?;
    Some((a, b))
}

pub fn parse_mask_ack(payload: &[u8]) -> Option<(String, bool)> {
    let (id, rest) = take_str(payload)?;
    let applied = *rest.first()? != 0;
    Some((id, applied))
}

pub fn parse_health(payload: &[u8]) -> Option<(u32, u16)> {
    if payload.len() < 6 {
        return None;
    }
    let rtt = u32::from_be_bytes(payload[0..4].try_into().ok()?);
    let loss = u16::from_be_bytes(payload[4..6].try_into().ok()?);
    Some((rtt, loss))
}

pub fn parse_backoff(payload: &[u8]) -> Option<(u32, u16)> {
    if payload.len() < 6 {
        return None;
    }
    let ms = u32::from_be_bytes(payload[0..4].try_into().ok()?);
    let reason = u16::from_be_bytes(payload[4..6].try_into().ok()?);
    Some((ms, reason))
}

fn put_str(b: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    b.put_u16(bytes.len() as u16);
    b.extend_from_slice(bytes);
}

fn take_str(input: &[u8]) -> Option<(String, &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes(input[0..2].try_into().ok()?) as usize;
    if input.len() < 2 + n {
        return None;
    }
    let s = String::from_utf8_lossy(&input[2..2 + n]).to_string();
    Some((s, &input[2 + n..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    #[test]
    fn mask_offer_ack_roundtrip() {
        let f = mask_offer("tls13_stable", "deadbeef");
        assert_eq!(f.ty, FrameType::Control);
        let (t, p) = parse_ctrl(&f).unwrap();
        assert_eq!(t, CtrlType::MaskOffer);
        let (id, hash) = parse_mask_offer(&p).unwrap();
        assert_eq!(id, "tls13_stable");
        assert_eq!(hash, "deadbeef");

        let ack = mask_ack(&id, true);
        let (t2, p2) = parse_ctrl(&ack).unwrap();
        assert_eq!(t2, CtrlType::MaskAck);
        let (id2, ok) = parse_mask_ack(&p2).unwrap();
        assert_eq!(id2, id);
        assert!(ok);
    }
}
