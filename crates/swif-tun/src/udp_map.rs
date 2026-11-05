//! UDP mapping wire format inside DATAGRAM payload (MVP IPv4).

/// Payload: atype(1)=1 | ipv4(4) | port(2 BE) | data
pub fn encode_udp4(dst: [u8; 4], port: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + data.len());
    v.push(1);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&port.to_be_bytes());
    v.extend_from_slice(data);
    v
}

pub fn decode_udp4(payload: &[u8]) -> Option<([u8; 4], u16, &[u8])> {
    if payload.len() < 7 || payload[0] != 1 {
        return None;
    }
    let mut ip = [0u8; 4];
    ip.copy_from_slice(&payload[1..5]);
    let port = u16::from_be_bytes([payload[5], payload[6]]);
    Some((ip, port, &payload[7..]))
}

/// Reply payload: same header + response data (from edge → client).
pub fn encode_udp4_reply(src: [u8; 4], port: u16, data: &[u8]) -> Vec<u8> {
    encode_udp4(src, port, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp4_roundtrip() {
        let p = encode_udp4([1, 2, 3, 4], 53, b"dns");
        let (ip, port, data) = decode_udp4(&p).unwrap();
        assert_eq!(ip, [1, 2, 3, 4]);
        assert_eq!(port, 53);
        assert_eq!(data, b"dns");
    }
}
