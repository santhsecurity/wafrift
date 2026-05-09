pub fn serialize(payload: &str) -> Vec<u8> {
    let p_body = super::protobuf::serialize(payload);
    let mut out = Vec::new();
    out.push(0x00); // no compression
    out.extend_from_slice(&(p_body.len() as u32).to_be_bytes());
    out.extend_from_slice(&p_body);
    out
}

pub fn deserialize(bytes: &[u8]) -> String {
    if bytes.len() < 5 {
        return String::new();
    }
    // Skip compression flag (1 byte) and length (4 bytes)
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + len {
        return String::new();
    }
    super::protobuf::deserialize(&bytes[5..5 + len])
}
