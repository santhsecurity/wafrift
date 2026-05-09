pub fn serialize(payload: &str) -> Vec<u8> {
    // Basic mock: fixmap(1) { fixstr(7)"payload" => fixstr(len)payload }
    let mut out = vec![0x81, 0xA7];
    out.extend_from_slice(b"payload");
    let len = payload.len();
    if len <= 31 {
        out.push(0xA0 | (len as u8));
    } else if len <= 255 {
        out.push(0xD9); // str8
        out.push(len as u8);
    } else {
        out.push(0xDA); // str16
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(payload.as_bytes());
    out
}

pub fn deserialize(bytes: &[u8]) -> String {
    // Parse fixmap(1) { fixstr(7)"payload" => fixstr(len)payload }
    if bytes.len() < 9 {
        return String::new();
    }
    // Skip: 0x81 (fixmap 1), 0xA7 (fixstr 7), "payload" (7 bytes)
    let mut idx = 9;
    if idx >= bytes.len() {
        return String::new();
    }
    let len = match bytes[idx] {
        b if b & 0xE0 == 0xA0 => {
            // fixstr
            idx += 1;
            (b & 0x1F) as usize
        }
        0xD9 => {
            // str8
            if idx + 1 >= bytes.len() {
                return String::new();
            }
            idx += 2;
            bytes[idx - 1] as usize
        }
        0xDA => {
            // str16
            if idx + 2 >= bytes.len() {
                return String::new();
            }
            idx += 3;
            u16::from_be_bytes([bytes[idx - 2], bytes[idx - 1]]) as usize
        }
        _ => return String::new(),
    };
    if idx + len > bytes.len() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[idx..idx + len]).into_owned()
}
