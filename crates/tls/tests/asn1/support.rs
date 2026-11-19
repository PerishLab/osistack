use tls::x509::Time;

pub fn when(date: (u16, u8, u8), clock: (u8, u8, u8)) -> Time {
    Time {
        year: date.0,
        month: date.1,
        day: date.2,
        hour: clock.0,
        minute: clock.1,
        second: clock.2,
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let size = content.len();
    let mut out = vec![tag];
    if size < 128 {
        out.push(size as u8);
    } else {
        let raw: Vec<u8> = size
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | raw.len() as u8);
        out.extend(raw);
    }
    out.extend_from_slice(content);
    out
}
