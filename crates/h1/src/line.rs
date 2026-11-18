use crate::error::Error;

pub fn find(input: &[u8], pattern: &[u8]) -> Option<usize> {
    input
        .windows(pattern.len())
        .position(|window| window == pattern)
}

pub fn clean(region: &[u8]) -> Result<(), Error> {
    for (at, byte) in region.iter().enumerate() {
        let before = at.checked_sub(1).and_then(|prior| region.get(prior));
        let after = region.get(at + 1);
        let bare = match byte {
            b'\n' => before != Some(&b'\r'),
            b'\r' => after.is_some_and(|next| *next != b'\n'),
            _ => false,
        };
        if bare {
            return Err(Error::Line);
        }
    }
    Ok(())
}

pub fn blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

pub fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !blank(*byte))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !blank(*byte))
        .map_or(start, |last| last + 1);
    &bytes[start..end]
}
