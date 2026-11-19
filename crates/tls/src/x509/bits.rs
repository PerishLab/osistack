use super::Flaw;

pub fn bits(content: &[u8]) -> Result<(u8, &[u8]), Flaw> {
    let (unused, data) = content.split_first().ok_or(Flaw::Value)?;
    if *unused > 7 {
        return Err(Flaw::Value);
    }
    let last = data.last().copied();
    if last.is_none() && *unused != 0 {
        return Err(Flaw::Value);
    }
    if last.is_some_and(|byte| byte & ((1u8 << unused) - 1) != 0) {
        return Err(Flaw::Value);
    }
    Ok((*unused, data))
}
