use crate::error::Error;

#[cfg(unix)]
pub(crate) fn entropy() -> Result<[u8; 32], Error> {
    use std::io::Read;
    let mut out = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut out))
        .map_err(|_| Error::Random)?;
    Ok(out)
}

#[cfg(not(unix))]
pub(crate) fn entropy() -> Result<[u8; 32], Error> {
    Err(Error::Random)
}
