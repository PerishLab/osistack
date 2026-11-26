use crate::behaviour::Check;

#[cfg(target_os = "linux")]
mod ecn;
#[cfg(target_os = "linux")]
mod gso;

#[cfg(target_os = "linux")]
pub fn table() -> Vec<(&'static str, Check)> {
    let mut rows = ecn::table();
    rows.extend(gso::table());
    rows
}

#[cfg(not(target_os = "linux"))]
pub fn table() -> Vec<(&'static str, Check)> {
    Vec::new()
}
