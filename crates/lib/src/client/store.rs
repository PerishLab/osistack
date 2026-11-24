use std::fs;
use std::path::{Path, PathBuf};
use tls::x509::trust::{Roots, blocks};

const BEGIN: &str = "-----BEGIN ";
const LABEL: &str = "CERTIFICATE";

#[cfg(target_os = "linux")]
const BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

#[cfg(target_os = "linux")]
const FOLDERS: &[&str] = &["/etc/ssl/certs", "/etc/pki/tls/certs"];

#[cfg(not(target_os = "linux"))]
const BUNDLES: &[&str] = &[];

#[cfg(not(target_os = "linux"))]
const FOLDERS: &[&str] = &[];

pub fn stored() -> Roots {
    let (file, folder) = probe();
    load(file.as_deref(), folder.as_deref())
}

pub fn load(file: Option<&Path>, folder: Option<&Path>) -> Roots {
    let mut roots = Roots::default();
    if let Some(path) = file {
        ingest(&mut roots, path);
    }
    if let Some(path) = folder {
        walk(&mut roots, path);
    }
    roots
}

fn probe() -> (Option<PathBuf>, Option<PathBuf>) {
    if let Some(path) = existing(BUNDLES, Path::is_file) {
        return (Some(path), None);
    }
    (None, existing(FOLDERS, Path::is_dir))
}

fn existing(paths: &[&str], test: fn(&Path) -> bool) -> Option<PathBuf> {
    paths.iter().map(PathBuf::from).find(|path| test(path))
}

fn ingest(held: &mut Roots, path: &Path) {
    if let Ok(bytes) = fs::read(path) {
        offer(held, &bytes);
    }
}

fn walk(held: &mut Roots, path: &Path) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            ingest(held, &path);
        }
    }
}

fn offer(held: &mut Roots, bytes: &[u8]) {
    if let Some(text) = decode(bytes) {
        picked(held, text);
        return;
    }
    let _ = held.add(bytes);
}

fn decode(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.contains(BEGIN).then_some(text)
}

fn picked(into: &mut Roots, text: &str) {
    let Ok(parsed) = blocks(text) else {
        return;
    };
    for block in parsed {
        if block.label == LABEL {
            let _ = into.add(&block.data);
        }
    }
}
