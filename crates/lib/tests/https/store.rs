use super::support::{certs, get, local, mint, serve, spawn};
use osistack::http::Uri;
use osistack::{Client, Error, Roots, driven, load, stored};
use std::fs;

fn unique(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("osistack-330-{name}-{}", std::process::id()))
}

#[test]
fn loaded() {
    let held = mint("localhost");
    let path = unique("pem");
    fs::write(&path, certs(&held.der)).unwrap();
    let roots = load(Some(&path), None);
    assert_eq!(roots.count(), 1);
    let (port, server) = spawn(serve);
    let client = local(roots);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = client.fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.body, b"ok");
    let _ = server.join();
    let _ = fs::remove_file(&path);
}

#[test]
fn der() {
    let held = mint("localhost");
    let path = unique("der");
    fs::write(&path, &held.der).unwrap();
    let roots = load(Some(&path), None);
    assert_eq!(roots.count(), 1);
    assert!(roots.contains(&held.der));
    let _ = fs::remove_file(&path);
}

#[test]
fn folder() {
    let held = mint("localhost");
    let dir = unique("dir");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ca.pem"), certs(&held.der)).unwrap();
    fs::write(dir.join("junk"), b"not a certificate").unwrap();
    let roots = load(None, Some(&dir));
    assert_eq!(roots.count(), 1);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn missing() {
    let path = unique("absent");
    assert_eq!(load(Some(&path), None).count(), 0);
    let dir = unique("absent-dir");
    assert_eq!(load(None, Some(&dir)).count(), 0);
}

#[test]
fn vacant() {
    let client = Client {
        roots: Roots::default(),
        ..Client::default()
    };
    match driven(client, &["https://127.0.0.1:1/"]) {
        Err(err) => {
            assert!(matches!(err, Error::Trust), "{err:?}");
            assert!(err.to_string().contains("--cacert"), "{err}");
        }
        Ok(_) => panic!("expected trust error"),
    }
}

#[test]
#[cfg(not(target_os = "linux"))]
fn bare() {
    assert_eq!(stored().count(), 0);
}

#[test]
#[cfg(target_os = "linux")]
fn platform() {
    let path = std::path::Path::new("/etc/ssl/certs/ca-certificates.crt");
    if path.is_file() {
        let held = stored();
        assert!(held.count() > 0);
        assert_eq!(load(Some(path), None).count(), held.count());
    }
}
