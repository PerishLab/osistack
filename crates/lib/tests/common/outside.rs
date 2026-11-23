use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn present() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub struct Issued {
    pub cert: PathBuf,
    pub key: PathBuf,
    folder: PathBuf,
}

impl Drop for Issued {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.folder);
    }
}

pub fn minted() -> Issued {
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let folder = std::env::temp_dir().join(format!("osi-284-{}-{}", std::process::id(), tick));
    fs::create_dir_all(&folder).unwrap();
    let cert = folder.join("cert.pem");
    let key = folder.join("key.pem");
    let status = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("ec")
        .arg("-pkeyopt")
        .arg("ec_paramgen_curve:P-256")
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .arg("-days")
        .arg("365")
        .arg("-nodes")
        .arg("-subj")
        .arg("/CN=localhost")
        .arg("-addext")
        .arg("subjectAltName=DNS:localhost")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    Issued { cert, key, folder }
}

pub struct Serving {
    child: Child,
    pub port: u16,
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn serving(cert: &Path, key: &Path) -> Serving {
    let log = cert.with_file_name("server.out");
    let file = File::create(&log).unwrap();
    let sink = file.try_clone().unwrap();
    let child = Command::new("openssl")
        .arg("s_server")
        .arg("-accept")
        .arg("127.0.0.1:0")
        .arg("-cert")
        .arg(cert)
        .arg("-key")
        .arg(key)
        .arg("-www")
        .arg("-tls1_3")
        .arg("-alpn")
        .arg("http/1.1")
        .arg("-naccept")
        .arg("1")
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(sink))
        .spawn()
        .unwrap();
    let port = waited(&log);
    Serving { child, port }
}

fn waited(path: &Path) -> u16 {
    let start = Instant::now();
    loop {
        if let Some(port) = posted(path) {
            return port;
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn posted(path: &Path) -> Option<u16> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("ACCEPT 127.0.0.1:") {
            return rest.parse().ok();
        }
    }
    None
}
