use super::outside::Issued;
use std::fs::{self, File};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub fn present() -> bool {
    Command::new("nghttpd")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub struct Hosted {
    child: Child,
    pub port: u16,
}

impl Drop for Hosted {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn hosted(issued: &Issued) -> Hosted {
    let docs = issued.cert.parent().unwrap();
    fs::write(docs.join("index.html"), b"ok").unwrap();
    let port = unused();
    let log = docs.join("httpd.out");
    let file = File::create(&log).unwrap();
    let sink = file.try_clone().unwrap();
    let child = Command::new("nghttpd")
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-d")
        .arg(docs)
        .arg(port.to_string())
        .arg(&issued.key)
        .arg(&issued.cert)
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(sink))
        .spawn()
        .unwrap();
    waited(port);
    Hosted { child, port }
}

fn unused() -> u16 {
    let bound = TcpListener::bind("127.0.0.1:0").unwrap();
    bound.local_addr().unwrap().port()
}

fn waited(port: u16) {
    let start = Instant::now();
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(10));
    }
}
