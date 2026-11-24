use osistack::http::{Method, Request, Uri};
use osistack::{Client, Error, applied, command, driven, fetch};

fn hosted(reply: &[u8], path: &str) -> (osistack::h1::Server, String) {
    let server = osistack::h1::Server::replying(vec![reply.to_vec()]).unwrap();
    let target = format!("http://127.0.0.1:{}{path}", server.port);
    (server, target)
}

fn served() -> (osistack::h1::Server, String) {
    hosted(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok", "/path")
}

#[test]
fn scheme() {
    let uri = Uri::parse("https://example.test/").unwrap();
    let request = Request::new(Method::new("GET").unwrap(), &uri, Vec::new()).unwrap();
    assert!(matches!(fetch(&request, b""), Err(Error::Scheme)));
    let err = command(&["https://127.0.0.1:1/"]).unwrap_err();
    assert!(matches!(err, Error::Trust), "{err:?}");
    assert!(err.to_string().contains("--cacert"), "{err}");
}

#[test]
fn usage() {
    let bad = [
        &[][..],
        &["--method"],
        &["-o"],
        &["--output"],
        &["--max-time"],
        &["-w"],
        &["--write-out"],
        &["-H"],
        &["--header"],
        &["--retry"],
        &["--noproxy"],
        &["-x"],
        &["--proxy"],
        &["--cacert"],
        &["-D"],
        &["--dump-header"],
        &["-A"],
        &["--user-agent"],
        &["--connect-timeout"],
        &["--http3"],
        &["--http3-only"],
        &["--http3", "--http3-only", "https://a/"],
        &["--http3-only", "--http3", "https://a/"],
        &["--http3", "http://a/"],
        &["--http3-only", "http://a/"],
        &["--connect-timeout", "abc", "http://a/"],
        &["--connect-timeout", "-1", "http://a/"],
        &["--proxy", "not-a-url", "http://a/"],
        &["--retry", "abc", "http://a/"],
        &["--retry", "-1", "http://a/"],
        &["--header", "X-Test", "http://a/"],
        &["-H", ": yes", "http://a/"],
        &["--max-time", "abc", "http://a/"],
        &["--max-time", "-1", "http://a/"],
        &["--verbose", "http://a/"],
        &["http://a/", "http://b/"],
    ];
    for args in bad {
        assert!(matches!(command(args), Err(Error::Usage)), "{args:?}");
    }
}

#[test]
fn posting() {
    let (server, target) = hosted(
        b"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\nok",
        "/upload",
    );
    let response = command(&["fetch", "--method", "POST", "--data", "hi", &target]).unwrap();
    assert_eq!(response.head.status.get(), 201);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.captured().unwrap()).unwrap();
    assert!(seen.starts_with("POST /upload HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("content-length: 2\r\n"), "{seen}");
    assert!(seen.ends_with("\r\n\r\nhi"), "{seen}");
}

#[test]
fn output() {
    for flag in ["-o", "--output"] {
        let (_server, target) = served();
        let path = std::env::temp_dir().join(format!("osi-254-{flag}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let response = command(&[flag, path.to_str().unwrap(), &target]).unwrap();
        assert_eq!(response.body, b"ok");
        assert_eq!(std::fs::read(&path).unwrap(), b"ok");
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn failing() {
    let miss = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
    let (_, target) = hosted(miss, "/missing");
    assert_eq!(command(&[&target]).unwrap().head.status.get(), 404);
    let (_, target) = hosted(miss, "/missing");
    assert!(matches!(command(&["-f", &target]), Err(Error::Status)));
    let error = b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n";
    let (_, target) = hosted(error, "/fail");
    assert!(matches!(command(&["--fail", &target]), Err(Error::Status)));
}

#[test]
fn located() {
    let (dest, _) = served();
    let location = format!("http://127.0.0.1:{}/next", dest.port);
    let head = format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
    let (src, target) = hosted(head.as_bytes(), "/old");
    let response = command(&["-fsSL", &target]).unwrap();
    assert_eq!(response.body, b"ok");
    let _ = (src.captured().unwrap(), dest.captured().unwrap());
    let head =
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/next\r\nContent-Length: 0\r\n\r\n"
            .to_vec();
    let (_, target) = hosted(&head, "/old");
    let response = command(&[&target]).unwrap();
    assert_eq!(response.head.status.get(), 302);
    assert!(matches!(command(&["-fsSL"]), Err(Error::Usage)));
    let long = [
        "--silent",
        "--show-error",
        "--location",
        "http://a/",
        "http://b/",
    ];
    assert!(matches!(command(&long), Err(Error::Usage)));
}

#[test]
fn capped() {
    use std::time::Duration;
    let server = osistack::h1::Server::silent(Duration::from_secs(5)).unwrap();
    let target = format!("http://127.0.0.1:{}/slow", server.port);
    assert!(matches!(
        command(&["--max-time", "0.2", &target]),
        Err(Error::Timeout)
    ));
    let (_server, target) = served();
    let response = command(&["--max-time", "5", &target]).unwrap();
    assert_eq!(response.body, b"ok");
}

#[test]
fn written() {
    let (_server, target) = served();
    let outcome = applied(&["-w", "%{http_code} %{size_download}", &target]).unwrap();
    assert_eq!(outcome.response.body, b"ok");
    assert_eq!(outcome.written.as_deref(), Some("200 2"));
    let (_, target) = hosted(
        b"HTTP/1.1 201 Created\r\ncontent-length: 3\r\n\r\nyes",
        "/file",
    );
    let outcome = applied(&["--write-out", "code=%{http_code}", &target]).unwrap();
    assert_eq!(outcome.response.body, b"yes");
    assert_eq!(outcome.written.as_deref(), Some("code=201"));
}

#[test]
fn headed() {
    let (server, target) = served();
    let response = command(&["-H", "X-Test: one", "--header", "X-More: two", &target]).unwrap();
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.captured().unwrap()).unwrap();
    assert!(seen.contains("x-test: one\r\n"), "{seen}");
    assert!(seen.contains("x-more: two\r\n"), "{seen}");
}

#[test]
fn retrying() {
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;
    let ok = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        drop(listener.accept().unwrap().0);
        let (mut peer, _) = listener.accept().unwrap();
        let _ = peer.write_all(ok);
    });
    let target = format!("http://127.0.0.1:{port}/path");
    let response = command(&["--retry", "1", &target]).unwrap();
    assert_eq!(response.body, b"ok");
    server.join().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        drop(listener.accept().unwrap().0);
        drop(listener.accept().unwrap().0);
    });
    let target = format!("http://127.0.0.1:{port}/path");
    assert!(command(&["--retry", "1", &target]).is_err());
    server.join().unwrap();
}

#[test]
fn skipping() {
    use std::time::Duration;
    let (origin, target) = served();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    let proxy = format!("http://127.0.0.1:{port}");
    let client = Client {
        via: Some(osistack::http::Uri::parse(&proxy).unwrap()),
        connect: Duration::from_millis(200),
        ..Client::default()
    };
    let response = driven(client, &["--noproxy", "127.0.0.1", &target])
        .unwrap()
        .response;
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(origin.captured().unwrap()).unwrap();
    assert!(seen.starts_with("GET /path HTTP/1.1\r\n"), "{seen}");
}

#[test]
fn proxied() {
    let (proxy, _) = hosted(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nproxy", "/");
    let hop = format!("http://127.0.0.1:{}", proxy.port);
    let response = command(&["--proxy", &hop, "http://127.0.0.1:9/path"]).unwrap();
    assert_eq!(response.body, b"proxy");
    let seen = String::from_utf8(proxy.captured().unwrap()).unwrap();
    assert!(
        seen.starts_with("GET http://127.0.0.1:9/path HTTP/1.1\r\n"),
        "{seen}"
    );
    let (origin, target) = served();
    let response = command(&["-x", &hop, "--noproxy", "127.0.0.1", &target]).unwrap();
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(origin.captured().unwrap()).unwrap();
    assert!(seen.starts_with("GET /path HTTP/1.1\r\n"), "{seen}");
}

#[test]
fn heading() {
    for flag in ["-I", "--head"] {
        let (server, target) = hosted(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", "/path");
        command(&[flag, &target]).unwrap();
        let seen = String::from_utf8(server.captured().unwrap()).unwrap();
        assert!(seen.starts_with("HEAD /path HTTP/1.1\r\n"), "{seen}");
    }
    assert!(matches!(
        command(&["-I", "--method", "POST", "http://a/"]),
        Err(Error::Usage)
    ));
}

#[test]
fn dumping() {
    for flag in ["-D", "--dump-header"] {
        let (_server, target) = served();
        let path = std::env::temp_dir().join(format!("osi-277-{flag}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let response = command(&[flag, path.to_str().unwrap(), &target]).unwrap();
        assert_eq!(response.body, b"ok");
        let text = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n") && text.contains("content-length: 2\r\n"),
            "{text}"
        );
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn agent() {
    for flag in ["-A", "--user-agent"] {
        let (server, target) = served();
        command(&[flag, "osistack", &target]).unwrap();
        let seen = String::from_utf8(server.captured().unwrap()).unwrap();
        assert!(seen.contains("user-agent: osistack\r\n"), "{seen}");
    }
}

#[test]
fn connecting() {
    use osistack::socket::{Error as Socket, Phase};
    let err = command(&["--connect-timeout", "0.2", "http://192.0.2.1/path"]).unwrap_err();
    assert!(matches!(
        err,
        Error::Socket(Socket::Timeout(Phase::Connect))
    ));
}
