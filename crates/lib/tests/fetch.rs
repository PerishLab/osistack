use osistack::http::{Method, Request, Uri};
use osistack::{Client, Error, applied, command, driven, fetch};

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
    use osistack::h1::Server;
    let server = Server::replying(vec![
        b"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/upload", server.port);
    let response = command(&["fetch", "--method", "POST", "--data", "hi", &target]).unwrap();
    assert_eq!(response.head.status.get(), 201);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.captured()).unwrap();
    assert!(seen.starts_with("POST /upload HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("content-length: 2\r\n"), "{seen}");
    assert!(seen.ends_with("\r\n\r\nhi"), "{seen}");
}

#[test]
fn output() {
    use osistack::h1::Server;
    let server = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/file", server.port);
    let path = std::env::temp_dir().join(format!("osistack-254-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let held = path.to_str().unwrap().to_owned();
    let response = command(&["-o", &held, &target]).unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    assert_eq!(std::fs::read(&path).unwrap(), b"ok");
    let again = std::env::temp_dir().join(format!("osistack-254-out-{}", std::process::id()));
    let _ = std::fs::remove_file(&again);
    let held = again.to_str().unwrap().to_owned();
    let server = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nyes".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/file", server.port);
    let response = command(&["--output", &held, &target]).unwrap();
    assert_eq!(response.body, b"yes");
    assert_eq!(std::fs::read(&again).unwrap(), b"yes");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&again);
}

#[test]
fn failing() {
    use osistack::h1::Server;
    let server = Server::replying(vec![
        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/missing", server.port);
    let response = command(&[&target]).unwrap();
    assert_eq!(response.head.status.get(), 404);
    let server = Server::replying(vec![
        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/missing", server.port);
    assert!(matches!(command(&["-f", &target]), Err(Error::Status)));
    let server = Server::replying(vec![
        b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/fail", server.port);
    assert!(matches!(command(&["--fail", &target]), Err(Error::Status)));
}

#[test]
fn located() {
    use osistack::h1::Server;
    let dest = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let location = format!("http://127.0.0.1:{}/next", dest.port);
    let head = format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
    let src = Server::replying(vec![head.into_bytes()]);
    let target = format!("http://127.0.0.1:{}/old", src.port);
    let response = command(&["-fsSL", &target]).unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let _ = src.captured();
    let _ = dest.captured();
    let head =
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/next\r\nContent-Length: 0\r\n\r\n"
            .to_vec();
    let src = Server::replying(vec![head]);
    let target = format!("http://127.0.0.1:{}/old", src.port);
    let response = command(&[&target]).unwrap();
    assert_eq!(response.head.status.get(), 302);
    let _ = src.captured();
    assert!(matches!(command(&["-fsSL"]), Err(Error::Usage)));
    assert!(matches!(
        command(&[
            "--silent",
            "--show-error",
            "--location",
            "http://a/",
            "http://b/"
        ]),
        Err(Error::Usage)
    ));
}

#[test]
fn capped() {
    use osistack::h1::Server;
    use std::time::Duration;
    let server = Server::silent(Duration::from_secs(5));
    let target = format!("http://127.0.0.1:{}/slow", server.port);
    assert!(matches!(
        command(&["--max-time", "0.2", &target]),
        Err(Error::Timeout)
    ));
    let server = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/fast", server.port);
    let response = command(&["--max-time", "5", &target]).unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
}

#[test]
fn written() {
    use osistack::h1::Server;
    let server = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/file", server.port);
    let outcome = applied(&["-w", "%{http_code} %{size_download}", &target]).unwrap();
    assert_eq!(outcome.response.head.status.get(), 200);
    assert_eq!(outcome.response.body, b"ok");
    assert_eq!(outcome.written.as_deref(), Some("200 2"));
    let server = Server::replying(vec![
        b"HTTP/1.1 201 Created\r\ncontent-length: 3\r\n\r\nyes".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/file", server.port);
    let outcome = applied(&["--write-out", "code=%{http_code}", &target]).unwrap();
    assert_eq!(outcome.response.body, b"yes");
    assert_eq!(outcome.written.as_deref(), Some("code=201"));
}

#[test]
fn headed() {
    use osistack::h1::Server;
    let server = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/path", server.port);
    let response = command(&["-H", "X-Test: one", "--header", "X-More: two", &target]).unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.captured()).unwrap();
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
    assert_eq!(response.head.status.get(), 200);
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
    use osistack::h1::Server;
    use std::time::Duration;
    let origin = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/path", origin.port);
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
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(origin.captured()).unwrap();
    assert!(seen.starts_with("GET /path HTTP/1.1\r\n"), "{seen}");
}

#[test]
fn proxied() {
    use osistack::h1::Server;
    let proxy = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nproxy".to_vec(),
    ]);
    let hop = format!("http://127.0.0.1:{}", proxy.port);
    let response = command(&["--proxy", &hop, "http://127.0.0.1:9/path"]).unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"proxy");
    let seen = String::from_utf8(proxy.captured()).unwrap();
    assert!(
        seen.starts_with("GET http://127.0.0.1:9/path HTTP/1.1\r\n"),
        "{seen}"
    );
    let origin = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
    ]);
    let target = format!("http://127.0.0.1:{}/path", origin.port);
    let response = command(&["-x", &hop, "--noproxy", "127.0.0.1", &target]).unwrap();
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(origin.captured()).unwrap();
    assert!(seen.starts_with("GET /path HTTP/1.1\r\n"), "{seen}");
}

#[test]
fn heading() {
    use osistack::h1::Server;
    for flag in ["-I", "--head"] {
        let server = Server::replying(vec![
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_vec(),
        ]);
        let target = format!("http://127.0.0.1:{}/path", server.port);
        let response = command(&[flag, &target]).unwrap();
        assert_eq!(response.head.status.get(), 200);
        let seen = String::from_utf8(server.captured()).unwrap();
        assert!(seen.starts_with("HEAD /path HTTP/1.1\r\n"), "{seen}");
    }
    assert!(matches!(
        command(&["-I", "--method", "POST", "http://a/"]),
        Err(Error::Usage)
    ));
}
