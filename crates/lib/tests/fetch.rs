use osistack::http::{Method, Request, Uri};
use osistack::{Error, applied, command, fetch};

#[test]
fn scheme() {
    let uri = Uri::parse("https://example.test/").unwrap();
    let request = Request::new(Method::new("GET").unwrap(), &uri, Vec::new()).unwrap();
    assert!(matches!(fetch(&request, b""), Err(Error::Scheme)));
    assert!(matches!(
        command(&["https://example.test/"]),
        Err(Error::Scheme)
    ));
}

#[test]
fn usage() {
    assert!(matches!(command(&[]), Err(Error::Usage)));
    assert!(matches!(command(&["--method"]), Err(Error::Usage)));
    assert!(matches!(command(&["-o"]), Err(Error::Usage)));
    assert!(matches!(command(&["--output"]), Err(Error::Usage)));
    assert!(matches!(command(&["--max-time"]), Err(Error::Usage)));
    assert!(matches!(command(&["-w"]), Err(Error::Usage)));
    assert!(matches!(command(&["--write-out"]), Err(Error::Usage)));
    assert!(matches!(
        command(&["--max-time", "abc", "http://a/"]),
        Err(Error::Usage)
    ));
    assert!(matches!(
        command(&["--max-time", "-1", "http://a/"]),
        Err(Error::Usage)
    ));
    assert!(matches!(
        command(&["--verbose", "http://a/"]),
        Err(Error::Usage)
    ));
    assert!(matches!(
        command(&["http://a/", "http://b/"]),
        Err(Error::Usage)
    ));
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
