use osistack::http::{Method, Request, Uri};
use osistack::{Error, command, fetch};

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
