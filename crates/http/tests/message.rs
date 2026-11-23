use http::{Error, Method, Name, Request, Response, Status, Uri, Value};

fn pair(name: &str, value: &str) -> (Name, Value) {
    (
        Name::new(name).unwrap(),
        Value::new(value.as_bytes()).unwrap(),
    )
}

fn uri(text: &str) -> Uri {
    Uri::parse(text).unwrap()
}

fn get() -> Request {
    Request::new(
        Method::new("GET").unwrap(),
        &uri("http://example.test/index?q=1"),
        vec![pair("accept", "*/*")],
    )
    .unwrap()
}

#[test]
fn names() {
    assert_eq!(Name::new(":method"), Err(Error::Character));
    assert_eq!(Name::new(":status"), Err(Error::Character));
}

#[test]
fn request() {
    let request = get();
    assert_eq!(request.method().text(), "GET");
    assert_eq!(request.scheme().text(), "http");
    assert_eq!(request.authority(), "example.test");
    assert_eq!(request.path(), "/index?q=1");
    assert_eq!(request.target(), "/index?q=1");
    assert_eq!(request.fields(), &[pair("accept", "*/*")]);
    let lines = request.headers();
    assert_eq!(
        lines,
        vec![
            (b":method".to_vec(), b"GET".to_vec()),
            (b":scheme".to_vec(), b"http".to_vec()),
            (b":authority".to_vec(), b"example.test".to_vec()),
            (b":path".to_vec(), b"/index?q=1".to_vec()),
            (b"accept".to_vec(), b"*/*".to_vec()),
        ]
    );
    assert_eq!(Request::incoming(&lines).unwrap(), request);
}

#[test]
fn written() {
    let request = get();
    assert_eq!(
        request.written().unwrap(),
        vec![pair("host", "example.test"), pair("accept", "*/*")]
    );
}

#[test]
fn hosted() {
    let method = Method::new("GET").unwrap();
    let fields = vec![pair("host", "example.test"), pair("accept", "*/*")];
    let request = Request::parse(method, "/index?q=1", fields).unwrap();
    assert_eq!(request.authority(), "example.test");
    assert_eq!(request.path(), "/index?q=1");
    assert_eq!(request.fields(), &[pair("accept", "*/*")]);
}

#[test]
fn absolute() {
    let method = Method::new("GET").unwrap();
    let request = Request::parse(
        method.clone(),
        "https://example.test:8443/x",
        vec![pair("accept", "*/*")],
    )
    .unwrap();
    assert_eq!(request.scheme().text(), "https");
    assert_eq!(request.authority(), "example.test:8443");
    assert_eq!(request.path(), "/x");
    let conflict = vec![pair("host", "other.test")];
    assert_eq!(
        Request::parse(method, "https://example.test:8443/x", conflict),
        Err(Error::Host)
    );
}

#[test]
fn tunnel() {
    let method = Method::new("CONNECT").unwrap();
    let request =
        Request::new(method.clone(), &uri("http://example.test:443/"), Vec::new()).unwrap();
    assert_eq!(request.path(), "");
    assert_eq!(request.target(), "example.test:443");
    let lines = request.headers();
    assert_eq!(
        lines,
        vec![
            (b":method".to_vec(), b"CONNECT".to_vec()),
            (b":scheme".to_vec(), b"http".to_vec()),
            (b":authority".to_vec(), b"example.test:443".to_vec()),
        ]
    );
    assert_eq!(Request::incoming(&lines).unwrap(), request);
    let parsed = Request::parse(method, "example.test:443", Vec::new()).unwrap();
    assert_eq!(parsed.target(), "example.test:443");
}

#[test]
fn starred() {
    let request = Request::star(&uri("http://example.test/"), Vec::new()).unwrap();
    assert_eq!(request.method().text(), "OPTIONS");
    assert_eq!(request.path(), "*");
    assert_eq!(request.target(), "*");
    let lines = request.headers();
    assert_eq!(lines[3], (b":path".to_vec(), b"*".to_vec()));
    assert_eq!(Request::incoming(&lines).unwrap(), request);
    let parsed = Request::parse(
        Method::new("OPTIONS").unwrap(),
        "*",
        vec![pair("host", "example.test")],
    )
    .unwrap();
    assert_eq!(parsed.path(), "*");
}

#[test]
fn hopping() {
    let request = Request::new(
        Method::new("GET").unwrap(),
        &uri("http://example.test/"),
        vec![
            pair("connection", "keep-alive"),
            pair("keep-alive", "timeout=5"),
            pair("proxy-connection", "close"),
            pair("transfer-encoding", "chunked"),
            pair("upgrade", "h2c"),
            pair("accept", "*/*"),
        ],
    )
    .unwrap();
    let lines = request.headers();
    let names: Vec<_> = lines.iter().map(|(name, _)| name.as_slice()).collect();
    assert_eq!(
        names,
        vec![
            &b":method"[..],
            &b":scheme"[..],
            &b":authority"[..],
            &b":path"[..],
            &b"accept"[..],
        ]
    );
}

#[test]
fn refused() {
    let method = Method::new("GET").unwrap();
    assert_eq!(
        Request::new(
            method.clone(),
            &uri("http://example.test/"),
            vec![pair("host", "example.test")]
        ),
        Err(Error::Host)
    );
    assert_eq!(
        Request::new(Method::new("CONNECT").unwrap(), &uri("http://a/"), vec![])
            .unwrap()
            .path(),
        ""
    );
    assert_eq!(
        Request::star(&uri("http://a/"), vec![pair("host", "a")]).err(),
        Some(Error::Host)
    );
    let lines = get().headers();
    let mut swapped = lines.clone();
    swapped.swap(1, 2);
    assert_eq!(Request::incoming(&swapped), Err(Error::Order));
    let mut late = get().headers();
    late.push((b":scheme".to_vec(), b"http".to_vec()));
    assert_eq!(Request::incoming(&late), Err(Error::Order));
    let mut unknown = get().headers();
    unknown.insert(4, (b":foo".to_vec(), b"x".to_vec()));
    assert_eq!(Request::incoming(&unknown), Err(Error::Pseudo));
    let mut protocol = get().headers();
    protocol.insert(4, (b":protocol".to_vec(), b"connect-tcp".to_vec()));
    assert_eq!(Request::incoming(&protocol), Err(Error::Pseudo));
    let mut status = get().headers();
    status.insert(4, (b":status".to_vec(), b"200".to_vec()));
    assert_eq!(Request::incoming(&status), Err(Error::Pseudo));
    let mut twice = get().headers();
    twice.insert(1, (b":method".to_vec(), b"POST".to_vec()));
    assert_eq!(Request::incoming(&twice), Err(Error::Order));
    let mut connect = Request::new(
        Method::new("CONNECT").unwrap(),
        &uri("http://example.test:443/"),
        Vec::new(),
    )
    .unwrap()
    .headers();
    connect.push((b":path".to_vec(), b"/".to_vec()));
    assert_eq!(Request::incoming(&connect), Err(Error::Target));
    let mut missing = get().headers();
    missing.remove(3);
    assert_eq!(Request::incoming(&missing), Err(Error::Pseudo));
}

#[test]
fn response() {
    let response = Response::new(
        Status::new(200).unwrap(),
        vec![pair("content-type", "text/plain")],
    )
    .unwrap();
    assert_eq!(response.status().get(), 200);
    let lines = response.headers();
    assert_eq!(
        lines,
        vec![
            (b":status".to_vec(), b"200".to_vec()),
            (b"content-type".to_vec(), b"text/plain".to_vec()),
        ]
    );
    assert_eq!(Response::incoming(&lines).unwrap(), response);
    let hopped = Response::new(
        Status::new(101).unwrap(),
        vec![pair("connection", "upgrade"), pair("upgrade", "h2c")],
    )
    .unwrap();
    assert_eq!(
        hopped.headers(),
        vec![(b":status".to_vec(), b"101".to_vec())]
    );
    assert_eq!(
        Response::incoming(&[(b":method".to_vec(), b"GET".to_vec())]),
        Err(Error::Pseudo)
    );
    assert_eq!(Response::incoming(&[]), Err(Error::Pseudo));
    let late = vec![
        (b"content-type".to_vec(), b"text/plain".to_vec()),
        (b":status".to_vec(), b"200".to_vec()),
    ];
    assert_eq!(Response::incoming(&late), Err(Error::Order));
    let twice = vec![
        (b":status".to_vec(), b"200".to_vec()),
        (b":status".to_vec(), b"204".to_vec()),
    ];
    assert_eq!(Response::incoming(&twice), Err(Error::Duplicate));
}
