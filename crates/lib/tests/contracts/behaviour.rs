use crate::common::{Server, client, text};
use osistack::h1::Request;
use osistack::http::Method;
use osistack::{Error, h1};

pub type Check = fn();

pub fn table() -> Vec<(&'static str, Check)> {
    vec![
        ("content-length", length as Check),
        ("chunked", chunked as Check),
        ("keep-alive-pool", pooling as Check),
        ("connection-close", closing as Check),
        ("http10-response", legacy as Check),
        ("status-not-error", status as Check),
        ("framing", framing as Check),
        ("smuggling-defense", smuggling as Check),
        ("redirect-policy", redirect as Check),
        ("total-timeout", lasting as Check),
        ("phase-timeout", phased as Check),
        ("loopback-test-server", loopback as Check),
        ("proxy", proxy as Check),
    ]
}

fn get() -> Method {
    Method::new("GET").unwrap()
}

fn body(parts: &[&str]) -> Vec<u8> {
    let server = Server::replying(text(parts)).unwrap();
    client().fetch(get(), &server.uri, b"").unwrap().body
}

fn fails(parts: &[&str]) -> Error {
    let server = Server::replying(text(parts)).unwrap();
    client().fetch(get(), &server.uri, b"").unwrap_err()
}

fn length() {
    let sent = ["HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Kind: plain\r\n\r\nhello"];
    let server = Server::replying(text(&sent)).unwrap();
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.head.values("x-kind"), vec![&b"plain"[..]]);
    assert_eq!(response.body, b"hello");
    let short = fails(&["HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"]);
    assert!(matches!(short, Error::Short));
}

fn chunked() {
    let sent = [
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "5\r\nhello\r\n1;ext=1\r\n \r\n5\r\nworld\r\n0\r\n\r\n",
    ];
    assert_eq!(body(&sent), b"hello world");
    let cut = ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"];
    assert!(matches!(fails(&cut), Error::Short));
}

fn closing() {
    let server = Server::replying(text(&["HTTP/1.1 204 No Content\r\n\r\n"])).unwrap();
    let port = server.port;
    client().fetch(get(), &server.uri, b"").unwrap();
    let seen = String::from_utf8(server.captured()).unwrap();
    let expected =
        format!("GET /path?q=1 HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nconnection: close\r\n\r\n");
    assert_eq!(seen, expected);
    let sent = [
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil ",
        "the end",
    ];
    assert_eq!(body(&sent), b"until the end");
}

fn legacy() {
    let server = Server::replying(text(&["HTTP/1.0 200 OK\r\n\r\nuntil ", "the end"])).unwrap();
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"until the end");
}

fn status() {
    for (line, code) in [
        ("404 Not Found", 404),
        ("500 Oops", 500),
        ("301 Moved", 301),
    ] {
        let sent = format!("HTTP/1.1 {line}\r\nContent-Length: 4\r\n\r\ngone");
        let server = Server::replying(text(&[sent.as_str()])).unwrap();
        let response = client().fetch(get(), &server.uri, b"").unwrap();
        assert_eq!(response.head.status.get(), code);
        assert_eq!(response.body, b"gone");
    }
}

fn framing() {
    let sized = ["HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"];
    let chunks = ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"];
    let ended = ["HTTP/1.0 200 OK\r\n\r\nabc"];
    for sent in [&sized[..], &chunks[..], &ended[..]] {
        assert_eq!(body(sent), b"abc");
    }
    let server =
        Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"])).unwrap();
    let method = Method::new("HEAD").unwrap();
    let response = client().fetch(method, &server.uri, b"").unwrap();
    assert!(response.body.is_empty());
    assert!(body(&["HTTP/1.1 204 No Content\r\n\r\n"]).is_empty());
    let both = ["HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc"];
    let outcome = fails(&both);
    assert!(matches!(outcome, Error::Frame(h1::Error::Ambiguous)));
}

fn refused(sent: &str, expected: h1::Error) {
    let outcome = fails(&[sent]);
    assert!(
        matches!(outcome, Error::Frame(found) if found == expected),
        "{sent:?}"
    );
}

fn smuggling() {
    let head = |fields: &str| format!("HTTP/1.1 200 OK\r\n{fields}\r\n\r\nabc");
    let ambiguous = [
        "Content-Length: 3\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: chunked\r\nContent-Length: 3",
        "Content-Length: 3\r\nTransfer-Encoding: gzip",
    ];
    for fields in ambiguous {
        refused(&head(fields), h1::Error::Ambiguous);
    }
    let lengths = [
        "Content-Length: 3\r\nContent-Length: 4",
        "Content-Length: 3, 4",
        "Content-Length: +3",
    ];
    for fields in lengths {
        refused(&head(fields), h1::Error::Length);
    }
    let encodings = [
        "Transfer-Encoding: chunked, chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip",
    ];
    for fields in encodings {
        refused(&head(fields), h1::Error::Encoding);
    }
    refused(&head("A: b\r\n c\r\nContent-Length: 3"), h1::Error::Fold);
    refused(&head("Content-Length : 3"), h1::Error::Space);
    refused(&head("A: b\nContent-Length: 3"), h1::Error::Line);
    let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    for chunks in [
        "g\r\nabc\r\n0\r\n\r\n",
        "3\r\nabcXX0\r\n\r\n",
        "3\nabc\r\n0\r\n\r\n",
    ] {
        refused(&format!("{chunked}{chunks}"), h1::Error::Chunk);
    }
    assert_eq!(
        body(&[&head("Content-Length: 3\r\nContent-Length: 3")]),
        b"abc"
    );
    let extra = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nevil";
    assert_eq!(body(&[extra]), b"abc");
    let server = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"])).unwrap();
    let method = Method::new("POST").unwrap();
    client().fetch(method, &server.uri, b"payload").unwrap();
    let seen = String::from_utf8(server.captured())
        .unwrap()
        .to_ascii_lowercase();
    assert_eq!(seen.matches("content-length:").count(), 1);
    assert!(!seen.contains("transfer-encoding"));
}

fn loopback() {
    let server =
        Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"])).unwrap();
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"body");
    let seen = server.captured();
    assert!(seen.starts_with(b"GET /path?q=1 HTTP/1.1\r\n"));
}

fn proxy() {
    let sent = ["HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"];
    let server = Server::replying(text(&sent)).unwrap();
    let port = server.port;
    let response = client().forward(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"body");
    let seen = String::from_utf8(server.captured()).unwrap();
    let target = format!("http://127.0.0.1:{port}/path?q=1");
    assert!(
        seen.starts_with(&format!("GET {target} HTTP/1.1\r\n")),
        "{seen}"
    );
    let server = Server::replying(text(&["HTTP/1.1 200 Connection Established\r\n\r\n"])).unwrap();
    let port = server.port;
    let response = client().tunnel(&server.uri).unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert!(response.body.is_empty());
    let seen = String::from_utf8(server.captured()).unwrap();
    assert!(
        seen.starts_with(&format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n")),
        "{seen}"
    );
    assert!(Request::parse(seen.as_bytes(), 4096).unwrap().is_some());
}

fn pooling() {
    use osistack::Pool;
    let server = Server::holding(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb".to_vec(),
    ])
    .unwrap();
    let first = format!("http://127.0.0.1:{}/one", server.port);
    let second = format!("http://127.0.0.1:{}/two", server.port);
    let one = osistack::http::Uri::parse(&first).unwrap();
    let two = osistack::http::Uri::parse(&second).unwrap();
    let mut pool = Pool::new(client());
    assert_eq!(pool.fetch(get(), &one, b"").unwrap().body, b"a");
    assert_eq!(pool.fetch(get(), &two, b"").unwrap().body, b"b");
    let seen = String::from_utf8(server.captured()).unwrap();
    assert!(seen.contains("GET /one HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("GET /two HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("connection: keep-alive\r\n"), "{seen}");
}

fn redirect() {
    let dest =
        Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nend"])).unwrap();
    let location = format!("http://127.0.0.1:{}/dest", dest.port);
    let head = format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
    let src = Server::replying(text(&[&head])).unwrap();
    let response = client().fetch(get(), &src.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"end");
    let _ = src.captured();
    let _ = dest.captured();
}

fn lasting() {
    use std::time::Duration;
    let server = Server::silent(Duration::from_millis(600)).unwrap();
    let tight = osistack::Client {
        total: Duration::from_millis(80),
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
        write: Duration::from_secs(5),
        ..client()
    };
    let outcome = tight.fetch(get(), &server.uri, b"");
    let _ = server.captured();
    assert!(
        matches!(outcome, Err(osistack::Error::Timeout)),
        "{outcome:?}"
    );
}

fn phased() {
    use osistack::socket::{Error as Socket, Phase};
    use std::time::Duration;
    let server = Server::silent(Duration::from_millis(600)).unwrap();
    let tight = osistack::Client {
        read: Duration::from_millis(150),
        ..client()
    };
    let outcome = tight.fetch(get(), &server.uri, b"");
    let _ = server.captured();
    assert!(
        matches!(
            outcome,
            Err(osistack::Error::Socket(Socket::Timeout(Phase::Read)))
        ),
        "{outcome:?}"
    );
}
