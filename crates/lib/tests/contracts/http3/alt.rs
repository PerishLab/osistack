use crate::behaviour::Check;
use crate::common::{Server, client, text};
use h3::{Cache, Defect, Origin};
use osistack::http::Method;

const SECOND: u64 = 1_000_000;

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("alt-svc-discovery", discovery as Check)]
}

fn fetched(field: &str) -> (Origin, String) {
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nAlt-Svc: {field}\r\n\r\nok");
    let server = Server::replying(text(&[&head])).unwrap();
    let get = Method::new("GET").unwrap();
    let response = client().fetch(get, &server.uri, b"").unwrap();
    let values = response.head.values("alt-svc");
    assert_eq!(values.len(), 1);
    let origin = Origin::new("127.0.0.1", server.port);
    (origin, String::from_utf8(values[0].to_vec()).unwrap())
}

fn discovery() {
    let mut cache = Cache::new(8);
    let field = "h2=\":8000\", h3=\"alt.example:8443\"; ma=60; persist=1";
    let (origin, value) = fetched(field);
    let start = 5 * SECOND;
    cache.receive(&origin, &value, start).unwrap();
    let best = cache.best(&origin, start).unwrap();
    assert_eq!(best.protocol, b"h3");
    assert_eq!((best.host.as_str(), best.port), ("alt.example", 8443));
    assert_eq!((best.age, best.persist), (60, true));
    assert_eq!(cache.fresh(&origin, start).len(), 2);
    let due = start + 60 * SECOND;
    assert!(cache.best(&origin, due - 1).is_some());
    assert!(cache.best(&origin, due).is_none());
    let rest = cache.fresh(&origin, due);
    assert_eq!(rest.len(), 1);
    assert_eq!(
        (rest[0].protocol.as_slice(), rest[0].age),
        (&b"h2"[..], 86_400)
    );
    cache.purge(due);
    assert_eq!(cache.count(), 1);
    cache.purge(start + 86_400 * SECOND);
    assert_eq!(cache.count(), 0);
    let (origin, value) = fetched("h3=\":443\"");
    cache.receive(&origin, &value, 0).unwrap();
    let best = cache.best(&origin, 0).unwrap();
    assert_eq!((best.host.as_str(), best.age), ("127.0.0.1", 86_400));
    assert!(!best.persist);
    let (_, bad) = fetched("h3=");
    assert!(matches!(
        cache.receive(&origin, &bad, 1),
        Err(Defect::Syntax)
    ));
    assert!(cache.best(&origin, 1).is_some());
    let moved = "h3=\":1\"; persist=1, h3=\":2\"";
    let (other, _) = fetched("h3=\":9\"");
    cache.receive(&other, moved, 3).unwrap();
    cache.change();
    let kept = cache.fresh(&other, 3);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].port, 1);
    let (_, gone) = fetched("clear");
    cache.receive(&origin, &gone, 2).unwrap();
    assert!(cache.best(&origin, 2).is_none());
    assert_eq!(cache.count(), 1);
    let mut big = Cache::new(8);
    big.receive(&origin, "h3=\":1\"", 0).unwrap();
    big.receive(&origin, "h3=\":3\"", 1).unwrap();
    assert_eq!(big.fresh(&origin, 1).len(), 1);
    assert_eq!(big.best(&origin, 1).unwrap().port, 3);
    let mut small = Cache::new(1);
    small.receive(&origin, "h3=\":1\"", 0).unwrap();
    small.receive(&other, "h3=\":2\"", 0).unwrap();
    assert_eq!(small.count(), 1);
    assert!(small.fresh(&origin, 0).is_empty());
    assert_eq!(small.fresh(&other, 0).len(), 1);
    small.receive(&other, "h3=\":3\"", 1).unwrap();
    assert_eq!(small.count(), 1);
    assert_eq!(small.fresh(&other, 1)[0].port, 3);
    assert!(matches!(small.receive(&other, "", 2), Err(Defect::Empty)));
}
