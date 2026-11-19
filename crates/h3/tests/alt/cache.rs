use crate::support::{alt, keep, origin};
use h3::{Alternative, Cache, Defect, Directive, Origin};

const SECOND: u64 = 1_000_000;

fn other(host: &str) -> Origin {
    Origin::new(host, 443)
}

fn ports(list: Vec<&Alternative>) -> Vec<u16> {
    list.iter().map(|each| each.port).collect()
}

#[test]
fn fresh() {
    let mut cache = Cache::new(8);
    cache
        .receive(&origin(), "h3=\":443\"; ma=60", 1000)
        .unwrap();
    let due = 1000 + 60 * SECOND;
    assert_eq!(ports(cache.fresh(&origin(), 1000)), [443]);
    assert_eq!(ports(cache.fresh(&origin(), 0)), [443]);
    assert_eq!(ports(cache.fresh(&origin(), due - 1)), [443]);
    assert!(cache.fresh(&origin(), due).is_empty());
    assert!(cache.fresh(&origin(), due + 1).is_empty());
    assert_eq!(cache.count(), 1);
}

#[test]
fn unknown() {
    let cache = Cache::new(8);
    assert!(cache.fresh(&origin(), 0).is_empty());
    assert!(cache.best(&origin(), 0).is_none());
    assert_eq!(cache.count(), 0);
}

#[test]
fn replace() {
    let mut cache = Cache::new(8);
    cache
        .receive(&origin(), "h3=\":443\", h3=\":444\"", 0)
        .unwrap();
    cache.receive(&origin(), "h3=\":445\"", 5).unwrap();
    assert_eq!(ports(cache.fresh(&origin(), 5)), [445]);
    assert_eq!(cache.count(), 1);
}

#[test]
fn erase() {
    let mut cache = Cache::new(8);
    cache.receive(&origin(), "h3=\":443\"", 0).unwrap();
    cache
        .receive(&other("b.example"), "h3=\":444\"", 0)
        .unwrap();
    cache.receive(&origin(), "clear", 1).unwrap();
    assert!(cache.fresh(&origin(), 1).is_empty());
    assert_eq!(cache.count(), 1);
    cache.receive(&other("c.example"), "clear", 1).unwrap();
    assert_eq!(cache.count(), 1);
    assert_eq!(ports(cache.fresh(&other("b.example"), 1)), [444]);
    cache.store(&other("b.example"), Directive::Clear, 2);
    assert_eq!(cache.count(), 0);
}

#[test]
fn origins() {
    let mut cache = Cache::new(8);
    cache
        .receive(&Origin::new("A.example", 443), "h3=\":1\"", 0)
        .unwrap();
    cache
        .receive(&Origin::new("a.example", 8443), "h3=\":2\"", 0)
        .unwrap();
    cache
        .receive(&Origin::new("b.example", 443), "h3=\":3\"", 0)
        .unwrap();
    assert_eq!(cache.count(), 3);
    assert_eq!(ports(cache.fresh(&other("a.example"), 0)), [1]);
    assert_eq!(ports(cache.fresh(&Origin::new("a.example", 8443), 0)), [2]);
    assert_eq!(ports(cache.fresh(&other("b.example"), 0)), [3]);
    assert!(cache.fresh(&other("c.example"), 0).is_empty());
}

#[test]
fn order() {
    let mut cache = Cache::new(8);
    let text = "h3=\":1\"; ma=30, h2=\":2\"; ma=10, h3=\":3\"; ma=20";
    cache.receive(&origin(), text, 0).unwrap();
    assert_eq!(ports(cache.fresh(&origin(), 0)), [1, 2, 3]);
    assert_eq!(ports(cache.fresh(&origin(), 10 * SECOND)), [1, 3]);
    assert_eq!(ports(cache.fresh(&origin(), 20 * SECOND)), [1]);
    assert!(cache.fresh(&origin(), 30 * SECOND).is_empty());
}

#[test]
fn best() {
    let mut cache = Cache::new(8);
    let text = "h3-29=\":1\", h2=\":2\", H3=\":3\", h3=\":4\"; ma=10, h3=\":5\"";
    cache.receive(&origin(), text, 0).unwrap();
    assert_eq!(cache.best(&origin(), 0).unwrap().port, 4);
    assert_eq!(cache.best(&origin(), 10 * SECOND).unwrap().port, 5);
    cache
        .receive(&origin(), "h3-29=\":1\", h2=\":2\", H3=\":3\"", 0)
        .unwrap();
    assert!(cache.best(&origin(), 0).is_none());
    assert_eq!(cache.fresh(&origin(), 0).len(), 3);
}

#[test]
fn zero() {
    let mut cache = Cache::new(8);
    cache.receive(&origin(), "h3=\":443\"; ma=0", 7).unwrap();
    assert!(cache.fresh(&origin(), 7).is_empty());
    assert!(cache.best(&origin(), 7).is_none());
    assert_eq!(cache.count(), 1);
    cache.purge(7);
    assert_eq!(cache.count(), 0);
}

#[test]
fn purge() {
    let mut cache = Cache::new(8);
    cache
        .receive(&origin(), "h3=\":1\"; ma=10, h3=\":2\"; ma=20", 0)
        .unwrap();
    cache
        .receive(&other("b.example"), "h3=\":3\"; ma=10", 0)
        .unwrap();
    cache.purge(10 * SECOND - 1);
    assert_eq!(cache.count(), 2);
    assert_eq!(ports(cache.fresh(&origin(), 0)), [1, 2]);
    cache.purge(10 * SECOND);
    assert_eq!(cache.count(), 1);
    assert_eq!(ports(cache.fresh(&origin(), 0)), [2]);
    cache.purge(20 * SECOND);
    assert_eq!(cache.count(), 0);
}

#[test]
fn change() {
    let mut cache = Cache::new(8);
    cache
        .receive(
            &origin(),
            "h3=\":1\"; persist=1, h3=\":2\", h3=\":3\"; persist=1; ma=5",
            0,
        )
        .unwrap();
    cache
        .receive(&other("b.example"), "h3=\":4\"; persist=0, h3=\":5\"", 0)
        .unwrap();
    cache.change();
    assert_eq!(cache.count(), 1);
    assert_eq!(ports(cache.fresh(&origin(), 0)), [1, 3]);
    assert!(cache.fresh(&other("b.example"), 0).is_empty());
    cache.change();
    assert_eq!(ports(cache.fresh(&origin(), 0)), [1, 3]);
}

#[test]
fn limit() {
    let mut cache = Cache::new(2);
    for (host, port) in [("a.example", 1), ("b.example", 2), ("c.example", 3)] {
        cache
            .receive(&other(host), &format!("h3=\":{port}\""), 0)
            .unwrap();
    }
    assert_eq!(cache.count(), 2);
    assert!(cache.fresh(&other("a.example"), 0).is_empty());
    assert_eq!(ports(cache.fresh(&other("b.example"), 0)), [2]);
    assert_eq!(ports(cache.fresh(&other("c.example"), 0)), [3]);
}

#[test]
fn refresh() {
    let mut cache = Cache::new(2);
    cache.receive(&other("a.example"), "h3=\":1\"", 0).unwrap();
    cache.receive(&other("b.example"), "h3=\":2\"", 0).unwrap();
    cache.receive(&other("a.example"), "h3=\":4\"", 0).unwrap();
    assert_eq!(cache.count(), 2);
    cache.receive(&other("c.example"), "h3=\":3\"", 0).unwrap();
    assert!(cache.fresh(&other("b.example"), 0).is_empty());
    assert_eq!(ports(cache.fresh(&other("a.example"), 0)), [4]);
    assert_eq!(ports(cache.fresh(&other("c.example"), 0)), [3]);
    let mut single = Cache::new(1);
    single.receive(&other("a.example"), "h3=\":1\"", 0).unwrap();
    single.receive(&other("a.example"), "h3=\":2\"", 0).unwrap();
    assert_eq!(ports(single.fresh(&other("a.example"), 0)), [2]);
}

#[test]
fn nothing() {
    let mut cache = Cache::new(0);
    assert_eq!(cache.receive(&origin(), "h3=\":443\"", 0), Ok(()));
    assert_eq!(cache.count(), 0);
    assert!(cache.fresh(&origin(), 0).is_empty());
    assert_eq!(cache.receive(&origin(), "junk", 0), Err(Defect::Syntax));
}

#[test]
fn failed() {
    let mut cache = Cache::new(1);
    cache.receive(&origin(), "h3=\":443\"", 0).unwrap();
    assert_eq!(cache.receive(&origin(), "junk", 1), Err(Defect::Syntax));
    assert_eq!(cache.receive(&origin(), "", 1), Err(Defect::Empty));
    assert_eq!(
        cache.receive(&other("b.example"), "h3=\":0\"", 1),
        Err(Defect::Port)
    );
    assert_eq!(ports(cache.fresh(&origin(), 1)), [443]);
    assert_eq!(cache.count(), 1);
    assert_eq!(cache.receive(&origin(), "clear, junk(", 1), Ok(()));
    assert_eq!(cache.count(), 0);
}

#[test]
fn saturate() {
    let mut cache = Cache::new(8);
    let late = u64::MAX - 5;
    cache
        .receive(&origin(), "h3=\":443\"; ma=60", late)
        .unwrap();
    assert_eq!(ports(cache.fresh(&origin(), late)), [443]);
    assert_eq!(ports(cache.fresh(&origin(), u64::MAX - 1)), [443]);
    assert!(cache.fresh(&origin(), u64::MAX).is_empty());
    let huge = alt("h3", "www.example.com", 9, u64::MAX);
    cache.store(&origin(), Directive::Offer(vec![huge]), 10);
    assert_eq!(ports(cache.fresh(&origin(), u64::MAX - 1)), [9]);
}

#[test]
fn manual() {
    let mut cache = Cache::new(8);
    cache.receive(&origin(), "h3=\":443\"", 0).unwrap();
    cache.store(&origin(), Directive::Offer(vec![]), 1);
    assert_eq!(cache.count(), 0);
    let first = keep(alt("h3", "alt.example", 1, 5));
    let second = alt("h2", "alt.example", 2, 6);
    cache.store(
        &origin(),
        Directive::Offer(vec![first.clone(), second.clone()]),
        100,
    );
    assert_eq!(cache.fresh(&origin(), 100), vec![&first, &second]);
    assert_eq!(cache.fresh(&origin(), 100 + 5 * SECOND), vec![&second]);
}
