use http::{Class, Error, Status};

#[test]
fn classes() {
    let cases = [
        (100, Class::Informational),
        (199, Class::Informational),
        (200, Class::Success),
        (204, Class::Success),
        (301, Class::Redirection),
        (404, Class::Client),
        (500, Class::Server),
        (599, Class::Server),
    ];
    for (code, class) in cases {
        let status = Status::new(code).unwrap();
        assert_eq!(status.get(), code);
        assert_eq!(status.class(), class);
    }
}

#[test]
fn range() {
    for code in [0, 1, 99, 600, 999, 1000, u16::MAX] {
        assert_eq!(Status::new(code), Err(Error::Range), "{code}");
    }
}

#[test]
fn order() {
    assert!(Status::new(200).unwrap() < Status::new(404).unwrap());
}
