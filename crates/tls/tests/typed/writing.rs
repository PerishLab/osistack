use tls::{Error, Identity, Share, Typed};

fn share(group: u16, size: usize) -> Share {
    Share {
        group,
        key: vec![1; size],
    }
}

fn offered(labels: usize, binders: &[usize]) -> Typed {
    Typed::Offered {
        identities: (0..labels)
            .map(|at| Identity {
                label: vec![5; at + 1],
                age: 7,
            })
            .collect(),
        binders: binders.iter().map(|size| vec![9; *size]).collect(),
    }
}

fn fails(typed: Typed, error: Error) {
    assert_eq!(
        typed.write().map(|found| found.kind),
        Err(error),
        "{typed:?}"
    );
}

#[test]
fn names() {
    fails(Typed::Name(Some(vec![])), Error::Length);
    fails(Typed::Name(Some(vec![1; 65533])), Error::Length);
    assert_eq!(
        Typed::Name(Some(vec![1; 65532]))
            .write()
            .unwrap()
            .data
            .len(),
        65537
    );
    assert_eq!(Typed::Name(None).write().unwrap().data.len(), 0);
}

#[test]
fn lists() {
    for typed in [
        Typed::Groups(vec![]),
        Typed::Algorithms(vec![]),
        Typed::Versions(vec![]),
    ] {
        fails(typed, Error::Length);
    }
    fails(Typed::Groups(vec![1; 32768]), Error::Length);
    assert!(Typed::Groups(vec![1; 32767]).write().is_ok());
    fails(Typed::Versions(vec![1; 128]), Error::Length);
    assert!(Typed::Versions(vec![1; 127]).write().is_ok());
}

#[test]
fn protocols() {
    fails(Typed::Protocols(vec![]), Error::Length);
    fails(Typed::Protocols(vec![vec![]]), Error::Length);
    fails(Typed::Protocols(vec![vec![1; 256]]), Error::Length);
    assert!(Typed::Protocols(vec![vec![1; 255]]).write().is_ok());
}

#[test]
fn identities() {
    fails(offered(0, &[]), Error::Length);
    fails(
        Typed::Offered {
            identities: vec![Identity {
                label: vec![],
                age: 1,
            }],
            binders: vec![vec![9; 32]],
        },
        Error::Length,
    );
    fails(offered(1, &[31]), Error::Length);
    fails(offered(2, &[32]), Error::Value);
    fails(offered(1, &[32, 32]), Error::Value);
    assert!(offered(2, &[32, 255]).write().is_ok());
    fails(offered(1, &[256]), Error::Length);
    fails(offered(2, &[31, 32]), Error::Length);
    fails(offered(2, &[32, 31]), Error::Length);
    let blank = Identity {
        label: vec![],
        age: 1,
    };
    let kept = Identity {
        label: vec![1],
        age: 1,
    };
    let binders = vec![vec![9; 32], vec![9; 32]];
    let found = Typed::Offered {
        identities: vec![blank, kept],
        binders,
    };
    fails(found, Error::Length);
}

#[test]
fn wrapped() {
    fails(Typed::Cookie(vec![]), Error::Length);
    fails(Typed::Cookie(vec![1; 65536]), Error::Length);
    assert!(Typed::Cookie(vec![1; 65535]).write().is_ok());
    fails(Typed::Modes(vec![]), Error::Length);
    fails(Typed::Modes(vec![1; 256]), Error::Length);
    assert!(Typed::Modes(vec![1; 255]).write().is_ok());
}

#[test]
fn shares() {
    fails(
        Typed::Shares(vec![share(1, 1), share(1, 2)]),
        Error::Duplicate,
    );
    fails(Typed::Shares(vec![share(1, 0)]), Error::Length);
    fails(Typed::Chosen(share(1, 0)), Error::Length);
    fails(Typed::Chosen(share(1, 65536)), Error::Length);
    assert!(Typed::Chosen(share(1, 65535)).write().is_ok());
    assert_eq!(Typed::Shares(vec![]).write().unwrap().data, vec![0, 0]);
}

#[test]
fn kinds() {
    let pairs = [
        (offered(1, &[32]), 41),
        (Typed::Selected(1), 41),
        (Typed::Versions(vec![1]), 43),
        (Typed::Version(1), 43),
        (Typed::Shares(vec![]), 51),
        (Typed::Chosen(share(1, 1)), 51),
        (Typed::Group(1), 51),
        (Typed::Early(None), 42),
        (Typed::Early(Some(u32::MAX)), 42),
        (Typed::Name(None), 0),
        (Typed::Groups(vec![1]), 10),
        (Typed::Algorithms(vec![1]), 13),
        (Typed::Protocols(vec![vec![1]]), 16),
        (Typed::Cookie(vec![1]), 44),
        (Typed::Modes(vec![1]), 45),
    ];
    for (typed, kind) in pairs {
        assert_eq!(typed.write().unwrap().kind, kind, "{typed:?}");
    }
}
