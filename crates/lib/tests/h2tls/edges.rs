use crate::support::{Codec, Frame, Setting, Wire, keys, local, settings, spawn, speak, write};
use h2::INITIAL;
use osistack::http::{Method, Uri};

fn note() -> &'static str {
    "this fixture does not choose the h2 test-peer shape"
}

fn uri(port: u16) -> Uri {
    Uri::parse(&format!("https://localhost:{port}/path")).unwrap()
}

fn post() -> Method {
    Method::new("POST").unwrap()
}

#[test]
fn pushing() {
    let (port, server) = spawn(|mut stream| {
        let (hello, waiting, mut buffer) = speak(&mut stream);
        let (mut send, mut recv) = keys(&hello, &waiting);
        let codec = Codec::default();
        let mut seen = Vec::new();
        let mut used = 0;
        let mut wire = Wire {
            recv: &mut recv,
            stream: &mut stream,
            buffer: &mut buffer,
            seen: &mut seen,
            used: &mut used,
        };
        wire.preface(&codec);
        let list = vec![Setting { id: 2, value: 1 }];
        write(
            &mut send,
            wire.stream,
            &[Frame::Settings { ack: false, list }, settings(true)],
        );
        seen
    });
    let result = local().fetch(Method::new("GET").unwrap(), &uri(port), b"");
    assert!(result.is_err(), "{}: {result:?}", note());
    drop(server);
}

#[test]
fn blocked() {
    let (port, server) = spawn(|mut stream| {
        let (hello, waiting, mut buffer) = speak(&mut stream);
        let (mut send, mut recv) = keys(&hello, &waiting);
        let codec = Codec::default();
        let mut seen = Vec::new();
        let mut used = 0;
        let mut wire = Wire {
            recv: &mut recv,
            stream: &mut stream,
            buffer: &mut buffer,
            seen: &mut seen,
            used: &mut used,
        };
        wire.preface(&codec);
        let list = vec![Setting { id: 4, value: 0 }];
        write(
            &mut send,
            wire.stream,
            &[Frame::Settings { ack: false, list }, settings(true)],
        );
        seen
    });
    let result = local().fetch(post(), &uri(port), b"hello");
    assert!(result.is_err(), "{}: {result:?}", note());
    drop(server);
}

#[test]
fn overflow() {
    let (port, server) = spawn(|mut stream| {
        let (hello, waiting, mut buffer) = speak(&mut stream);
        let (mut send, mut recv) = keys(&hello, &waiting);
        let codec = Codec::default();
        let mut seen = Vec::new();
        let mut used = 0;
        let mut wire = Wire {
            recv: &mut recv,
            stream: &mut stream,
            buffer: &mut buffer,
            seen: &mut seen,
            used: &mut used,
        };
        wire.preface(&codec);
        write(&mut send, wire.stream, &[settings(false), settings(true)]);
        let (id, _, _) = wire.request(&codec);
        let block = h2::Encoder::new(4096, true).encode(&[
            h2::Header::new(b":status", b"200"),
            h2::Header::new(b"content-type", b"text/plain"),
        ]);
        write(
            &mut send,
            wire.stream,
            &[Frame::Headers {
                stream: id,
                fin: false,
                complete: true,
                pad: None,
                priority: None,
                block,
            }],
        );
        let chunk = vec![b'x'; 16_384];
        let mut sent = 0u32;
        while sent <= INITIAL {
            let fin = sent + 16_384 > INITIAL;
            write(
                &mut send,
                wire.stream,
                &[Frame::Data {
                    stream: id,
                    fin,
                    pad: None,
                    data: chunk.clone(),
                }],
            );
            sent += 16_384;
            if fin {
                break;
            }
        }
        seen
    });
    let result = local().fetch(Method::new("GET").unwrap(), &uri(port), b"");
    assert!(result.is_err(), "{}: {result:?}", note());
    drop(server);
}
