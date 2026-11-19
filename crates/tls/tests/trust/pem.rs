use crate::support::{Dice, encode, pem};
use tls::x509::trust::{Refusal, blocks, decode};

fn body() -> Vec<u8> {
    (0..100u8).collect()
}

#[test]
fn base() {
    for (plain, coded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(decode(coded), Ok(plain.as_bytes().to_vec()), "{coded}");
        assert_eq!(encode(plain.as_bytes()), coded);
    }
}

#[test]
fn padding() {
    for text in [
        "Zg", "Zg=", "Z===", "====", "Zg==Zg==", "Zm9v=", "Z=g=", "Zm9vZg=", "Zm9=Zm9v", "A===",
    ] {
        assert_eq!(decode(text), Err(Refusal::Base64), "{text}");
    }
}

#[test]
fn canon() {
    for text in ["Zh==", "Zm9=", "Zm+=", "ZR==", "Zg=A"] {
        assert_eq!(decode(text), Err(Refusal::Base64), "{text}");
    }
    assert_eq!(decode("Zg=="), Ok(vec![b'f']));
    assert_eq!(decode("Zm8="), Ok(b"fo".to_vec()));
}

#[test]
fn alphabet() {
    for text in [
        "Zm 9v",
        "Zm9v\n",
        " Zm9v",
        "Zm-v",
        "Zm_v",
        "Zm9\u{e9}",
        "Zm.v",
        "Zm9v\r\n",
    ] {
        assert_eq!(decode(text), Err(Refusal::Base64), "{text:?}");
    }
    let every: Vec<u8> = (0..=255).collect();
    assert_eq!(decode(&encode(&every)), Ok(every));
    assert_eq!(
        decode("++++////"),
        Ok(vec![0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff])
    );
}

#[test]
fn sweep() {
    for seed in 1..=64 {
        let mut dice = Dice::new(seed);
        let size = dice.below(300);
        let data = dice.bytes(size);
        assert_eq!(decode(&encode(&data)), Ok(data), "seed {seed}");
    }
}

#[test]
fn single() {
    let text = pem("CERTIFICATE", &body(), 64, "\n");
    let found = blocks(&text).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].label, "CERTIFICATE");
    assert_eq!(found[0].data, body());
}

#[test]
fn multi() {
    let first = pem("CERTIFICATE", &body(), 64, "\n");
    let second = pem("PRIVATE KEY", b"secret", 64, "\n");
    let text = format!(
        "Subject: one\nsome notes\n{first}between -----BEGIN not\n{second}trailing words\n"
    );
    let found = blocks(&text).unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(
        (found[0].label.as_str(), found[0].data.clone()),
        ("CERTIFICATE", body())
    );
    assert_eq!(
        (found[1].label.as_str(), found[1].data.clone()),
        ("PRIVATE KEY", b"secret".to_vec())
    );
}

#[test]
fn ends() {
    let want = blocks(&pem("CERTIFICATE", &body(), 64, "\n")).unwrap();
    for eol in ["\r\n", "\r", "\n"] {
        assert_eq!(
            blocks(&pem("CERTIFICATE", &body(), 64, eol)).unwrap(),
            want,
            "{eol:?}"
        );
    }
    let mixed = pem("CERTIFICATE", &body(), 64, "\n")
        .replacen('\n', "\r\n", 1)
        .replacen('\n', "\r", 1);
    assert_eq!(blocks(&mixed).unwrap(), want);
    let bare = pem("CERTIFICATE", &body(), 64, "\n");
    assert_eq!(blocks(bare.trim_end()).unwrap(), want);
}

#[test]
fn blanks() {
    let want = blocks(&pem("CERTIFICATE", &body(), 64, "\n")).unwrap();
    let text = pem("CERTIFICATE", &body(), 64, "\n")
        .replace("-----\n", "-----  \t\n")
        .replace("=\n", "= \n");
    assert_eq!(blocks(&text).unwrap(), want);
    let lead = format!("\n\n{}", pem("CERTIFICATE", &body(), 64, "\n"));
    assert_eq!(blocks(&lead).unwrap(), want);
    let after = pem("CERTIFICATE", &body(), 64, "\n").replacen("-----\n", "-----\n\n\n", 1);
    assert_eq!(blocks(&after).unwrap(), want);
}

#[test]
fn widths() {
    let want = blocks(&pem("CERTIFICATE", &body(), 64, "\n")).unwrap();
    for width in [1, 4, 7, 16, 76, 200] {
        assert_eq!(
            blocks(&pem("CERTIFICATE", &body(), width, "\n")).unwrap(),
            want,
            "{width}"
        );
    }
}

#[test]
fn empty() {
    let found = blocks("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").unwrap();
    assert_eq!(found[0].data, Vec::<u8>::new());
    let found = blocks("-----BEGIN -----\nZg==\n-----END -----\n").unwrap();
    assert_eq!(
        (found[0].label.as_str(), found[0].data.clone()),
        ("", b"f".to_vec())
    );
    assert_eq!(blocks(""), Ok(vec![]));
    assert_eq!(blocks("only words\nand more\n"), Ok(vec![]));
}

#[test]
fn labels() {
    let text = "-----BEGIN A-----\nZg==\n-----END B-----\n";
    assert_eq!(blocks(text), Err(Refusal::Label));
    let text = "-----BEGIN A-----\nZg==\n-----END a-----\n";
    assert_eq!(blocks(text), Err(Refusal::Label));
    for good in [
        "CERTIFICATE",
        "X509 CRL",
        "PRIVATE KEY",
        "A-B C",
        "a",
        "A B C",
        "A~B",
        "A!B",
    ] {
        let text = format!("-----BEGIN {good}-----\nZg==\n-----END {good}-----\n");
        assert_eq!(blocks(&text).unwrap()[0].label, good);
    }
    for bad in [
        "A--B", "A -B", "-A", "A-", "A ", " A", "A  B", "A- B", "A\u{e9}B", "A\tB", "A\u{7f}B",
    ] {
        let text = format!("-----BEGIN {bad}-----\nZg==\n-----END {bad}-----\n");
        assert_eq!(blocks(&text), Err(Refusal::Label), "{bad:?}");
    }
}

#[test]
fn frames() {
    assert_eq!(blocks("-----BEGIN A-----\nZg==\n"), Err(Refusal::Frame));
    assert_eq!(blocks("-----BEGIN A-----\n"), Err(Refusal::Frame));
    assert_eq!(blocks("Zg==\n-----END A-----\n"), Err(Refusal::Frame));
    assert_eq!(
        blocks("-----BEGIN A-----\nZg==\n-----BEGIN B-----\nZg==\n-----END B-----\n"),
        Err(Refusal::Frame)
    );
    assert_eq!(
        blocks("-----BEGIN A-----\nZg==\n-----BEGIN B-----\n"),
        Err(Refusal::Frame)
    );
    let text = format!(
        "{}-----END CERTIFICATE-----\n",
        pem("CERTIFICATE", &body(), 64, "\n")
    );
    assert_eq!(blocks(&text), Err(Refusal::Frame));
}

#[test]
fn dashes() {
    let text = "-----BEGIN A----\nZg==\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Frame));
    let text = "------BEGIN A-----\nZg==\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Frame));
    let text = "-----BEGIN A-----\nZg==\n-----END A----\n";
    assert_eq!(blocks(text), Err(Refusal::Frame));
    let text = "-----BEGIN A------\nZg==\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Label));
    let text = " -----BEGIN A-----\nZg==\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Frame));
}

#[test]
fn stray() {
    let text = "-----BEGIN A-----\nZm9v!\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Base64));
    let text = "-----BEGIN A-----\nZm9v\n\nZm9v\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Base64));
    let text = "-----BEGIN A-----\nProc-Type: 4,ENCRYPTED\nZm9v\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Base64));
    let text = "-----BEGIN A-----\nZm9v=\nZm9v\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Base64));
    let text = "-----BEGIN A-----\n Zm9v\n-----END A-----\n";
    assert_eq!(blocks(text), Err(Refusal::Base64));
    let text = "-----BEGIN A-----\nZm\n9v\n-----END A-----\n";
    assert_eq!(blocks(text).unwrap()[0].data, b"foo".to_vec());
    let text = "-----BEGIN A-----\nQQ=\n=\n-----END A-----\n";
    assert_eq!(blocks(text).unwrap()[0].data, b"A".to_vec());
}
