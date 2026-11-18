use http::{Error, Scheme, Uri};

fn parse(text: &str) -> Uri {
    Uri::parse(text).unwrap()
}

#[test]
fn example() {
    let uri = parse("http://example.com:8042/over/there?name=ferret#nose");
    assert_eq!(uri.scheme(), Scheme::Http);
    assert_eq!(uri.host(), "example.com");
    assert_eq!(uri.port(), 8042);
    assert_eq!(uri.authority(), "example.com:8042");
    assert_eq!(uri.target(), "/over/there?name=ferret");
}

#[test]
fn simple() {
    let uri = parse("http://www.ietf.org/rfc/rfc2396.txt");
    assert_eq!(uri.host(), "www.ietf.org");
    assert_eq!(uri.port(), 80);
    assert_eq!(uri.authority(), "www.ietf.org");
    assert_eq!(uri.target(), "/rfc/rfc2396.txt");
}

#[test]
fn literal() {
    let uri = parse("http://[2001:db8::7]/c=GB?objectClass?one");
    assert_eq!(uri.host(), "2001:db8::7");
    assert_eq!(uri.authority(), "[2001:db8::7]");
    assert_eq!(uri.target(), "/c=GB?objectClass?one");
    let uri = parse("https://[::1]:8443/");
    assert_eq!(uri.authority(), "[::1]:8443");
    assert_eq!(uri.port(), 8443);
}

#[test]
fn lowercase() {
    let uri = parse("HTTPS://Example.COM/Path/CaSe?Q=A");
    assert_eq!(uri.scheme(), Scheme::Https);
    assert_eq!(uri.scheme().text(), "https");
    assert_eq!(uri.host(), "example.com");
    assert_eq!(uri.target(), "/Path/CaSe?Q=A");
    assert_eq!(parse("http://[FE80::1]/").host(), "fe80::1");
}

#[test]
fn defaults() {
    assert_eq!(parse("http://a/").port(), 80);
    assert_eq!(parse("https://a/").port(), 443);
    assert_eq!(parse("http://a:80/").authority(), "a");
    assert_eq!(parse("https://a:443/").authority(), "a");
    assert_eq!(parse("http://a:443/").authority(), "a:443");
    assert_eq!(parse("https://a:80/").authority(), "a:80");
    assert_eq!(parse("http://a:8080").port(), 8080);
}

#[test]
fn empty() {
    assert_eq!(parse("http://example.com").target(), "/");
    assert_eq!(parse("http://example.com?x=1").target(), "/?x=1");
    assert_eq!(parse("http://example.com#top").target(), "/");
    assert_eq!(parse("http://example.com/?").target(), "/?");
    assert_eq!(parse("http://example.com:/").port(), 80);
    assert_eq!(parse("http://example.com:/").authority(), "example.com");
}

#[test]
fn preserved() {
    let uri = parse("http://a/%7Euser/a%2Fb/./../c;p=1?x=%41&y=a+b#frag");
    assert_eq!(uri.target(), "/%7Euser/a%2Fb/./../c;p=1?x=%41&y=a+b");
    assert_eq!(parse("http://a/@:!$&'()*+,;=").target(), "/@:!$&'()*+,;=");
}

#[test]
fn fragment() {
    assert_eq!(parse("http://a/p?q#f").target(), "/p?q");
    assert_eq!(parse("http://a/p#f?g").target(), "/p");
    assert_eq!(parse("http://a/#").target(), "/");
}

#[test]
fn userinfo() {
    for text in [
        "http://user@example.com/",
        "http://user:pass@example.com/",
        "http://@a/",
        "http://[::1]@a/",
    ] {
        assert_eq!(Uri::parse(text), Err(Error::Userinfo), "{text}");
    }
}

#[test]
fn hostile() {
    for text in [
        "http://exa mple.com/",
        "http://example.com/a b",
        "http://example.com/a\r\nHost: x",
        "http://example.com/a\tb",
        "http://example.com/\u{7f}",
        "http://example.com/名字",
        "http://例え.jp/",
        " http://example.com/",
        "http://example.com/\u{0}",
    ] {
        assert_eq!(Uri::parse(text), Err(Error::Character), "{text:?}");
    }
}

#[test]
fn escapes() {
    for text in [
        "http://a/%",
        "http://a/%4",
        "http://a/%zz",
        "http://a/a%g1",
        "http://a/?q=%",
        "http://a/#%x",
        "http://a/<",
        "http://a/?q=\"",
        "http://a/a|b",
        "http://a/a\\b",
        "http://a/?q=[1]",
    ] {
        assert_eq!(Uri::parse(text), Err(Error::Character), "{text}");
    }
}

#[test]
fn schemes() {
    for text in [
        "ftp://a/",
        "file:///etc",
        "//a/",
        "a/b",
        "mailto:x@y",
        "httpx://a/",
        "://a/",
        "",
    ] {
        let expected = if text.is_empty() {
            Error::Empty
        } else {
            Error::Scheme
        };
        assert_eq!(Uri::parse(text), Err(expected), "{text}");
    }
    assert_eq!(Uri::parse("http:example.com"), Err(Error::Host));
    assert_eq!(Uri::parse("http:/example.com"), Err(Error::Host));
}

#[test]
fn hosts() {
    for text in [
        "http:///path",
        "http://:80/",
        "http://?x",
        "http://a%41/",
        "http://a:b:80/",
        "http://[::1/",
        "http://[]/",
        "http://[1:2:3]/",
        "http://[::1%25eth0]/",
        "http://[::1]x/",
        "http://a<b/",
        "http://a[b/",
    ] {
        assert_eq!(Uri::parse(text), Err(Error::Host), "{text}");
    }
}

#[test]
fn ports() {
    for text in [
        "http://a:0/",
        "http://a:65536/",
        "http://a:x/",
        "http://a:80x/",
        "http://a:-1/",
        "http://a:+80/",
        "http://a:99999999999999999999/",
        "http://[::1]:0/",
    ] {
        assert_eq!(Uri::parse(text), Err(Error::Port), "{text}");
    }
    assert_eq!(parse("http://a:65535/").port(), 65535);
    assert_eq!(parse("http://a:1/").port(), 1);
}
