use super::Clock;
use super::handshake::{Session, emit, start, wait};
use crate::client::Response;
use crate::error::Error;
use h1::{Field, Head, Version};
use h3::{Call, Control, Decoder, Event, Request, Settings};
use http::{Method, Name, Status, Uri, Value};
use quic::{Frame, Number, Short};

pub(crate) fn ask(
    clock: &Clock,
    method: Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Response, Error> {
    let mut session = start(clock, uri)?;
    let fields = listed(&method, uri, &clock.client.extra, body)?;
    request(&mut session, &fields, body)?;
    collect(&mut session, clock.client.body)
}

fn listed(
    method: &Method,
    uri: &Uri,
    extra: &[Field],
    body: &[u8],
) -> Result<Vec<h3::Field>, Error> {
    let mut fields = vec![
        h3::Field::new(b":method", method.text().as_bytes()),
        h3::Field::new(b":scheme", uri.scheme().text().as_bytes()),
        h3::Field::new(b":authority", uri.authority().as_bytes()),
        h3::Field::new(b":path", uri.target().as_bytes()),
    ];
    if !body.is_empty() {
        let size = body.len().to_string();
        fields.push(h3::Field::new(b"content-length", size.as_bytes()));
    }
    for field in extra {
        if field.name.text() == "host" || field.name.text() == "connection" {
            continue;
        }
        fields.push(h3::Field::new(
            field.name.text().as_bytes(),
            field.value.bytes(),
        ));
    }
    Ok(fields)
}

fn request(session: &mut Session, fields: &[h3::Field], body: &[u8]) -> Result<(), Error> {
    let control = Call::control(&Settings::default())?;
    stream(session, 2, &control, false)?;
    let mut call = Call::new(1 << 16);
    let mut payload = call.headers(fields)?;
    if !body.is_empty() {
        payload.extend(call.data(body)?);
    }
    call.finish()?;
    stream(session, 0, &payload, true)
}

fn stream(session: &mut Session, id: u64, data: &[u8], fin: bool) -> Result<(), Error> {
    let frame = Frame::Stream(quic::Stream {
        id,
        offset: 0,
        data: data.to_vec(),
        fin,
        sized: true,
    });
    let payload = Frame::join(&[frame])?;
    let written = Number::new(session.sent, None)?;
    let short = Short {
        spin: false,
        phase: false,
        dcid: session.dcid.clone(),
        offset: 0,
    };
    let packet = session
        .applied
        .client
        .protect(session.sent, &short.write(&written)?, &payload)?;
    session.sent += 1;
    emit(&session.wire, &packet)
}

struct Inbox {
    control: Control,
    incoming: Request,
    typed: bool,
    headers: Option<Vec<u8>>,
    body: Vec<u8>,
    ended: bool,
    seen: u64,
    limit: usize,
}

fn collect(session: &mut Session, limit: usize) -> Result<Response, Error> {
    let mut inbox = Inbox {
        control: Control::new(1 << 16),
        incoming: Request::new(1 << 16),
        typed: false,
        headers: None,
        body: Vec::new(),
        ended: false,
        seen: 0,
        limit,
    };
    while !inbox.ended {
        let datagram = wait(&session.wire, session.read)?;
        let opened = session
            .applied
            .server
            .unprotect(&datagram, 1 + session.scid.len(), None)?;
        for frame in Frame::all(&opened.payload)? {
            accept(&mut inbox, frame)?;
        }
    }
    let block = inbox.headers.ok_or(Error::Short)?;
    headed(&Decoder::new(0).decode(&block)?, &inbox.body)
}

fn accept(inbox: &mut Inbox, frame: Frame) -> Result<(), Error> {
    let Frame::Stream(quic::Stream {
        id,
        offset,
        data,
        fin,
        ..
    }) = frame
    else {
        return Ok(());
    };
    if id == 3 {
        let rest = skip(data, &mut inbox.typed);
        inbox.control.feed(&rest)?;
        return Ok(());
    }
    if id != 0 {
        return Ok(());
    }
    if offset != inbox.seen {
        return Err(Error::Short);
    }
    inbox.seen += data.len() as u64;
    if inbox.body.len() + data.len() > inbox.limit {
        return Err(Error::Limit);
    }
    for event in inbox.incoming.feed(&data)? {
        match event {
            Event::Headers(block) => inbox.headers = Some(block),
            Event::Data(part) => inbox.body.extend(part),
            Event::End => inbox.ended = true,
            Event::Trailers(_) => {}
        }
    }
    if fin && inbox.incoming.end()? == Event::End {
        inbox.ended = true;
    }
    Ok(())
}

fn skip(data: Vec<u8>, typed: &mut bool) -> Vec<u8> {
    if *typed {
        return data;
    }
    if data.first() == Some(&0x00) {
        *typed = true;
        return data[1..].to_vec();
    }
    data
}

fn headed(fields: &[h3::Field], body: &[u8]) -> Result<Response, Error> {
    let mut code = None;
    let mut list = Vec::new();
    for field in fields {
        if field.name == b":status" {
            let text = std::str::from_utf8(&field.value).map_err(|_| Error::Usage)?;
            code = Some(text.parse().map_err(|_| Error::Usage)?);
            continue;
        }
        if field.name.first() == Some(&b':') {
            continue;
        }
        list.push(Field {
            name: Name::new(std::str::from_utf8(&field.name).map_err(|_| Error::Usage)?)?,
            value: Value::new(&field.value)?,
        });
    }
    Ok(Response {
        head: Head {
            version: Version::Http11,
            status: Status::new(code.ok_or(Error::Short)?)?,
            reason: String::new(),
            fields: list,
        },
        body: body.to_vec(),
    })
}
