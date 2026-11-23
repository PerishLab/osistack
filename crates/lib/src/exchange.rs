use crate::client::Client;
use crate::error::Error;
use crate::secure::{self, Link};
use h1::{Chunked, Framing, Head};
use socket::Stream;
use std::time::{Duration, Instant};

enum Body {
    Plain(Stream),
    Secure(Link),
}

pub(crate) enum Slot {
    Plain { stream: Stream, data: Vec<u8> },
    Secure { link: Link, data: Vec<u8> },
}

pub struct Exchange<'a> {
    body: Option<Body>,
    client: &'a Client,
    data: Vec<u8>,
    deadline: Instant,
}

impl<'a> Exchange<'a> {
    pub fn open(client: &'a Client, host: &str, port: u16) -> Result<Self, Error> {
        Self::until(client, host, port, Instant::now() + client.total)
    }

    pub fn until(
        client: &'a Client,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let timeout = budget(deadline, client.connect)?;
        let stream = Stream::connect(host, port, timeout)
            .map_err(|error| stamp(error, deadline, client.connect))?;
        Ok(Self::resume(client, stream, Vec::new(), deadline))
    }

    pub fn resume(client: &'a Client, stream: Stream, data: Vec<u8>, deadline: Instant) -> Self {
        Self::restore(client, Slot::Plain { stream, data }, deadline)
    }

    pub(crate) fn restore(client: &'a Client, slot: Slot, deadline: Instant) -> Self {
        let (body, data) = match slot {
            Slot::Plain { stream, data } => (Body::Plain(stream), data),
            Slot::Secure { link, data } => (Body::Secure(link), data),
        };
        Self {
            body: Some(body),
            client,
            data,
            deadline,
        }
    }

    pub fn wrap(&mut self, host: &str) -> Result<(), Error> {
        self.hold(host, false)
    }

    pub fn wire(&mut self, host: &str) -> Result<(), Error> {
        self.hold(host, true)
    }

    pub fn h2(&self) -> bool {
        matches!(&self.body, Some(Body::Secure(link)) if link.h2())
    }

    fn hold(&mut self, host: &str, offered: bool) -> Result<(), Error> {
        let Body::Plain(stream) = self.body.take().ok_or(Error::Short)? else {
            return Err(Error::Scheme);
        };
        let link = if offered {
            secure::browse(stream, host, self.client, self.deadline)?
        } else {
            secure::open(stream, host, self.client, self.deadline)?
        };
        self.body = Some(Body::Secure(link));
        Ok(())
    }

    pub(crate) fn gather(&mut self) -> Result<Vec<u8>, Error> {
        self.fill()?;
        Ok(std::mem::take(&mut self.data))
    }

    pub(crate) fn release(self) -> Slot {
        match self.body {
            Some(Body::Plain(stream)) => Slot::Plain {
                stream,
                data: self.data,
            },
            Some(Body::Secure(link)) => Slot::Secure {
                link,
                data: self.data,
            },
            None => panic!("held"),
        }
    }

    fn limit(&self, phase: Duration) -> Result<Duration, Error> {
        budget(self.deadline, phase)
    }

    fn used(&mut self) -> Result<&mut Body, Error> {
        self.body.as_mut().ok_or(Error::Short)
    }

    fn emit(&mut self, bytes: &[u8], phase: Duration) -> Result<usize, Error> {
        let timeout = self.limit(phase)?;
        match self.used()? {
            Body::Plain(stream) => stream
                .write(bytes, Some(timeout))
                .map_err(|error| stamp(error, self.deadline, phase)),
            Body::Secure(link) => link.write(bytes, timeout),
        }
    }

    fn recv(&mut self, buf: &mut [u8], phase: Duration) -> Result<usize, Error> {
        let timeout = self.limit(phase)?;
        match self.used()? {
            Body::Plain(stream) => stream
                .read(buf, Some(timeout))
                .map_err(|error| stamp(error, self.deadline, phase)),
            Body::Secure(link) => link.read(buf, timeout),
        }
    }

    pub fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut sent = 0;
        while sent < bytes.len() {
            let count = self.emit(&bytes[sent..], self.client.write)?;
            if count == 0 {
                return Err(Error::Short);
            }
            sent += count;
        }
        Ok(())
    }

    pub fn head(&mut self) -> Result<Head, Error> {
        loop {
            if let Some(head) = self.peel()? {
                return Ok(head);
            }
            self.fill()?;
        }
    }

    pub fn body(&mut self, framing: Framing) -> Result<Vec<u8>, Error> {
        match framing {
            Framing::Empty => Ok(Vec::new()),
            Framing::Length(size) => self.sized(size),
            Framing::Chunked => self.chunked(),
            Framing::Close => self.closed(),
        }
    }

    fn peel(&mut self) -> Result<Option<Head>, Error> {
        while let Some((head, used)) = Head::parse(&self.data, self.client.head)? {
            self.data.drain(..used);
            if head.status.get() >= 200 {
                return Ok(Some(head));
            }
        }
        Ok(None)
    }

    fn fill(&mut self) -> Result<(), Error> {
        if self.pull()? == 0 {
            return Err(Error::Short);
        }
        Ok(())
    }

    fn pull(&mut self) -> Result<usize, Error> {
        let mut chunk = [0u8; 8192];
        let count = self.recv(&mut chunk, self.client.read)?;
        self.data.extend_from_slice(&chunk[..count]);
        Ok(count)
    }

    fn sized(&mut self, size: u64) -> Result<Vec<u8>, Error> {
        let size = usize::try_from(size)
            .ok()
            .filter(|size| *size <= self.client.body)
            .ok_or(Error::Limit)?;
        while self.data.len() < size {
            self.fill()?;
        }
        self.data.truncate(size);
        Ok(std::mem::take(&mut self.data))
    }

    fn chunked(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            let found = Chunked::decode(&self.data)?;
            if found
                .as_ref()
                .is_some_and(|body| body.data.len() > self.client.body)
            {
                return Err(Error::Limit);
            }
            if let Some(body) = found {
                return Ok(body.data);
            }
            if self.data.len() > self.client.body {
                return Err(Error::Limit);
            }
            self.fill()?;
        }
    }

    fn closed(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            if self.data.len() > self.client.body {
                return Err(Error::Limit);
            }
            if self.pull()? == 0 {
                return Ok(std::mem::take(&mut self.data));
            }
        }
    }
}

fn budget(deadline: Instant, phase: Duration) -> Result<Duration, Error> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| *left > Duration::ZERO)
        .ok_or(Error::Timeout)?;
    Ok(left.min(phase))
}

fn stamp(error: socket::Error, deadline: Instant, phase: Duration) -> Error {
    let capped = deadline
        .checked_duration_since(Instant::now())
        .is_none_or(|left| left < phase);
    if matches!(error, socket::Error::Timeout(_)) && capped {
        Error::Timeout
    } else {
        Error::Socket(error)
    }
}
