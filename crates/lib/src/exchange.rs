use crate::client::Client;
use crate::error::Error;
use h1::{Chunked, Framing, Head};
use socket::Stream;
use std::time::{Duration, Instant};

pub struct Exchange<'a> {
    stream: Stream,
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
        Self {
            stream,
            client,
            data,
            deadline,
        }
    }

    pub fn taken(self) -> (Stream, Vec<u8>) {
        (self.stream, self.data)
    }

    fn limit(&self, phase: Duration) -> Result<Duration, Error> {
        budget(self.deadline, phase)
    }

    fn wrap(&self, error: socket::Error, phase: Duration) -> Error {
        stamp(error, self.deadline, phase)
    }

    pub fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut sent = 0;
        while sent < bytes.len() {
            let count = self
                .stream
                .write(&bytes[sent..], Some(self.limit(self.client.write)?))
                .map_err(|error| self.wrap(error, self.client.write))?;
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
        let count = self
            .stream
            .read(&mut chunk, Some(self.limit(self.client.read)?))
            .map_err(|error| self.wrap(error, self.client.read))?;
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
