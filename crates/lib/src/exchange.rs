use crate::client::Client;
use crate::error::Error;
use h1::{Chunked, Framing, Head};
use socket::Stream;

pub struct Exchange<'a> {
    stream: Stream,
    client: &'a Client,
    data: Vec<u8>,
}

impl<'a> Exchange<'a> {
    pub fn open(client: &'a Client, host: &str, port: u16) -> Result<Self, Error> {
        let stream = Stream::connect(host, port, client.connect)?;
        Ok(Self {
            stream,
            client,
            data: Vec::new(),
        })
    }

    pub fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut sent = 0;
        while sent < bytes.len() {
            let count = self.stream.write(&bytes[sent..], Some(self.client.write))?;
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
        let count = self.stream.read(&mut chunk, Some(self.client.read))?;
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
