use crate::error::Error;
use crate::fault::Fault;
use crate::flow::{Credit, Inbound, Lanes, Receiving, Role, Sending};
use crate::frame::{Direction, Frame, Stream};
use std::collections::BTreeMap;

pub struct Streams {
    lanes: Lanes,
    send: BTreeMap<u64, Sending>,
    recv: BTreeMap<u64, Receiving>,
    outgoing: Credit,
    incoming: Inbound,
    taken: u64,
    limit: u64,
}

impl Streams {
    pub fn new(role: Role, count: u64, limit: u64, shared: u64) -> Self {
        Self {
            lanes: Lanes::new(role, [count, count], [count, count]),
            send: BTreeMap::new(),
            recv: BTreeMap::new(),
            outgoing: Credit::new(shared),
            incoming: Inbound::new(shared),
            taken: 0,
            limit,
        }
    }

    pub fn open(&mut self) -> Result<u64, Error> {
        let id = self.lanes.open(Direction::Bidi).map_err(|_| Error::Limit)?;
        self.held(id);
        Ok(id)
    }

    pub fn write(&mut self, id: u64, data: &[u8]) -> Result<usize, Error> {
        let send = self.send.get_mut(&id).ok_or(Error::Value)?;
        Ok(send.write(data))
    }

    pub fn finish(&mut self, id: u64) -> Result<(), Error> {
        let send = self.send.get_mut(&id).ok_or(Error::Value)?;
        if send.finish() {
            Ok(())
        } else {
            Err(Error::Value)
        }
    }

    pub fn next(&mut self, id: u64, max: usize) -> Result<Option<Frame>, Error> {
        let send = self.send.get_mut(&id).ok_or(Error::Value)?;
        let room = self.outgoing.room().min(max as u64) as usize;
        let Some(piece) = send.next(room) else {
            return Ok(None);
        };
        self.outgoing.take(piece.data.len() as u64);
        Ok(Some(Frame::Stream(Stream {
            id,
            offset: piece.offset,
            data: piece.data,
            fin: piece.fin,
            sized: true,
        })))
    }

    pub fn ingest(&mut self, frames: &[Frame]) -> Result<(), Error> {
        for frame in frames {
            self.frame(frame)?;
        }
        Ok(())
    }

    pub fn read(&mut self, id: u64, max: usize) -> Result<Vec<u8>, Error> {
        let recv = self.recv.get_mut(&id).ok_or(Error::Value)?;
        let data = recv.read(max);
        self.incoming.consume(data.len() as u64);
        Ok(data)
    }

    pub fn grant(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        if let Some(limit) = self.incoming.grant() {
            frames.push(Frame::Data(limit));
        }
        for (id, recv) in &mut self.recv {
            if let Some(limit) = recv.grant() {
                frames.push(Frame::Window { stream: *id, limit });
            }
        }
        frames
    }

    fn frame(&mut self, frame: &Frame) -> Result<(), Error> {
        match frame {
            Frame::Stream(stream) => self.push(stream),
            Frame::Window { stream, limit } => {
                let send = self.send.get_mut(stream).ok_or(Error::Value)?;
                send.raise(*limit);
                Ok(())
            }
            Frame::Data(limit) => {
                self.outgoing.raise(*limit);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn push(&mut self, stream: &Stream) -> Result<(), Error> {
        for id in self.lanes.admit(stream.id).map_err(fail)? {
            self.held(id);
        }
        self.held(stream.id);
        let recv = self.recv.get_mut(&stream.id).ok_or(Error::Value)?;
        let fresh = recv
            .data(stream.offset, &stream.data, stream.fin)
            .map_err(fail)?;
        self.incoming.data(self.taken, fresh, false).map_err(fail)?;
        self.taken += fresh;
        Ok(())
    }

    fn held(&mut self, id: u64) {
        self.send
            .entry(id)
            .or_insert_with(|| Sending::new(self.limit));
        self.recv
            .entry(id)
            .or_insert_with(|| Receiving::new(self.limit));
    }
}

fn fail(fault: Fault) -> Error {
    match fault {
        Fault::Limit | Fault::Flow => Error::Limit,
        _ => Error::Value,
    }
}
