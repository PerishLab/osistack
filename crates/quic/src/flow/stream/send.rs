use super::span::Spans;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    pub offset: u64,
    pub data: Vec<u8>,
    pub fin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Ready,
    Send,
    Sent,
    Acked,
    Reset,
    Gone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    Idle,
    Sent,
    Lost,
    Acked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cut {
    Queued,
    Flying,
    Done,
}

#[derive(Debug, Clone)]
pub struct Sending {
    base: u64,
    data: Vec<u8>,
    sent: u64,
    acked: Spans,
    lost: Spans,
    limit: u64,
    told: Option<u64>,
    finish: bool,
    tail: Tail,
    reset: Option<(u64, u64)>,
    cut: Cut,
}

impl Sending {
    pub fn new(limit: u64) -> Self {
        Self {
            base: 0,
            data: Vec::new(),
            sent: 0,
            acked: Spans::default(),
            lost: Spans::default(),
            limit,
            told: None,
            finish: false,
            tail: Tail::Idle,
            reset: None,
            cut: Cut::Queued,
        }
    }

    pub fn written(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        if self.finish || self.reset.is_some() {
            return 0;
        }
        self.data.extend_from_slice(data);
        data.len()
    }

    pub fn finish(&mut self) -> bool {
        if self.finish || self.reset.is_some() {
            return false;
        }
        self.finish = true;
        true
    }

    fn slice(&self, from: u64, to: u64) -> Vec<u8> {
        let (low, high) = ((from - self.base) as usize, (to - self.base) as usize);
        self.data[low..high].to_vec()
    }

    pub fn next(&mut self, max: usize) -> Option<Piece> {
        if self.reset.is_some() {
            return None;
        }
        let max = max as u64;
        self.again(max)
            .or_else(|| self.fresh(max))
            .or_else(|| self.close())
    }

    fn again(&mut self, max: u64) -> Option<Piece> {
        let (start, stop) = self.lost.first()?;
        let size = (stop - start).min(max);
        if size == 0 {
            return None;
        }
        self.lost.cut(start, start + size);
        let last = start + size == self.written();
        let fin = last && self.tail == Tail::Lost;
        if fin {
            self.tail = Tail::Sent;
        }
        let data = self.slice(start, start + size);
        Some(Piece {
            offset: start,
            data,
            fin,
        })
    }

    fn fresh(&mut self, max: u64) -> Option<Piece> {
        let room = self.written().min(self.limit).saturating_sub(self.sent);
        let size = room.min(max);
        if size == 0 {
            return None;
        }
        let offset = self.sent;
        self.sent += size;
        let fin = self.finish && self.sent == self.written() && self.tail == Tail::Idle;
        if fin {
            self.tail = Tail::Sent;
        }
        let data = self.slice(offset, self.sent);
        Some(Piece { offset, data, fin })
    }

    fn close(&mut self) -> Option<Piece> {
        let flush = self.finish && self.sent == self.written() && self.tail == Tail::Idle;
        let retry = self.tail == Tail::Lost && self.lost.first().is_none();
        if !flush && !retry {
            return None;
        }
        self.tail = Tail::Sent;
        Some(Piece {
            offset: self.written(),
            data: Vec::new(),
            fin: true,
        })
    }

    pub fn acked(&mut self, offset: u64, size: u64, fin: bool) {
        if self.reset.is_some() {
            return;
        }
        let start = offset.max(self.base);
        let stop = offset.saturating_add(size).min(self.sent);
        self.acked.add(start, stop);
        self.lost.cut(start, stop);
        if fin && self.tail != Tail::Idle {
            self.tail = Tail::Acked;
        }
        if let Some((from, to)) = self.acked.first().filter(|(from, _)| *from == self.base) {
            self.data.drain(..(to - from) as usize);
            self.base = to;
            self.acked.cut(from, to);
        }
    }

    pub fn lost(&mut self, offset: u64, size: u64, fin: bool) {
        if self.reset.is_some() {
            return;
        }
        let start = offset.max(self.base);
        let stop = offset.saturating_add(size).min(self.sent);
        for (from, to) in self.acked.gaps(start, stop) {
            self.lost.add(from, to);
        }
        if fin && self.tail == Tail::Sent {
            self.tail = Tail::Lost;
        }
    }

    pub fn reset(&mut self, code: u64) -> bool {
        if self.reset.is_some() || self.stage() == Stage::Acked {
            return false;
        }
        self.reset = Some((code, self.sent));
        self.data.clear();
        self.acked = Spans::default();
        self.lost = Spans::default();
        true
    }

    pub fn stop(&mut self, code: u64) -> bool {
        self.reset(code)
    }

    pub fn frame(&mut self) -> Option<(u64, u64)> {
        let pair = self.reset?;
        if self.cut != Cut::Queued {
            return None;
        }
        self.cut = Cut::Flying;
        Some(pair)
    }

    pub fn retry(&mut self) {
        if self.cut == Cut::Flying {
            self.cut = Cut::Queued;
        }
    }

    pub fn settle(&mut self) {
        if self.reset.is_some() {
            self.cut = Cut::Done;
        }
    }

    pub fn raise(&mut self, limit: u64) -> bool {
        if limit <= self.limit {
            return false;
        }
        self.limit = limit;
        true
    }

    pub fn blocked(&mut self) -> Option<u64> {
        let stuck = self.reset.is_none() && self.sent < self.written() && self.sent >= self.limit;
        if !stuck || self.told == Some(self.limit) {
            return None;
        }
        self.told = Some(self.limit);
        Some(self.limit)
    }

    pub fn stage(&self) -> Stage {
        if self.reset.is_some() {
            return if self.cut == Cut::Done {
                Stage::Gone
            } else {
                Stage::Reset
            };
        }
        if self.tail == Tail::Acked && self.base == self.written() {
            return Stage::Acked;
        }
        if self.tail != Tail::Idle {
            return Stage::Sent;
        }
        if self.written() > 0 || self.finish {
            return Stage::Send;
        }
        Stage::Ready
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }

    pub fn buffered(&self) -> usize {
        self.data.len()
    }
}
