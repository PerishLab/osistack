use super::{GRANULARITY, Outcome, Rtt, Sent};

#[derive(Debug, Clone)]
pub struct Reno {
    datagram: u64,
    delay: u64,
    window: u64,
    flight: u64,
    start: Option<u64>,
    limit: Option<u64>,
    credit: u64,
    pinned: bool,
}

fn segments(packets: &[Sent]) -> Vec<Vec<&Sent>> {
    let mut sorted: Vec<&Sent> = packets.iter().collect();
    sorted.sort_by_key(|packet| packet.number);
    let mut out: Vec<Vec<&Sent>> = Vec::new();
    for packet in sorted {
        match out.last_mut() {
            Some(run)
                if run
                    .last()
                    .is_some_and(|last| last.number + 1 == packet.number) =>
            {
                run.push(packet)
            }
            _ => out.push(vec![packet]),
        }
    }
    out
}

fn width(run: &[&Sent], first: u64) -> u64 {
    let times: Vec<u64> = run
        .iter()
        .filter(|packet| packet.eliciting && packet.time > first)
        .map(|packet| packet.time)
        .collect();
    match (times.iter().min(), times.iter().max()) {
        (Some(low), Some(high)) => high - low,
        _ => 0,
    }
}

impl Reno {
    pub fn new(datagram: u64, delay: u64) -> Self {
        let datagram = datagram.max(1);
        Self {
            datagram,
            delay,
            window: (10 * datagram).min((2 * datagram).max(14_720)),
            flight: 0,
            start: None,
            limit: None,
            credit: 0,
            pinned: false,
        }
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    pub fn flight(&self) -> u64 {
        self.flight
    }

    pub fn threshold(&self) -> Option<u64> {
        self.limit
    }

    pub fn start(&self) -> Option<u64> {
        self.start
    }

    pub fn room(&self) -> u64 {
        self.window.saturating_sub(self.flight)
    }

    pub fn limited(&mut self, flag: bool) {
        self.pinned = flag;
    }

    pub fn sent(&mut self, packet: &Sent) {
        if packet.flight {
            self.flight = self.flight.saturating_add(packet.size);
        }
    }

    pub fn discard(&mut self, packets: &[Sent]) {
        for packet in packets.iter().filter(|packet| packet.flight) {
            self.flight = self.flight.saturating_sub(packet.size);
        }
    }

    pub fn settle(&mut self, now: u64, outcome: &Outcome, rtt: &Rtt) {
        self.lost(now, &outcome.lost, rtt);
        self.acked(&outcome.acked);
    }

    pub fn acked(&mut self, packets: &[Sent]) {
        for packet in packets.iter().filter(|packet| packet.flight) {
            self.flight = self.flight.saturating_sub(packet.size);
            if self.pinned || self.recovering(packet.time) {
                continue;
            }
            if self.limit.is_none_or(|limit| self.window < limit) {
                self.window = self.window.saturating_add(packet.size);
            } else {
                self.grow(packet.size);
            }
        }
    }

    pub fn lost(&mut self, now: u64, packets: &[Sent], rtt: &Rtt) {
        let mut latest = None;
        for packet in packets.iter().filter(|packet| packet.flight) {
            self.flight = self.flight.saturating_sub(packet.size);
            latest = latest.max(Some(packet.time));
        }
        if let Some(time) = latest {
            self.event(now, time);
        }
        if self.persistent(packets, rtt) {
            self.window = 2 * self.datagram;
            self.start = None;
            self.credit = 0;
        }
    }

    fn recovering(&self, time: u64) -> bool {
        self.start.is_some_and(|start| time <= start)
    }

    fn grow(&mut self, size: u64) {
        self.credit = self.credit.saturating_add(size);
        let steps = self.credit / self.window;
        self.credit %= self.window;
        self.window = self
            .window
            .saturating_add(steps.saturating_mul(self.datagram));
    }

    fn event(&mut self, now: u64, time: u64) {
        if self.recovering(time) {
            return;
        }
        self.start = Some(now);
        let half = self.window / 2;
        self.limit = Some(half);
        self.window = half.max(2 * self.datagram);
        self.credit = 0;
    }

    fn persistent(&self, packets: &[Sent], rtt: &Rtt) -> bool {
        let Some(first) = rtt.first() else {
            return false;
        };
        let spread = rtt.vary().saturating_mul(4).max(GRANULARITY);
        let span = rtt
            .smooth()
            .saturating_add(spread)
            .saturating_add(self.delay);
        let period = span.saturating_mul(3);
        segments(packets)
            .iter()
            .any(|run| width(run, first) > period)
    }
}
