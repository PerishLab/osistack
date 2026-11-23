use crate::error::Error;
use crate::frame::{Ack, Frame};
use crate::recovery::{Arrival, Life, Outcome, Received, Recovery, Seen, Sent, Space};

pub struct Control {
    pub recovery: Recovery,
    pub received: Received,
    pub life: Life,
}

impl Control {
    pub fn new(delay: u64, exponent: u64) -> Self {
        Self {
            recovery: Recovery::new(false, delay, exponent),
            received: Received::new(delay, exponent, 64),
            life: Life::default(),
        }
    }

    pub fn ingest(&mut self, space: Space, arrival: Arrival) -> Seen {
        self.received.receive(space, arrival)
    }

    pub fn ack(&mut self, space: Space, now: u64) -> Option<Ack> {
        self.received.frame(space, now)
    }

    pub fn sent(&mut self, space: Space, packet: Sent) {
        self.recovery.sent(space, packet);
    }

    pub fn acked(&mut self, now: u64, space: Space, ack: &Ack) -> Result<Outcome, Error> {
        self.recovery.acked(now, space, ack)
    }

    pub fn close(
        &mut self,
        now: u64,
        code: u64,
        frame: u64,
        reason: &[u8],
    ) -> Result<Frame, Error> {
        let pto = u64::from(self.recovery.pto()).max(1_000);
        let frame = Frame::Transport {
            code,
            frame,
            reason: reason.to_vec(),
        };
        self.life.close(now, pto, frame.clone())?;
        Ok(frame)
    }
}
