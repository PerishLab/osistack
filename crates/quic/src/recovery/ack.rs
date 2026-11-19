use super::{GRANULARITY, Outcome, Recovery, Sent, Space};
use crate::error::Error;
use crate::frame::Ack;

const THRESHOLD: u64 = 3;

fn spans(ack: &Ack) -> Vec<(u64, u64)> {
    let mut high = ack.largest;
    let mut low = high - ack.first;
    let mut out = vec![(low, high)];
    for (gap, length) in &ack.ranges {
        high = low - gap - 2;
        low = high - length;
        out.push((low, high));
    }
    out
}

impl Recovery {
    pub fn acked(&mut self, now: u64, space: Space, ack: &Ack) -> Result<Outcome, Error> {
        ack.check()?;
        if space == Space::Handshake {
            self.validated = true;
        }
        let lane = &mut self.lanes[space.slot()];
        lane.largest = lane.largest.max(Some(ack.largest));
        let mut found = Vec::new();
        for (low, high) in spans(ack) {
            let mut tail = lane.sent.split_off(&low);
            let rest = tail.split_off(&high.saturating_add(1));
            found.extend(tail.into_values());
            lane.sent.extend(rest);
        }
        found.sort_by_key(|packet| packet.number);
        let Some(top) = found.last() else {
            return Ok(Outcome::default());
        };
        if top.number == ack.largest && found.iter().any(|packet| packet.eliciting) {
            let latest = now.saturating_sub(top.time);
            let delay = self.scaled(space, ack);
            self.rtt.update(now, latest, delay);
        }
        let lost = self.detect(now, space);
        if self.validated {
            self.pto = 0;
        }
        self.arm(now);
        Ok(Outcome { acked: found, lost })
    }

    fn scaled(&self, space: Space, ack: &Ack) -> u64 {
        if space == Space::Initial {
            return 0;
        }
        let raw = ack.delay.saturating_mul(1 << self.exponent.min(20));
        if self.confirmed {
            raw.min(self.delay)
        } else {
            raw
        }
    }

    pub(super) fn detect(&mut self, now: u64, space: Space) -> Vec<Sent> {
        let base = self.rtt.latest().max(self.rtt.smooth());
        let window = (base.saturating_mul(9) / 8).max(GRANULARITY);
        let lane = &mut self.lanes[space.slot()];
        lane.loss = None;
        let Some(largest) = lane.largest else {
            return Vec::new();
        };
        let mut gone = Vec::new();
        for (number, packet) in lane.sent.range(..=largest) {
            let late = packet.time.saturating_add(window);
            if late <= now || largest >= number + THRESHOLD {
                gone.push(*number);
            } else {
                lane.loss = Some(lane.loss.map_or(late, |least| least.min(late)));
            }
        }
        gone.iter()
            .filter_map(|number| lane.sent.remove(number))
            .collect()
    }
}
