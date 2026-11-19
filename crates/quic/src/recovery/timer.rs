use super::{Fired, GRANULARITY, Recovery, Sent, Space};

impl Recovery {
    pub(super) fn arm(&mut self, now: u64) {
        self.timer = self.pick(now);
    }

    fn earliest(&self) -> Option<(u64, Space)> {
        let mut best: Option<(u64, Space)> = None;
        for space in Space::ALL {
            let Some(time) = self.lanes[space.slot()].loss else {
                continue;
            };
            if best.is_none_or(|(least, _)| time < least) {
                best = Some((time, space));
            }
        }
        best
    }

    fn pick(&self, now: u64) -> Option<u64> {
        if let Some((time, _)) = self.earliest() {
            return Some(time);
        }
        if self.blocked {
            return None;
        }
        if self.idle() && self.validated {
            return None;
        }
        self.probe(now).map(|(time, _)| time)
    }

    fn idle(&self) -> bool {
        self.lanes.iter().all(|lane| !lane.live())
    }

    fn base(&self) -> u64 {
        let spread = self.rtt.vary().saturating_mul(4).max(GRANULARITY);
        let span = self.rtt.smooth().saturating_add(spread);
        span.saturating_mul(1 << self.pto.min(40))
    }

    fn probe(&self, now: u64) -> Option<(u64, Space)> {
        let duration = self.base();
        if self.idle() {
            let space = if self.keys {
                Space::Handshake
            } else {
                Space::Initial
            };
            return Some((now.saturating_add(duration), space));
        }
        let mut best: Option<(u64, Space)> = None;
        for space in Space::ALL {
            let lane = &self.lanes[space.slot()];
            if !lane.live() {
                continue;
            }
            let mut length = duration;
            if space == Space::Data {
                if !self.confirmed {
                    return best;
                }
                let extra = self.delay.saturating_mul(1 << self.pto.min(40));
                length = length.saturating_add(extra);
            }
            let time = lane.last.unwrap_or(0).saturating_add(length);
            if best.is_none_or(|(least, _)| time < least) {
                best = Some((time, space));
            }
        }
        best
    }

    pub fn expire(&mut self, now: u64) -> Fired {
        if let Some((_, space)) = self.earliest() {
            let lost = self.detect(now, space);
            self.arm(now);
            return Fired::Lost(space, lost);
        }
        let fired = if self.idle() {
            Fired::Anti(self.probe(now).map_or(Space::Initial, |(_, space)| space))
        } else {
            Fired::Probe(self.probe(now).map_or(Space::Initial, |(_, space)| space))
        };
        self.pto = self.pto.saturating_add(1);
        self.arm(now);
        fired
    }

    pub fn discard(&mut self, now: u64, space: Space) -> Vec<Sent> {
        let lane = &mut self.lanes[space.slot()];
        let gone = lane.sent.values().filter(|p| p.flight).cloned().collect();
        lane.sent.clear();
        lane.last = None;
        lane.loss = None;
        self.pto = 0;
        self.arm(now);
        gone
    }
}
