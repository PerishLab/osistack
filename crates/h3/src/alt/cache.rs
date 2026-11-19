use super::{Alternative, Defect, Directive, Origin};

const MICROS: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct Cache {
    limit: usize,
    held: Vec<(Origin, Vec<(Alternative, u64)>)>,
}

impl Cache {
    pub fn new(limit: usize) -> Cache {
        Cache {
            limit,
            held: Vec::new(),
        }
    }

    pub fn store(&mut self, origin: &Origin, directive: Directive, now: u64) {
        self.held.retain(|(seen, _)| seen != origin);
        let Directive::Offer(list) = directive else {
            return;
        };
        if list.is_empty() || self.limit == 0 {
            return;
        }
        if self.held.len() >= self.limit {
            self.held.remove(0);
        }
        let kept = list
            .into_iter()
            .map(|alt| {
                let due = now.saturating_add(alt.age.saturating_mul(MICROS));
                (alt, due)
            })
            .collect();
        self.held.push((origin.clone(), kept));
    }

    pub fn receive(&mut self, origin: &Origin, text: &str, now: u64) -> Result<(), Defect> {
        let directive = Directive::parse(text, origin)?;
        self.store(origin, directive, now);
        Ok(())
    }

    pub fn fresh(&self, origin: &Origin, now: u64) -> Vec<&Alternative> {
        let Some((_, list)) = self.held.iter().find(|(seen, _)| seen == origin) else {
            return Vec::new();
        };
        list.iter()
            .filter(|(_, due)| now < *due)
            .map(|(alt, _)| alt)
            .collect()
    }

    pub fn best(&self, origin: &Origin, now: u64) -> Option<&Alternative> {
        self.fresh(origin, now)
            .into_iter()
            .find(|alt| alt.protocol == b"h3")
    }

    pub fn purge(&mut self, now: u64) {
        for (_, list) in &mut self.held {
            list.retain(|(_, due)| now < *due);
        }
        self.held.retain(|(_, list)| !list.is_empty());
    }

    pub fn change(&mut self) {
        for (_, list) in &mut self.held {
            list.retain(|(alt, _)| alt.persist);
        }
        self.held.retain(|(_, list)| !list.is_empty());
    }

    pub fn count(&self) -> usize {
        self.held.len()
    }
}
