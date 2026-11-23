use crate::catalog;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Wire,
    Semantics,
    Http1,
    Tls,
    Http2,
    Quic,
    Http3,
    Crypto,
    Cli,
    Scope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Supported,
    Excluded,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub area: Area,
    pub name: &'static str,
    pub state: State,
}

impl Capability {
    pub fn new(area: Area, name: &'static str, state: State) -> Self {
        Self { area, name, state }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub capabilities: Vec<Capability>,
}

impl Profile {
    pub fn current() -> Self {
        Self {
            capabilities: catalog::table(),
        }
    }

    pub fn state(&self, area: Area, name: &str) -> Option<State> {
        self.capabilities
            .iter()
            .find(|c| c.area == area && c.name == name)
            .map(|c| c.state)
    }

    pub fn count(&self, state: State) -> usize {
        self.capabilities
            .iter()
            .filter(|c| c.state == state)
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Capabilities,
    Fetch,
    Serve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Help {
    pub operation: Operation,
    pub availability: Availability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Unavailable(Operation),
}

pub fn dispatch(operation: Operation) -> Result<Profile, Refusal> {
    match operation {
        Operation::Capabilities => Ok(Profile::current()),
        Operation::Fetch | Operation::Serve => Err(Refusal::Unavailable(operation)),
    }
}

pub fn help() -> Vec<Help> {
    [Operation::Capabilities, Operation::Fetch, Operation::Serve]
        .into_iter()
        .map(|operation| Help {
            operation,
            availability: match operation {
                Operation::Capabilities | Operation::Fetch => Availability::Available,
                Operation::Serve => Availability::Unavailable,
            },
        })
        .collect()
}
