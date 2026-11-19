#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Flow,
    Limit,
    State,
    Final,
}

impl Fault {
    pub fn code(self) -> u64 {
        match self {
            Fault::Flow => 0x3,
            Fault::Limit => 0x4,
            Fault::State => 0x5,
            Fault::Final => 0x6,
        }
    }
}
