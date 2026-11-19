#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Clean,
    General,
    Internal,
    Creation,
    Critical,
    Unexpected,
    Frame,
    Load,
    Id,
    Setting,
    Missing,
    Rejected,
    Cancelled,
    Incomplete,
    Message,
    Connect,
    Version,
    Decompress,
    Encode,
    Decode,
}

const CODES: [Code; 20] = [
    Code::Clean,
    Code::General,
    Code::Internal,
    Code::Creation,
    Code::Critical,
    Code::Unexpected,
    Code::Frame,
    Code::Load,
    Code::Id,
    Code::Setting,
    Code::Missing,
    Code::Rejected,
    Code::Cancelled,
    Code::Incomplete,
    Code::Message,
    Code::Connect,
    Code::Version,
    Code::Decompress,
    Code::Encode,
    Code::Decode,
];

impl Code {
    pub fn get(self) -> u64 {
        match self {
            Code::Clean => 0x100,
            Code::General => 0x101,
            Code::Internal => 0x102,
            Code::Creation => 0x103,
            Code::Critical => 0x104,
            Code::Unexpected => 0x105,
            Code::Frame => 0x106,
            Code::Load => 0x107,
            Code::Id => 0x108,
            Code::Setting => 0x109,
            Code::Missing => 0x10a,
            Code::Rejected => 0x10b,
            Code::Cancelled => 0x10c,
            Code::Incomplete => 0x10d,
            Code::Message => 0x10e,
            Code::Connect => 0x10f,
            Code::Version => 0x110,
            Code::Decompress => 0x200,
            Code::Encode => 0x201,
            Code::Decode => 0x202,
        }
    }

    pub fn of(value: u64) -> Option<Self> {
        CODES.iter().copied().find(|code| code.get() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Connection { code: Code },
    Stream { code: Code },
}

impl Fault {
    pub fn code(self) -> Code {
        match self {
            Fault::Connection { code } | Fault::Stream { code } => code,
        }
    }
}
