use crate::fault::{Code, Fault};
use wire::{Reader, Varint, Writer};

const FRAME: Fault = Fault::Connection { code: Code::Frame };
const SETTING: Fault = Fault::Connection {
    code: Code::Setting,
};
const INTERNAL: Fault = Fault::Connection {
    code: Code::Internal,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    pub capacity: u64,
    pub size: Option<u64>,
    pub blocked: u64,
}

impl Settings {
    pub fn read(payload: &[u8]) -> Result<Self, Fault> {
        let mut reader = Reader::new(payload);
        let mut settings = Self::default();
        let mut seen: Vec<u64> = Vec::new();
        while reader.left() > 0 {
            let id = reader.varint().map_err(|_| FRAME)?.get();
            let value = reader.varint().map_err(|_| FRAME)?.get();
            if seen.contains(&id) || matches!(id, 0x0 | 0x2..=0x5) {
                return Err(SETTING);
            }
            seen.push(id);
            match id {
                0x1 => settings.capacity = value,
                0x6 => settings.size = Some(value),
                0x7 => settings.blocked = value,
                _ => {}
            }
        }
        Ok(settings)
    }

    pub fn write(&self) -> Result<Vec<u8>, Fault> {
        let base = Self::default();
        let entries = [
            (0x1, Some(self.capacity), self.capacity != base.capacity),
            (0x6, self.size, self.size != base.size),
            (0x7, Some(self.blocked), self.blocked != base.blocked),
        ];
        let mut writer = Writer::new();
        for (id, value, shown) in entries {
            let Some(value) = value.filter(|_| shown) else {
                continue;
            };
            let value = Varint::new(value).map_err(|_| INTERNAL)?;
            writer.varint(Varint::new(id).map_err(|_| INTERNAL)?);
            writer.varint(value);
        }
        Ok(writer.finish())
    }
}
