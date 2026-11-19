use crate::frame::{MASK, Setting};
use crate::stream::{Code, Fault};

const LEAST: u32 = 16_384;
const MOST: u32 = 0xff_ffff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub table: u32,
    pub push: bool,
    pub streams: Option<u32>,
    pub window: u32,
    pub frame: u32,
    pub header: Option<u32>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            table: 4096,
            push: true,
            streams: None,
            window: 65_535,
            frame: LEAST,
            header: None,
        }
    }
}

impl Settings {
    pub fn apply(&mut self, list: &[Setting]) -> Result<(), Fault> {
        let mut next = self.clone();
        for setting in list {
            next.set(*setting)?;
        }
        *self = next;
        Ok(())
    }

    pub fn list(&self) -> Vec<Setting> {
        let base = Self::default();
        let entries = [
            (1, self.table, self.table != base.table),
            (2, u32::from(self.push), self.push != base.push),
            (3, self.streams.unwrap_or(0), self.streams != base.streams),
            (4, self.window, self.window != base.window),
            (5, self.frame, self.frame != base.frame),
            (6, self.header.unwrap_or(0), self.header != base.header),
        ];
        let shown = entries.iter().filter(|entry| entry.2);
        shown
            .map(|(id, value, _)| Setting {
                id: *id,
                value: *value,
            })
            .collect()
    }

    fn set(&mut self, setting: Setting) -> Result<(), Fault> {
        let value = setting.value;
        let protocol = Fault::Connection {
            code: Code::Protocol,
        };
        match setting.id {
            1 => self.table = value,
            2 if value == 0 => self.push = false,
            2 => return Err(protocol),
            3 => self.streams = Some(value),
            4 if value <= MASK => self.window = value,
            4 => return Err(Fault::Connection { code: Code::Flow }),
            5 if (LEAST..=MOST).contains(&value) => self.frame = value,
            5 => return Err(protocol),
            6 => self.header = Some(value),
            _ => {}
        }
        Ok(())
    }
}
