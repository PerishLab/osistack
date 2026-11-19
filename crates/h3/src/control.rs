use crate::fault::{Code, Fault};
use crate::frame::{Frame, Framer};
use crate::settings::Settings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Settings(Settings),
    Goaway(u64),
}

#[derive(Debug, Clone)]
pub struct Control {
    framer: Framer,
    settings: Option<Settings>,
    goaway: Option<u64>,
}

fn fault(code: Code) -> Fault {
    Fault::Connection { code }
}

impl Control {
    pub fn new(limit: usize) -> Self {
        Self {
            framer: Framer::new(limit),
            settings: None,
            goaway: None,
        }
    }

    pub fn open(settings: &Settings) -> Result<Vec<u8>, Fault> {
        let mut bytes = vec![0x00];
        bytes.extend(Frame::Settings(settings.clone()).encode()?);
        Ok(bytes)
    }

    pub fn settings(&self) -> Option<&Settings> {
        self.settings.as_ref()
    }

    pub fn end(&self) -> Fault {
        fault(Code::Critical)
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Notice>, Fault> {
        let mut notices = Vec::new();
        for frame in self.framer.feed(bytes)? {
            notices.extend(self.accept(frame)?);
        }
        Ok(notices)
    }

    fn accept(&mut self, frame: Frame) -> Result<Option<Notice>, Fault> {
        match (self.settings.is_some(), frame) {
            (false, Frame::Settings(settings)) => {
                self.settings = Some(settings.clone());
                Ok(Some(Notice::Settings(settings)))
            }
            (false, _) => Err(fault(Code::Missing)),
            (true, Frame::Cancel(_)) => Err(fault(Code::Id)),
            (true, Frame::Goaway(id)) => self.farewell(id),
            (true, Frame::Unknown { .. }) => Ok(None),
            (true, _) => Err(fault(Code::Unexpected)),
        }
    }

    fn farewell(&mut self, id: u64) -> Result<Option<Notice>, Fault> {
        let raised = self.goaway.is_some_and(|before| id > before);
        if !id.is_multiple_of(4) || raised {
            return Err(fault(Code::Id));
        }
        self.goaway = Some(id);
        Ok(Some(Notice::Goaway(id)))
    }
}
