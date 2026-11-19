use h2::{Dependency, Frame};

pub struct Stream(pub u32);

impl Stream {
    pub fn headers(&self, fin: bool) -> Frame {
        Frame::Headers {
            stream: self.0,
            fin,
            complete: true,
            pad: None,
            priority: None,
            block: Vec::new(),
        }
    }

    pub fn data(&self, fin: bool) -> Frame {
        Frame::Data {
            stream: self.0,
            fin,
            pad: None,
            data: vec![1],
        }
    }

    pub fn reset(&self) -> Frame {
        Frame::Reset {
            stream: self.0,
            code: 8,
        }
    }

    pub fn window(&self) -> Frame {
        Frame::Window {
            stream: self.0,
            increment: 1,
        }
    }

    pub fn priority(&self) -> Frame {
        let dependency = Dependency {
            exclusive: false,
            stream: 0,
            weight: 15,
        };
        Frame::Priority {
            stream: self.0,
            dependency,
        }
    }

    pub fn more(&self) -> Frame {
        Frame::Continuation {
            stream: self.0,
            complete: true,
            block: Vec::new(),
        }
    }
}
