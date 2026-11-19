use super::Flaw;
use super::der::{GENERAL, UTC};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

fn leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn clock(hour: u32, minute: u32, second: u32) -> bool {
    hour < 24 && minute < 60 && second < 60
}

fn days(year: u32, month: u32) -> u32 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn number(content: &[u8], from: usize, count: usize) -> Result<u32, Flaw> {
    content[from..from + count]
        .iter()
        .try_fold(0u32, |acc, byte| {
            if byte.is_ascii_digit() {
                Ok(acc * 10 + u32::from(byte - b'0'))
            } else {
                Err(Flaw::Time)
            }
        })
}

impl Time {
    pub fn parse(tag: u8, content: &[u8]) -> Result<Self, Flaw> {
        let width = match tag {
            UTC => 2,
            GENERAL => 4,
            _ => return Err(Flaw::Tag),
        };
        if content.len() != width + 11 || content[width + 10] != b'Z' {
            return Err(Flaw::Time);
        }
        let raw = number(content, 0, width)?;
        let year = match (width, raw) {
            (2, 50..) => 1900 + raw,
            (2, _) => 2000 + raw,
            _ => raw,
        };
        let month = number(content, width, 2)?;
        let day = number(content, width + 2, 2)?;
        let hour = number(content, width + 4, 2)?;
        let minute = number(content, width + 6, 2)?;
        let second = number(content, width + 8, 2)?;
        let valid = (1..=12).contains(&month)
            && (1..=days(year, month)).contains(&day)
            && clock(hour, minute, second);
        if !valid {
            return Err(Flaw::Time);
        }
        Ok(Self {
            year: year as u16,
            month: month as u8,
            day: day as u8,
            hour: hour as u8,
            minute: minute as u8,
            second: second as u8,
        })
    }

    pub fn unix(&self) -> i64 {
        let month = i64::from(self.month);
        let year = i64::from(self.year) - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let cycle = year.rem_euclid(400);
        let shifted = (month + 9) % 12;
        let day = (153 * shifted + 2) / 5 + i64::from(self.day) - 1;
        let within = cycle * 365 + cycle / 4 - cycle / 100 + day;
        let days = era * 146_097 + within - 719_468;
        let clock = i64::from(self.hour) * 3600 + i64::from(self.minute) * 60;
        days * 86_400 + clock + i64::from(self.second)
    }
}
