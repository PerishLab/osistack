#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Empty,
    Character,
    Padding,
    Range,
    Scheme,
    Userinfo,
    Host,
    Port,
    Order,
    Duplicate,
    Pseudo,
    Target,
}
