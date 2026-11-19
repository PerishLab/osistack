use super::{Identity, Place, Share, Typed};
use crate::error::Error;
use crate::field::Scan;

pub struct Read<'a> {
    scan: Scan<'a>,
    place: Place,
}

impl<'a> Read<'a> {
    pub fn new(data: &'a [u8], place: Place) -> Self {
        Self {
            scan: Scan::new(data),
            place,
        }
    }

    pub fn typed(mut self, kind: u16) -> Result<Typed, Error> {
        let found = match kind {
            0 => self.name()?,
            10 => Typed::Groups(self.shorts()?),
            13 => Typed::Algorithms(self.shorts()?),
            16 => Typed::Protocols(self.protocols()?),
            41 => self.preshared()?,
            42 => self.early()?,
            43 => self.versions()?,
            44 => Typed::Cookie(self.wrapped(2)?),
            45 => Typed::Modes(self.wrapped(1)?),
            _ => self.keys()?,
        };
        self.scan.end()?;
        Ok(found)
    }

    fn name(&mut self) -> Result<Typed, Error> {
        if self.place == Place::Encrypted {
            return self.nothing().map(|_| Typed::Name(None));
        }
        let mut list = Scan::new(self.scan.prefixed(2)?);
        let mut host = None;
        while list.left() > 0 || host.is_none() {
            if list.byte().map_err(Error::inner)? != 0 {
                return Err(Error::Value);
            }
            let name = list.prefixed(2).map_err(Error::inner)?;
            if name.is_empty() {
                return Err(Error::Length);
            }
            if host.replace(name.to_vec()).is_some() {
                return Err(Error::Duplicate);
            }
        }
        Ok(Typed::Name(host))
    }

    fn nothing(&mut self) -> Result<(), Error> {
        if self.scan.left() > 0 {
            return Err(Error::Length);
        }
        Ok(())
    }

    fn shorts(&mut self) -> Result<Vec<u16>, Error> {
        let list = self.scan.prefixed(2)?;
        Self::pairs(list)
    }

    fn pairs(list: &[u8]) -> Result<Vec<u16>, Error> {
        if list.is_empty() || !list.len().is_multiple_of(2) {
            return Err(Error::Length);
        }
        Ok(list
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect())
    }

    fn protocols(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut list = Scan::new(self.scan.prefixed(2)?);
        let mut names = Vec::new();
        while list.left() > 0 || names.is_empty() {
            let name = list.prefixed(1).map_err(Error::inner)?;
            if name.is_empty() {
                return Err(Error::Length);
            }
            names.push(name.to_vec());
        }
        if self.place == Place::Encrypted && names.len() != 1 {
            return Err(Error::Value);
        }
        Ok(names)
    }

    fn wrapped(&mut self, width: usize) -> Result<Vec<u8>, Error> {
        let bytes = self.scan.prefixed(width)?;
        if bytes.is_empty() {
            return Err(Error::Length);
        }
        Ok(bytes.to_vec())
    }

    fn preshared(&mut self) -> Result<Typed, Error> {
        if self.place == Place::Reply {
            return Ok(Typed::Selected(self.scan.short()?));
        }
        let identities = self.scan.prefixed(2)?;
        let binders = self.scan.prefixed(2)?;
        if identities.len() < 7 || binders.len() < 33 {
            return Err(Error::Length);
        }
        let identities = Self::identities(identities)?;
        let binders = Self::binders(binders)?;
        if identities.len() != binders.len() {
            return Err(Error::Value);
        }
        Ok(Typed::Offered {
            identities,
            binders,
        })
    }

    fn identities(list: &[u8]) -> Result<Vec<Identity>, Error> {
        let mut scan = Scan::new(list);
        let mut found = Vec::new();
        while scan.left() > 0 {
            let label = scan.prefixed(2).map_err(Error::inner)?;
            let age = scan.long().map_err(Error::inner)?;
            if label.is_empty() {
                return Err(Error::Length);
            }
            found.push(Identity {
                label: label.to_vec(),
                age,
            });
        }
        Ok(found)
    }

    fn binders(list: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let mut scan = Scan::new(list);
        let mut found = Vec::new();
        while scan.left() > 0 {
            let binder = scan.prefixed(1).map_err(Error::inner)?;
            if binder.len() < 32 {
                return Err(Error::Length);
            }
            found.push(binder.to_vec());
        }
        Ok(found)
    }

    fn early(&mut self) -> Result<Typed, Error> {
        if self.place == Place::Ticket {
            return Ok(Typed::Early(Some(self.scan.long()?)));
        }
        self.nothing().map(|_| Typed::Early(None))
    }

    fn versions(&mut self) -> Result<Typed, Error> {
        if self.place != Place::Offer {
            return Ok(Typed::Version(self.scan.short()?));
        }
        let list = self.scan.prefixed(1)?;
        Self::pairs(list).map(Typed::Versions)
    }

    fn keys(&mut self) -> Result<Typed, Error> {
        match self.place {
            Place::Reply => Ok(Typed::Chosen(Self::share(&mut self.scan)?)),
            Place::Retry => Ok(Typed::Group(self.scan.short()?)),
            _ => self.shares(),
        }
    }

    fn shares(&mut self) -> Result<Typed, Error> {
        let mut list = Scan::new(self.scan.prefixed(2)?);
        let mut found: Vec<Share> = Vec::new();
        while list.left() > 0 {
            let share = Self::share(&mut list).map_err(Error::inner)?;
            if found.iter().any(|seen| seen.group == share.group) {
                return Err(Error::Duplicate);
            }
            found.push(share);
        }
        Ok(Typed::Shares(found))
    }

    fn share(scan: &mut Scan) -> Result<Share, Error> {
        let group = scan.short()?;
        let key = scan.prefixed(2)?;
        if key.is_empty() {
            return Err(Error::Length);
        }
        Ok(Share {
            group,
            key: key.to_vec(),
        })
    }
}
