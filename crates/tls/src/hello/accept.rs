use crate::error::Error;
use crate::extension::{Place, Share, Typed};
use crate::hello::{Hello, Offer, Reply};
use crate::message::{Kind, Message};
use crate::schedule::{Schedule, Traffic};
use crypto::{Hash, Running};

pub struct Accepted {
    pub(super) reply: Reply,
    pub(super) digest: Running,
    pub(super) client: Traffic,
    pub(super) server: Traffic,
    pub(super) schedule: Schedule,
}

impl Accepted {
    pub fn reply(&self) -> &Reply {
        &self.reply
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.peek()
    }

    pub fn client(&self) -> &Traffic {
        &self.client
    }

    pub fn server(&self) -> &Traffic {
        &self.server
    }
}

fn hash(suite: u16) -> Result<Hash, Error> {
    match suite {
        0x1301 | 0x1303 => Ok(Hash::Sha256),
        0x1302 => Ok(Hash::Sha384),
        _ => Err(Error::Suites),
    }
}

fn spoken(reply: &Reply) -> Result<Vec<u8>, Error> {
    Message {
        kind: Kind::Reply,
        body: reply.write()?,
    }
    .write()
}

struct Found {
    share: Option<Share>,
    group: Option<u16>,
    cookie: Option<Vec<u8>>,
}

fn only<T>(slot: Option<T>, value: T) -> Result<Option<T>, Error> {
    if slot.is_some() {
        return Err(Error::Duplicate);
    }
    Ok(Some(value))
}

fn selected(offer: &Offer, reply: &Reply, place: Place) -> Result<Found, Error> {
    if !offer.suites.contains(&reply.suite) {
        return Err(Error::Suites);
    }
    if reply.session != offer.session {
        return Err(Error::Value);
    }
    let mut version = None;
    let mut found = Found {
        share: None,
        group: None,
        cookie: None,
    };
    for extension in &reply.extensions {
        let Some(typed) = Typed::parse(extension, place)? else {
            continue;
        };
        match typed {
            Typed::Version(value) => version = only(version, value)?,
            Typed::Chosen(share) => found.share = only(found.share, share)?,
            Typed::Group(group) => found.group = only(found.group, group)?,
            Typed::Cookie(cookie) => found.cookie = only(found.cookie, cookie)?,
            _ => return Err(Error::Value),
        }
    }
    if version != Some(0x0304) {
        return Err(Error::Version);
    }
    match place {
        Place::Reply => {
            if found.group.is_some() || found.cookie.is_some() {
                return Err(Error::Place);
            }
            if found.share.is_none() {
                return Err(Error::Missing);
            }
            Ok(found)
        }
        Place::Retry => {
            if found.share.is_some() {
                return Err(Error::Place);
            }
            if found.group.is_none() {
                return Err(Error::Missing);
            }
            Ok(found)
        }
        _ => Err(Error::Place),
    }
}

fn absorbed(hello: &Hello, reply: &Reply, hash: Hash) -> Result<Running, Error> {
    let spoken = spoken(reply)?;
    if hello.digest.hash() == hash {
        let mut digest = hello.digest.clone();
        digest.update(&spoken);
        return Ok(digest);
    }
    if hello.digest.peek() == hello.digest.hash().digest(hello.spoken()) {
        let mut digest = Running::new(hash);
        digest.update(hello.spoken());
        digest.update(&spoken);
        return Ok(digest);
    }
    Err(Error::Suites)
}

impl Hello {
    pub fn accept(&self, reply: &Reply, shared: &[u8]) -> Result<Accepted, Error> {
        if reply.retry() {
            return Err(Error::Value);
        }
        let chosen = selected(self.offer(), reply, Place::Reply)?
            .share
            .ok_or(Error::Missing)?;
        let mut offered = None;
        for item in &self.offer().extensions {
            if let Some(Typed::Shares(items)) = Typed::parse(item, Place::Offer)? {
                offered = only(offered, items)?;
            }
        }
        let offered = offered.ok_or(Error::Missing)?;
        if !offered.iter().any(|item| item.group == chosen.group) {
            return Err(Error::Value);
        }
        let hash = hash(reply.suite)?;
        let digest = absorbed(self, reply, hash)?;
        let schedule = Schedule::new(hash, shared)?;
        let transcript = digest.peek();
        Ok(Accepted {
            reply: reply.clone(),
            client: schedule.client(&transcript)?,
            server: schedule.server(&transcript)?,
            digest,
            schedule,
        })
    }

    pub fn retry(&self, reply: &Reply, share: Share) -> Result<Self, Error> {
        if !reply.retry() {
            return Err(Error::Value);
        }
        let found = selected(self.offer(), reply, Place::Retry)?;
        let group = found.group.ok_or(Error::Missing)?;
        if share.group != group {
            return Err(Error::Value);
        }
        let cookie = found.cookie;
        let mut extensions = Vec::new();
        for item in &self.offer().extensions {
            match Typed::parse(item, Place::Offer)? {
                Some(Typed::Shares(_)) => {
                    extensions.push(Typed::Shares(vec![share.clone()]).write()?);
                }
                Some(Typed::Cookie(_)) => {}
                Some(typed) => extensions.push(typed.write()?),
                None => extensions.push(item.clone()),
            }
        }
        if let Some(cookie) = cookie {
            extensions.push(Typed::Cookie(cookie).write()?);
        }
        let offer = Offer {
            random: self.offer().random,
            session: self.offer().session.clone(),
            suites: self.offer().suites.clone(),
            extensions,
        };
        let spoken = Message {
            kind: Kind::Offer,
            body: offer.write()?,
        }
        .write()?;
        let hash = hash(reply.suite)?;
        let mut digest = Running::new(hash);
        digest.update(
            &Message {
                kind: Kind::Hash,
                body: hash.digest(self.spoken()),
            }
            .write()?,
        );
        digest.update(&self::spoken(reply)?);
        digest.update(&spoken);
        Ok(Self {
            offer,
            spoken,
            digest,
        })
    }
}
