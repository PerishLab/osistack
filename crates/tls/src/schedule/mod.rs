mod master;
mod stage;
mod traffic;

use crate::error::Error;
use crypto::{Hash, Secret};

pub use master::Master;
pub use stage::Schedule;
pub use traffic::{Keys, Traffic};

fn derive(secret: &Secret, hash: Hash, label: &[u8], transcript: &[u8]) -> Result<Vec<u8>, Error> {
    if transcript.len() != hash.size() {
        return Err(Error::Length);
    }
    Ok(secret.label(label, transcript, hash.size())?)
}
