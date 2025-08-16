use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};

use crate::{Error, Result, crypto::Signature};

pub struct Identity {
    pub_key: VerifyingKey,
}

impl Identity {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Identity> {
        let pub_key = VerifyingKey::from_bytes(bytes).map_err(|_| Error::ParseError)?;
        Ok(Self { pub_key })
    }
}

impl Identity {
    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        let sig = Ed25519Signature::from_bytes(&sig.0);
        self.pub_key.verify_strict(message, &sig).is_ok()
    }
}
