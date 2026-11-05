//! Ed25519 for mask-pack signatures (control plane).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct PackSigningKey(SigningKey);

#[derive(Clone)]
pub struct PackVerifyingKey(VerifyingKey);

impl PackSigningKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verifying_key(&self) -> PackVerifyingKey {
        PackVerifyingKey(self.0.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl PackVerifyingKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| Error::Signature)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let signature = Signature::from_bytes(sig);
        self.0.verify(msg, &signature).map_err(|_| Error::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let sk = PackSigningKey::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"pack-body");
        vk.verify(b"pack-body", &sig).unwrap();
        assert!(vk.verify(b"tampered", &sig).is_err());
    }
}
