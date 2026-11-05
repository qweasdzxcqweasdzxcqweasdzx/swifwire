use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct EphemeralKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(self.secret.diffie_hellman(their_public).to_bytes())
    }
}

#[derive(Clone)]
pub struct StaticKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl StaticKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(self.secret.diffie_hellman(their_public).to_bytes())
    }
}

#[derive(Zeroize)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn public_from_bytes(b: [u8; 32]) -> PublicKey {
    PublicKey::from(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_agrees() {
        let a = EphemeralKeypair::generate();
        let b = EphemeralKeypair::generate();
        let ab = a.diffie_hellman(&b.public);
        let ba = b.diffie_hellman(&a.public);
        assert_eq!(ab.0, ba.0);
    }
}
