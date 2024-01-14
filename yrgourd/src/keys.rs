use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use crrl::gls254::{Point, Scalar};
use rand_core::CryptoRngCore;

use crate::errors::{ParsePrivateKeyError, ParsePublicKeyError};

/// The GLS254 public key of a Yrgourd party.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    pub(crate) q: Point,
    pub(crate) encoded: [u8; PUBLIC_KEY_LEN],
}

/// The length of an encoded public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(encoded: &[u8]) -> Result<Self, Self::Error> {
        let encoded: [u8; PUBLIC_KEY_LEN] = encoded.try_into().map_err(|_| ())?;
        let q = Point::decode(&encoded).filter(|q| q.isneutral() == 0).ok_or(())?;
        Ok(PublicKey { q, encoded })
    }
}

impl From<Point> for PublicKey {
    fn from(q: Point) -> Self {
        Self { q, encoded: q.encode() }
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut encoded = [0u8; PUBLIC_KEY_LEN];
        hex::decode_to_slice(s, &mut encoded)?;
        PublicKey::try_from(<&[u8]>::from(&encoded))
            .map_err(|_| ParsePublicKeyError::InvalidPublicKey)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.encoded))
    }
}

impl std::hash::Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
    }
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // Compare public keys in constant time to avoid timing attacks on initiator restriction
        // policies.
        lockstitch::ct_eq(&self.encoded, &other.encoded)
    }
}

/// The GLS254 private key of a Yrgourd party.
#[derive(Clone)]
pub struct PrivateKey {
    pub(crate) d: Scalar,
    pub public_key: PublicKey,
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("d", &"[redacted]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl From<Scalar> for PrivateKey {
    fn from(d: Scalar) -> Self {
        Self { d, public_key: Point::mulgen(&d).into() }
    }
}

impl PrivateKey {
    /// Generates a random private key using the given RNG.
    pub fn random(mut rng: impl CryptoRngCore) -> PrivateKey {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        Scalar::decode_reduce(&buf).into()
    }
}

impl FromStr for PrivateKey {
    type Err = ParsePrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut encoded = [0u8; PUBLIC_KEY_LEN];
        hex::decode_to_slice(s, &mut encoded)?;

        Scalar::decode(&encoded)
            .filter(|d| d.equals(Scalar::ZERO) == 0)
            .map(Into::into)
            .ok_or(ParsePrivateKeyError::InvalidPrivateKey)
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.d.encode()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_public_key_from_str() {
        bolero::check!().with_type::<String>().for_each(|s| {
            if let Ok(pk) = PublicKey::from_str(s) {
                assert!(pk.q.isneutral() == 0);
            }
        });
    }

    #[test]
    fn fuzz_public_key_from_slice() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|b| {
            if let Ok(pk) = PublicKey::try_from(b.as_ref()) {
                assert!(pk.q.isneutral() == 0);
            }
        });
    }

    #[test]
    fn fuzz_private_key_from_str() {
        bolero::check!().with_type::<String>().for_each(|s| {
            if let Ok(pk) = PrivateKey::from_str(s) {
                assert!(pk.d.equals(Scalar::ZERO) == 0);
            }
        });
    }
}
