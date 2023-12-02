use std::fmt::{Debug, Display};
use std::str::FromStr;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::CryptoRngCore;

use crate::errors::{ParsePrivateKeyError, ParsePublicKeyError};

/// The Ristretto255 public key of a Yrgourd party.
#[derive(Debug, Clone, Copy, Eq)]
pub struct PublicKey {
    pub(crate) q: RistrettoPoint,
    pub(crate) encoded: [u8; PUBLIC_KEY_LEN],
}

/// The length of an encoded public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(encoded: &[u8]) -> Result<Self, Self::Error> {
        let encoded: [u8; PUBLIC_KEY_LEN] = encoded.try_into().map_err(|_| ())?;
        let q = CompressedRistretto::from_slice(&encoded).map_err(|_| ())?.decompress().ok_or(())?;
        Ok(PublicKey { q, encoded })
    }
}

impl From<RistrettoPoint> for PublicKey {
    fn from(q: RistrettoPoint) -> Self {
        Self { q, encoded: q.compress().to_bytes() }
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut encoded = [0u8; PUBLIC_KEY_LEN];
        hex::decode_to_slice(s, &mut encoded)?;

        CompressedRistretto::from_slice(&encoded)
            .expect("should be 32 bytes")
            .decompress()
            .map(Into::into)
            .ok_or(ParsePublicKeyError::InvalidPublicKey)
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

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // Compare public keys in constant time to avoid timing attacks on initiator restriction
        // policies.
        lockstitch::ct_eq(&self.encoded, &other.encoded)
    }
}

/// The Ristretto255 private key of a Yrgourd party.
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
        Self { d, public_key: RistrettoPoint::mul_base(&d).into() }
    }
}

impl PrivateKey {
    /// Generates a random private key using the given RNG.
    pub fn random(mut rng: impl CryptoRngCore) -> PrivateKey {
        Scalar::random(&mut rng).into()
    }
}

impl FromStr for PrivateKey {
    type Err = ParsePrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut encoded = [0u8; PUBLIC_KEY_LEN];
        hex::decode_to_slice(s, &mut encoded)?;

        Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded))
            .filter(|d| d != &Scalar::ZERO)
            .ok_or(ParsePrivateKeyError::InvalidPrivateKey)
            .map(Into::into)
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.d.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::traits::IsIdentity;

    use super::*;

    #[test]
    fn fuzz_public_key_from_str() {
        bolero::check!().with_type::<String>().for_each(|s| {
            if let Ok(pk) = PublicKey::from_str(s) {
                assert!(!pk.q.is_identity());
            }
        });
    }

    #[test]
    fn fuzz_public_key_from_slice() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|b| {
            if let Ok(pk) = PublicKey::try_from(b.as_ref()) {
                assert!(!pk.q.is_identity());
            }
        });
    }

    #[test]
    fn fuzz_private_key_from_str() {
        bolero::check!().with_type::<String>().for_each(|s| {
            if let Ok(pk) = PrivateKey::from_str(s) {
                assert_ne!(pk.d, Scalar::ZERO);
            }
        });
    }
}
