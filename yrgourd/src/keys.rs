use std::fmt::{Debug, Display};
use std::str::FromStr;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::errors::{ParsePrivateKeyError, ParsePublicKeyError};

/// The Ristretto255 public key of a Yrgourd party.
#[derive(Debug, Clone, Copy, Eq)]
pub struct PublicKey {
    pub(crate) q: RistrettoPoint,
    pub(crate) encoded: [u8; 32],
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(encoded: &[u8]) -> Result<Self, Self::Error> {
        let encoded: [u8; 32] = encoded.try_into().map_err(|_| ())?;
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
        let mut encoded = [0u8; 32];
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
    /// Generate a random private key using the given RNG.
    pub fn random(mut rng: impl RngCore + CryptoRng) -> PrivateKey {
        Scalar::random(&mut rng).into()
    }
}

impl FromStr for PrivateKey {
    type Err = ParsePrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut encoded = [0u8; 32];
        hex::decode_to_slice(s, &mut encoded)?;

        let d: Option<Scalar> = Scalar::from_canonical_bytes(encoded).into();
        d.ok_or(ParsePrivateKeyError::InvalidPrivateKey).map(Into::into)
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.d.as_bytes()))
    }
}
