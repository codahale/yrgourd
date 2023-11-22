use std::str::FromStr;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};

use crate::errors::{ParsePrivateKeyError, ParsePublicKeyError};

#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    pub(crate) q: RistrettoPoint,
    pub(crate) encoded: [u8; 32],
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

#[derive(Debug)]
pub struct PrivateKey {
    pub(crate) d: Scalar,
    pub public_key: PublicKey,
}

impl From<Scalar> for PrivateKey {
    fn from(d: Scalar) -> Self {
        let q = RistrettoPoint::mul_base(&d);
        Self { d, public_key: q.into() }
    }
}

impl PrivateKey {
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
