use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use ml_kem::{EncodedSizeUser as _, KemCore as _};
use rand_core::CryptoRngCore;

use crate::errors::{ParsePrivateKeyError, ParsePublicKeyError};

/// The length of an encoded public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 1184 + 32;

/// The length of an encoded private key in bytes.
pub const PRIVATE_KEY_LEN: usize = PUBLIC_KEY_LEN + 2400 + 32;

/// The public key of a Yrgourd party.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The ML-KEM-768 encrypting key.
    pub ek_pq: ml_kem::kem::EncapsulationKey<ml_kem::MlKem768Params>,

    /// The X25519 encrypting key.
    pub ek_c: x25519_dalek::PublicKey,

    pub(crate) encoded: [u8; PUBLIC_KEY_LEN],
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(encoded: &[u8]) -> Result<Self, Self::Error> {
        let encoded: [u8; PUBLIC_KEY_LEN] = encoded.try_into().map_err(|_| ())?;
        let (ek_pq, ek_c) = encoded.split_at(1184);
        let ek_pq = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &ek_pq.try_into().map_err(|_| ())?,
        );
        let ek_c = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ek_c).map_err(|_| ())?);
        Ok(PublicKey { ek_pq, ek_c, encoded })
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

/// The private key of a Yrgourd party.
#[derive(Clone)]
pub struct PrivateKey {
    /// The ML-KEM decrypting key.
    pub(crate) dk_pq: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,

    /// The X25519 decrypting key.
    pub(crate) dk_c: x25519_dalek::StaticSecret,

    pub public_key: PublicKey,

    pub(crate) encoded: [u8; PRIVATE_KEY_LEN],
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("dk_pq", &"[redacted]")
            .field("dk_c", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("encoded", &"[redacted]")
            .finish()
    }
}

impl PrivateKey {
    /// Generates a random private key using the given RNG.
    pub fn random(mut rng: impl CryptoRngCore) -> PrivateKey {
        let (dk_pq, ek_pq) = ml_kem::kem::Kem::<ml_kem::MlKem768Params>::generate(&mut rng);
        let dk_c = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let ek_c = x25519_dalek::PublicKey::from(&dk_c);

        let mut pub_encoded = Vec::with_capacity(PUBLIC_KEY_LEN);
        pub_encoded.extend_from_slice(&ek_pq.as_bytes());
        pub_encoded.extend_from_slice(ek_c.as_bytes());

        let mut priv_encoded = Vec::with_capacity(PRIVATE_KEY_LEN);
        priv_encoded.extend_from_slice(&pub_encoded);
        priv_encoded.extend_from_slice(&dk_pq.as_bytes());
        priv_encoded.extend_from_slice(dk_c.as_bytes());

        PrivateKey {
            dk_pq,
            dk_c,
            public_key: PublicKey {
                ek_pq,
                ek_c,
                encoded: pub_encoded.try_into().expect("should be public key sized"),
            },
            encoded: priv_encoded.try_into().expect("should be private key sized"),
        }
    }
}

impl FromStr for PrivateKey {
    type Err = ParsePrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut encoded = [0u8; PRIVATE_KEY_LEN];
        hex::decode_to_slice(s, &mut encoded)?;

        let (pub_key, dk_pq) = encoded.split_at(PUBLIC_KEY_LEN);
        let (dk_pq, dk_c) = dk_pq.split_at(2400);

        let public_key =
            PublicKey::try_from(pub_key).map_err(|_| ParsePrivateKeyError::InvalidPrivateKey)?;
        let dk_pq = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &dk_pq.try_into().expect("should be ML-KEM-786 private key sized"),
        );
        let dk_c = x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(dk_c).expect("should be X25519 private key sized"),
        );
        Ok(PrivateKey { dk_pq, dk_c, public_key, encoded })
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.encoded))
    }
}
