use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use fips203::{
    ml_kem_768::{self, KG},
    traits::{KeyGen, SerDes},
};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use crate::errors::{ParsePrivateKeyError, ParsePublicKeyError};

/// The length of an encoded public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 1184;

/// The length of an encoded private key in bytes.
pub const PRIVATE_KEY_LEN: usize = 32 + 32;

/// The public key of a Yrgourd party.
#[derive(Clone)]
pub struct PublicKey {
    /// The ML-KEM-768 encrypting key.
    pub(crate) ek: ml_kem_768::EncapsKey,

    pub(crate) encoded: [u8; PUBLIC_KEY_LEN],
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey").field("encoded", &self.encoded).finish_non_exhaustive()
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = ();

    fn try_from(encoded: &[u8]) -> Result<Self, Self::Error> {
        let encoded: [u8; PUBLIC_KEY_LEN] = encoded.try_into().map_err(|_| ())?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(encoded).map_err(|_| ())?;
        Ok(PublicKey { ek, encoded })
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
        self.encoded.ct_eq(&other.encoded).into()
    }
}

/// The private key of a Yrgourd party.
#[derive(Clone)]
pub struct PrivateKey {
    /// The ML-KEM decrypting key.
    pub(crate) dk: ml_kem_768::DecapsKey,

    pub public_key: PublicKey,

    pub(crate) encoded: [u8; PRIVATE_KEY_LEN],
}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey").field("public_key", &self.public_key).finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// Generates a random private key using the given RNG.
    pub fn random(mut rng: impl CryptoRngCore) -> PrivateKey {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rng.fill_bytes(&mut d);
        rng.fill_bytes(&mut z);
        let (ek, dk) = KG::keygen_from_seed(d, z);

        let public_key = PublicKey { ek: ek.clone(), encoded: ek.into_bytes() };

        let mut encoded = [0u8; PRIVATE_KEY_LEN];
        let (encoded_d, encoded_z) = encoded.split_at_mut(32);
        encoded_d.copy_from_slice(&d);
        encoded_z.copy_from_slice(&z);

        PrivateKey { dk, public_key, encoded }
    }
}

impl FromStr for PrivateKey {
    type Err = ParsePrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut encoded = [0u8; PRIVATE_KEY_LEN];
        hex::decode_to_slice(s, &mut encoded)?;

        let (d, z) = encoded.split_at(32);
        let (ek, dk) = KG::keygen_from_seed(
            d.try_into().expect("should be 32 bytes"),
            z.try_into().expect("should bee 32 bytes"),
        );

        let public_key = PublicKey { ek: ek.clone(), encoded: ek.into_bytes() };
        Ok(PrivateKey { dk, public_key, encoded })
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.encoded))
    }
}
