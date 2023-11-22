use thiserror::Error;

/// An error returned when parsing a public key was unsuccessful.
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum ParsePublicKeyError {
    /// Parsing failed because the value was not a valid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Parsing failed because the public key was not valid hex.
    #[error("invalid hex encoding")]
    InvalidEncoding(#[from] hex::FromHexError),
}

/// An error returned when parsing a private key was unsuccessful.
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum ParsePrivateKeyError {
    /// Parsing failed because the value was not a valid private key.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Parsing failed because the private key was not valid hex.
    #[error("invalid hex encoding")]
    InvalidEncoding(#[from] hex::FromHexError),
}
