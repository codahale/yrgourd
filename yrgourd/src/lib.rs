use std::collections::HashSet;
use std::time::Duration;

use rand_core::{CryptoRng, RngCore};
use tokio::io::{self, AsyncRead, AsyncWrite};

pub use crate::errors::*;
pub use crate::keys::*;
pub use crate::transport::Transport;

mod codec;
mod errors;
mod handshake;
mod keys;
mod transport;

/// Yrgourd provides mutually-authenticated, confidential connections with forward secrecy.
#[derive(Debug)]
pub struct Yrgourd<R> {
    private_key: PrivateKey,
    rng: R,
    allowed_initiators: Option<HashSet<PublicKey>>,
    max_ratchet_time: Duration,
    max_ratchet_bytes: u64,
}

impl<R> Yrgourd<R>
where
    R: RngCore + CryptoRng + Clone,
{
    /// Create a new Yrgourd with the given private key and RNG.
    pub fn new(private_key: PrivateKey, rng: R) -> Yrgourd<R> {
        Yrgourd {
            private_key,
            rng,
            allowed_initiators: None,
            max_ratchet_time: Duration::from_secs(120),
            max_ratchet_bytes: 100 * 1024 * 1024,
        }
    }

    /// When accepting handshakes, allow all initiators. Default.
    pub fn allow_all_initiators(mut self) -> Self {
        self.allowed_initiators = None;
        self
    }

    /// When accepting handshakes, allow this initiator and disallow others which have not been
    /// registered with [`allow_initiator`] or [`allow_initiators`].
    pub fn allow_initiator(mut self, initiator: PublicKey) -> Self {
        self.allowed_initiators.get_or_insert_with(HashSet::default).insert(initiator);
        self
    }

    /// When accepting handshakes, allow these initiators and disallow others which have not been
    /// registered with [`allow_initiator`] or [`allow_initiators`].
    pub fn allow_initiators<A: AsRef<[PublicKey]>>(mut self, initiators: A) -> Self {
        self.allowed_initiators.get_or_insert_with(HashSet::default).extend(initiators.as_ref());
        self
    }

    /// Specify the maximum amount of time allowed to pass between protocol ratchets.
    pub const fn max_ratchet_time(mut self, max_time: Duration) -> Self {
        self.max_ratchet_time = max_time;
        self
    }

    /// Specify the maximum amount of data allowed to pass between protocol ratchets.
    pub const fn max_ratchet_bytes(mut self, max_bytes: u64) -> Self {
        self.max_ratchet_bytes = max_bytes;
        self
    }

    /// Initiate a handshake via the given stream. Returns a [`Transport`] over the given stream if
    /// the handshake is successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake is unsuccessful or if if the stream returns an error on
    /// reads or writes during the handshake.
    pub async fn initiate_handshake<S>(
        &self,
        stream: S,
        acceptor: PublicKey,
    ) -> io::Result<Transport<S, R>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Transport::initiate_handshake(
            stream,
            self.rng.clone(),
            self.private_key.clone(),
            acceptor,
            self.max_ratchet_time,
            self.max_ratchet_bytes,
        )
        .await
    }

    /// Accept a handshake request over the given stream. Returns a [`Transport`] over the given
    /// stream if the handshake is successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake is unsuccessful or if if the stream returns an error on
    /// reads or writes during the handshake.
    pub async fn accept_handshake<S>(&self, stream: S) -> io::Result<Transport<S, R>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Transport::accept_handshake(
            stream,
            self.rng.clone(),
            self.private_key.clone(),
            self.allowed_initiators.as_ref(),
            self.max_ratchet_time,
            self.max_ratchet_bytes,
        )
        .await
    }
}
