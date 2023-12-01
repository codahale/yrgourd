use std::collections::HashSet;
use std::time::Duration;

use codec::Codec;
use handshake::{AcceptorState, InitiatorState, REQUEST_LEN, RESPONSE_LEN};
use rand_core::CryptoRngCore;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::Framed;

pub use crate::errors::*;
pub use crate::keys::*;
pub use crate::transport::*;

mod codec;
mod errors;
mod handshake;
mod keys;
mod transport;

/// The actor in a Yrgourd connection who initiates the handshake.
#[derive(Debug)]
pub struct Initiator {
    private_key: PrivateKey,

    /// The maximum amount of time between protocol ratchets.
    pub max_ratchet_time: Duration,
    /// The maximum amount of data between protocol ratchets.
    pub max_ratchet_bytes: u64,
}

impl Initiator {
    /// Create a new [`Initiator`] with the given private key.
    pub const fn new(private_key: PrivateKey) -> Initiator {
        Initiator {
            private_key,
            max_ratchet_time: Duration::from_secs(120),
            max_ratchet_bytes: 100 * 1024 * 1024,
        }
    }

    /// Initiate a handshake via the given stream. Returns a [`Transport`] over the given stream if
    /// the handshake is successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake is unsuccessful or if if the stream returns an error on
    /// reads or writes during the handshake.
    pub async fn initiate_handshake<S, R>(
        &mut self,
        mut rng: R,
        mut stream: S,
        acceptor: PublicKey,
    ) -> io::Result<Transport<S, R>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: CryptoRngCore,
    {
        // Initialize a handshake initiator state and initiate a handshake.
        let mut handshake = InitiatorState::new(&self.private_key, acceptor);
        let req = handshake.initiate(&mut rng);
        stream.write_all(&req).await?;

        // Read and parse the handshake response from the acceptor.
        let mut resp = [0u8; RESPONSE_LEN];
        stream.read_exact(&mut resp).await?;

        // Validate the acceptor response.
        let Some((recv, send)) = handshake.finalize(resp) else {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "invalid handshake"));
        };

        Ok(Transport::new(Framed::new(
            stream,
            Codec::new(
                rng,
                self.private_key.clone(),
                acceptor,
                recv,
                send,
                self.max_ratchet_time,
                self.max_ratchet_bytes,
            ),
        )))
    }
}

/// A policy for determining whether or not to accept a handshake from an initiator.
#[derive(Debug, Clone)]
pub enum AllowPolicy {
    /// Accept handshakes from all initiators.
    AllInitiators,
    /// Accept handshakes only from initiators in the given set.
    AllowedInitiators(HashSet<PublicKey>),
}

/// The actor in a Yrgourd connection who accepts a handshake.
#[derive(Debug)]
pub struct Acceptor {
    private_key: PrivateKey,

    /// The maximum amount of time between protocol ratchets.
    pub max_ratchet_time: Duration,
    /// The maximum amount of data between protocol ratchets.
    pub max_ratchet_bytes: u64,
    /// The policy for allowing initiators to perform handshakes.
    pub allow_policy: AllowPolicy,
}

impl Acceptor {
    /// Create a new [`Acceptor`] with the given private key.
    pub const fn new(private_key: PrivateKey) -> Acceptor {
        Acceptor {
            private_key,
            max_ratchet_time: Duration::from_secs(120),
            max_ratchet_bytes: 100 * 1024 * 1024,
            allow_policy: AllowPolicy::AllInitiators,
        }
    }

    /// Accept a handshake request over the given stream. Returns a [`Transport`] over the given
    /// stream if the handshake is successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake is unsuccessful or if if the stream returns an error on
    /// reads or writes during the handshake.
    pub async fn accept_handshake<S, R>(
        &mut self,
        mut rng: R,
        mut stream: S,
    ) -> io::Result<Transport<S, R>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: CryptoRngCore,
    {
        // Initialize a handshake acceptor state.
        let mut handshake = AcceptorState::new(
            &self.private_key,
            match self.allow_policy {
                AllowPolicy::AllInitiators => None,
                AllowPolicy::AllowedInitiators(ref keys) => Some(keys),
            },
        );

        // Read and parse the handshake request from the initiator.
        let mut request = [0u8; REQUEST_LEN];
        stream.read_exact(&mut request).await?;

        // Process the handshake and generate a response.
        let (pk, recv, send, resp) = handshake
            .respond(&mut rng, request)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad handshake"))?;

        // Send the handshake response.
        stream.write_all(&resp).await?;

        Ok(Transport::new(Framed::new(
            stream,
            Codec::new(
                rng,
                self.private_key.clone(),
                pk,
                recv,
                send,
                self.max_ratchet_time,
                self.max_ratchet_bytes,
            ),
        )))
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::{OsRng, SeedableRng};
    use std::sync::Mutex;

    use super::*;

    #[tokio::test]
    async fn round_trip() -> io::Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let mut initiator = Initiator::new(PrivateKey::random(OsRng));
        let acceptor_key = PrivateKey::random(&mut rng);
        let acceptor_pub = acceptor_key.public_key;
        let mut acceptor = Acceptor::new(acceptor_key);

        let (initiator_conn, acceptor_conn) = io::duplex(64);

        let acceptor = tokio::spawn(async move {
            let mut t = acceptor.accept_handshake(OsRng, acceptor_conn).await?;
            t.write_all(b"this is a server").await?;
            t.flush().await?;

            let mut buf = Vec::new();
            t.read_to_end(&mut buf).await?;
            assert_eq!(&buf, b"this is a client");

            t.shutdown().await
        });

        let initiator = tokio::spawn(async move {
            let mut t = initiator.initiate_handshake(OsRng, initiator_conn, acceptor_pub).await?;

            t.write_all(b"this is a client").await?;
            t.flush().await?;

            let mut buf = [0u8; 16];
            t.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"this is a server");

            t.shutdown().await
        });

        acceptor.await??;
        initiator.await??;

        Ok(())
    }

    #[tokio::test]
    async fn ratcheting() -> io::Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let mut initiator = Initiator::new(PrivateKey::random(OsRng));
        let acceptor_key = PrivateKey::random(&mut rng);
        let acceptor_pub = acceptor_key.public_key;
        let mut acceptor = Acceptor::new(acceptor_key);

        let (initiator_conn, acceptor_conn) = io::duplex(64);

        let acceptor = tokio::spawn(async move {
            let mut t = acceptor.accept_handshake(OsRng, acceptor_conn).await?;

            let mut buf = String::new();
            t.read_to_string(&mut buf).await?;
            assert_eq!(&buf, "this is a client and I ratcheted the connection and it was OK");

            t.shutdown().await
        });

        let initiator = tokio::spawn(async move {
            let mut t = initiator.initiate_handshake(OsRng, initiator_conn, acceptor_pub).await?;

            // This frame is sent as data.
            t.write_all(b"this is a client").await?;
            t.flush().await?;

            // This frame is sent with an ephemeral public key.
            t.write_all(b" and I ratcheted the connection").await?;
            t.flush().await?;

            // This frame is sent with an ephemeral public key.
            t.write_all(b" and it was OK").await?;
            t.flush().await?;

            t.shutdown().await
        });

        acceptor.await??;
        initiator.await??;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_transfer() -> io::Result<()> {
        let acceptor_key = PrivateKey::random(OsRng);
        let acceptor_pub = acceptor_key.public_key;
        let mut acceptor = Acceptor::new(acceptor_key);
        let initiator_key = PrivateKey::random(OsRng);
        let mut initiator = Initiator::new(initiator_key);
        let (initiator_conn, acceptor_conn) = io::duplex(1024 * 1024);

        let acceptor = tokio::spawn(async move {
            let mut t = acceptor.accept_handshake(OsRng, acceptor_conn).await?;
            io::copy(&mut t, &mut io::sink()).await?;
            t.shutdown().await
        });

        let initiator = tokio::spawn(async move {
            let mut t = initiator.initiate_handshake(OsRng, initiator_conn, acceptor_pub).await?;
            io::copy(&mut io::repeat(0xed).take(100 * 1024 * 1024), &mut t).await?;
            t.shutdown().await
        });

        acceptor.await??;
        initiator.await??;

        Ok(())
    }

    #[test]
    fn fuzz_transport() {
        let rt = Mutex::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("should have tokio/rt-multi-thread enabled"),
        );
        bolero::check!().with_type::<(u64, u64, u64, Vec<u8>)>().cloned().for_each(
            |(s0, s1, s2, data)| {
                let mut rng = ChaChaRng::seed_from_u64(s0);
                let acceptor_key = PrivateKey::random(&mut rng);
                let acceptor_pub = acceptor_key.public_key;
                let mut acceptor = Acceptor::new(acceptor_key);
                let initiator_key = PrivateKey::random(&mut rng);
                let mut initiator = Initiator::new(initiator_key);
                let (initiator_conn, acceptor_conn) = io::duplex(1024 * 1024);

                let rt = rt.lock().unwrap();
                rt.block_on(async {
                    let acceptor = tokio::spawn(async move {
                        let rng = ChaChaRng::seed_from_u64(s1);
                        let mut t = acceptor.accept_handshake(rng, acceptor_conn).await.unwrap();
                        // Don't wait more than 100ms for the copy to complete.
                        let res = tokio::time::timeout(
                            Duration::from_millis(100),
                            io::copy(&mut t, &mut io::sink()),
                        )
                        .await;
                        // Success is anything but received data.
                        assert!(!matches!(res, Ok(Ok(n)) if n > 0));
                    });

                    let initiator = tokio::spawn(async move {
                        let rng = ChaChaRng::seed_from_u64(s2);
                        // Perform a valid handshake.
                        let mut t =
                            initiator.initiate_handshake(rng, initiator_conn, acceptor_pub).await?;
                        // Then write fuzz data directly.
                        t.frame.get_mut().write_all(&data).await
                    });

                    let _ = acceptor.await;
                    initiator.await?
                })
                .expect("should fuzz successfully");
            },
        );
    }
}
