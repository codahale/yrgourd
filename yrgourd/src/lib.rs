use std::{collections::HashSet, time::Duration};

use codec::Codec;
use rand_core::CryptoRngCore;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::codec::Framed;

pub use crate::{errors::*, keys::*, transport::*};

mod codec;
mod errors;
mod handshake;
mod keys;
mod transport;

/// The party in a Yrgourd connection who initiates the handshake.
#[derive(Debug)]
pub struct Initiator {
    private_key: PrivateKey,

    /// The maximum amount of time between protocol ratchets.
    pub max_ratchet_time: Duration,
    /// The maximum amount of data between protocol ratchets.
    pub max_ratchet_bytes: u64,
}

impl Initiator {
    /// Creates a new [`Initiator`] with the given private key.
    pub const fn new(private_key: PrivateKey) -> Initiator {
        Initiator {
            private_key,
            max_ratchet_time: Duration::from_secs(120),
            max_ratchet_bytes: 100 * 1024 * 1024,
        }
    }

    /// Initiates a handshake via the given stream. Returns a [`Transport`] over the given stream if
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
        responder: PublicKey,
    ) -> io::Result<Transport<S, R>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: CryptoRngCore,
    {
        // Initialize a handshake initiator state and initiate a handshake.
        let ephemeral = PrivateKey::random(&mut rng);
        let (yr, req) = handshake::initiate(&self.private_key, &ephemeral, &responder, &mut rng);
        stream.write_all(&req).await?;

        // Read and parse the handshake response from the responder.
        let mut resp = [0u8; handshake::RESPONSE_LEN];
        stream.read_exact(&mut resp).await?;

        // Validate the responder response.
        let Some((recv, send)) = handshake::finalize(&self.private_key, &responder, yr, resp)
        else {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "invalid handshake"));
        };

        Ok(Transport::new(Framed::new(
            stream,
            Codec::new(
                rng,
                self.private_key.clone(),
                responder,
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

impl AllowPolicy {
    const fn keys(&self) -> Option<&HashSet<PublicKey>> {
        match self {
            AllowPolicy::AllInitiators => None,
            AllowPolicy::AllowedInitiators(ref keys) => Some(keys),
        }
    }
}

/// The party in a Yrgourd connection who accepts a handshake.
#[derive(Debug)]
pub struct Responder {
    private_key: PrivateKey,

    /// The maximum amount of time between protocol ratchets.
    pub max_ratchet_time: Duration,
    /// The maximum amount of data between protocol ratchets.
    pub max_ratchet_bytes: u64,
    /// The policy for allowing initiators to perform handshakes.
    pub allow_policy: AllowPolicy,
}

impl Responder {
    /// Creates a new [`Responder`] with the given private key.
    pub const fn new(private_key: PrivateKey) -> Responder {
        Responder {
            private_key,
            max_ratchet_time: Duration::from_secs(120),
            max_ratchet_bytes: 100 * 1024 * 1024,
            allow_policy: AllowPolicy::AllInitiators,
        }
    }

    /// Accepts a handshake request over the given stream. Returns a [`Transport`] over the given
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
        // Read the handshake request from the initiator.
        let mut req = [0u8; handshake::REQUEST_LEN];
        stream.read_exact(&mut req).await?;

        // Process the handshake and generate a response.
        let ephemeral = PrivateKey::random(&mut rng);
        let (pk, recv, send, resp) = handshake::accept(
            &self.private_key,
            &ephemeral,
            self.allow_policy.keys(),
            &mut rng,
            req,
        )
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
    use tokio::{io::BufReader, time};

    use super::*;

    #[tokio::test]
    async fn round_trip() -> io::Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let mut initiator = Initiator::new(PrivateKey::random(OsRng));
        let responder_key = PrivateKey::random(&mut rng);
        let responder_pub = responder_key.public_key;
        let mut responder = Responder::new(responder_key);

        let (initiator_conn, responder_conn) = io::duplex(64);

        let responder = tokio::spawn(async move {
            let mut t = responder.accept_handshake(OsRng, responder_conn).await?;
            t.write_all(b"this is a server").await?;
            t.flush().await?;

            let mut buf = Vec::new();
            t.read_to_end(&mut buf).await?;
            assert_eq!(&buf, b"this is a client");

            t.shutdown().await
        });

        let initiator = tokio::spawn(async move {
            let mut t = initiator.initiate_handshake(OsRng, initiator_conn, responder_pub).await?;

            t.write_all(b"this is a client").await?;
            t.flush().await?;

            let mut buf = [0u8; 16];
            time::timeout(Duration::from_millis(500), t.read_exact(&mut buf)).await??;
            assert_eq!(&buf, b"this is a server");

            t.shutdown().await
        });

        let (r, i) = futures::try_join!(responder, initiator)?;
        r.and(i)
    }

    #[tokio::test]
    async fn ratcheting() -> io::Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let mut initiator = Initiator::new(PrivateKey::random(OsRng));
        let responder_key = PrivateKey::random(&mut rng);
        let responder_pub = responder_key.public_key;
        let mut responder = Responder::new(responder_key);

        let (initiator_conn, responder_conn) = io::duplex(64);

        let responder = tokio::spawn(async move {
            let mut t = responder.accept_handshake(OsRng, responder_conn).await?;

            let mut buf = String::new();
            t.read_to_string(&mut buf).await?;
            assert_eq!(&buf, "this is a client and I ratcheted the connection and it was OK");

            t.shutdown().await
        });

        let initiator = tokio::spawn(async move {
            let mut t = initiator.initiate_handshake(OsRng, initiator_conn, responder_pub).await?;

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

        let (r, i) = futures::try_join!(responder, initiator)?;
        r.and(i)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_transfer() -> io::Result<()> {
        let responder_key = PrivateKey::random(OsRng);
        let responder_pub = responder_key.public_key;
        let mut responder = Responder::new(responder_key);
        let initiator_key = PrivateKey::random(OsRng);
        let mut initiator = Initiator::new(initiator_key);
        let (initiator_conn, responder_conn) = io::duplex(1024 * 1024);

        let responder = tokio::spawn(async move {
            let mut t = responder.accept_handshake(OsRng, responder_conn).await?;
            time::timeout(Duration::from_secs(10), io::copy(&mut t, &mut io::sink())).await??;
            t.shutdown().await
        });

        let initiator = tokio::spawn(async move {
            let mut t = initiator.initiate_handshake(OsRng, initiator_conn, responder_pub).await?;
            time::timeout(
                Duration::from_secs(10),
                io::copy_buf(
                    &mut BufReader::with_capacity(
                        64 * 1024,
                        io::repeat(0xed).take(100 * 1024 * 1024),
                    ),
                    &mut t,
                ),
            )
            .await??;
            t.shutdown().await
        });

        let (r, i) = futures::try_join!(responder, initiator)?;
        r.and(i)
    }

    #[test]
    fn fuzz_handshake() {
        let rt = Mutex::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("should have tokio/rt-multi-thread enabled"),
        );
        bolero::check!().with_type::<(u64, u64, Vec<u8>)>().cloned().for_each(|(s0, s1, data)| {
            let mut rng = ChaChaRng::seed_from_u64(s0);
            let responder_key = PrivateKey::random(&mut rng);
            let mut responder = Responder::new(responder_key);
            let (mut initiator_conn, responder_conn) = io::duplex(1024 * 1024);

            let rt = rt.lock().unwrap();
            rt.block_on(async {
                let responder = tokio::spawn(async move {
                    let rng = ChaChaRng::seed_from_u64(s1);
                    // Don't wait for more than 100ms for the handshake to complete.
                    let t = tokio::time::timeout(
                        Duration::from_millis(100),
                        responder.accept_handshake(rng, responder_conn),
                    )
                    .await;
                    // Success is either a timeout or a handshake failure.
                    assert!(t.is_err() || t.unwrap().is_err());
                    Ok(())
                });

                let initiator = tokio::spawn(async move {
                    // Write the fuzz data directly to the underlying stream.
                    initiator_conn.write_all(&data).await
                });

                let (r, i) = futures::try_join!(responder, initiator)?;
                r.and(i)
            })
            .expect("should fuzz successfully");
        });
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
                let responder_key = PrivateKey::random(&mut rng);
                let responder_pub = responder_key.public_key;
                let mut responder = Responder::new(responder_key);
                let initiator_key = PrivateKey::random(&mut rng);
                let mut initiator = Initiator::new(initiator_key);
                let (client, server) = io::duplex(1024 * 1024);

                let rt = rt.lock().unwrap();
                rt.block_on(async {
                    let responder = tokio::spawn(async move {
                        let rng = ChaChaRng::seed_from_u64(s1);
                        let mut t = responder.accept_handshake(rng, server).await.unwrap();
                        // Don't wait more than 100ms for the copy to complete.
                        let res = tokio::time::timeout(
                            Duration::from_millis(100),
                            io::copy(&mut t, &mut io::sink()),
                        )
                        .await;
                        // Success is anything but received data.
                        assert!(!matches!(res, Ok(Ok(n)) if n > 0));
                        Ok(())
                    });

                    let initiator = tokio::spawn(async move {
                        let rng = ChaChaRng::seed_from_u64(s2);
                        // Perform a valid handshake.
                        let t = initiator.initiate_handshake(rng, client, responder_pub).await?;
                        // Then write fuzz data directly.
                        t.into_inner().write_all(&data).await
                    });

                    let (r, i) = futures::try_join!(responder, initiator)?;
                    r.and(i)
                })
                .expect("should fuzz successfully");
            },
        );
    }
}
