#![allow(elided_lifetimes_in_paths)]

use divan::counter::BytesCount;
use rand::rngs::OsRng;
use tokio::io::{self, AsyncReadExt};
use yrgourd::{PrivateKey, Transport};

#[divan::bench]
fn handshake(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let acceptor_key = PrivateKey::random(OsRng);
            let acceptor_public_key = acceptor_key.public_key;
            let initiator_key = PrivateKey::random(OsRng);
            let (initiator, acceptor) = io::duplex(1024 * 1024);
            (rt, acceptor_key, initiator_key, acceptor_public_key, initiator, acceptor)
        })
        .bench_values(
            |(rt, acceptor_key, initiator_key, acceptor_public_key, initiator, acceptor)| {
                rt.block_on(async {
                    let acceptor = tokio::spawn(async move {
                        let t = Transport::accept_handshake(acceptor, OsRng, acceptor_key, None)
                            .await
                            .unwrap();

                        t.shutdown().await.unwrap();
                    });

                    let initiator = tokio::spawn(async move {
                        let t = Transport::initiate_handshake(
                            initiator,
                            OsRng,
                            initiator_key,
                            acceptor_public_key,
                        )
                        .await
                        .unwrap();

                        t.shutdown().await.unwrap();
                    });

                    acceptor.await.unwrap();
                    initiator.await.unwrap();
                });
            },
        );
}

#[divan::bench]
fn transfer(bencher: divan::Bencher) {
    const LEN: u64 = 100 * 1024 * 1024;
    bencher
        .with_inputs(|| {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let acceptor_key = PrivateKey::random(OsRng);
            let acceptor_public_key = acceptor_key.public_key;
            let initiator_key = PrivateKey::random(OsRng);
            let (initiator, acceptor) = io::duplex(1024 * 1024);
            (rt, acceptor_key, initiator_key, acceptor_public_key, initiator, acceptor)
        })
        .counter(BytesCount::new(LEN))
        .bench_values(
            |(rt, acceptor_key, initiator_key, acceptor_public_key, initiator, acceptor)| {
                rt.block_on(async {
                    let acceptor = tokio::spawn(async move {
                        let mut t =
                            Transport::accept_handshake(acceptor, OsRng, acceptor_key, None)
                                .await
                                .unwrap();
                        io::copy(&mut t, &mut io::sink()).await.unwrap();
                        t.shutdown().await.unwrap();
                    });

                    let initiator = tokio::spawn(async move {
                        let mut t = Transport::initiate_handshake(
                            initiator,
                            OsRng,
                            initiator_key,
                            acceptor_public_key,
                        )
                        .await
                        .unwrap();
                        io::copy(&mut io::repeat(0xed).take(LEN), &mut t).await.unwrap();
                        t.shutdown().await.unwrap();
                    });

                    acceptor.await.unwrap();
                    initiator.await.unwrap();
                });
            },
        );
}

fn main() {
    divan::main();
}
