#![allow(elided_lifetimes_in_paths)]

use divan::counter::BytesCount;
use rand::rngs::OsRng;
use tokio::io::{self, AsyncReadExt};
use yrgourd::{PrivateKey, Yrgourd};

#[divan::bench]
fn handshake(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let acceptor_key = PrivateKey::random(OsRng);
            let acceptor_public_key = acceptor_key.public_key;
            let initiator_key = PrivateKey::random(OsRng);
            let yg_acceptor = Yrgourd::new(acceptor_key, OsRng);
            let yg_initiator = Yrgourd::new(initiator_key, OsRng);
            let (initiator, acceptor) = io::duplex(1024 * 1024);
            (rt, yg_acceptor, yg_initiator, acceptor_public_key, initiator, acceptor)
        })
        .bench_values(
            |(rt, yg_acceptor, yg_initiator, acceptor_public_key, initiator, acceptor)| {
                rt.block_on(async {
                    let acceptor = tokio::spawn(async move {
                        let t = yg_acceptor.accept_handshake(acceptor).await.unwrap();
                        t.shutdown().await.unwrap();
                    });

                    let initiator = tokio::spawn(async move {
                        let t = yg_initiator
                            .initiate_handshake(initiator, acceptor_public_key)
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
            let yg_acceptor = Yrgourd::new(acceptor_key, OsRng);
            let yg_initiator = Yrgourd::new(initiator_key, OsRng);
            let (initiator, acceptor) = io::duplex(1024 * 1024);
            (rt, yg_acceptor, yg_initiator, acceptor_public_key, initiator, acceptor)
        })
        .counter(BytesCount::new(LEN))
        .bench_values(
            |(rt, yg_acceptor, yg_initiator, acceptor_public_key, initiator, acceptor)| {
                rt.block_on(async {
                    let acceptor = tokio::spawn(async move {
                        let mut t = yg_acceptor.accept_handshake(acceptor).await.unwrap();
                        io::copy(&mut t, &mut io::sink()).await.unwrap();
                        t.shutdown().await.unwrap();
                    });

                    let initiator = tokio::spawn(async move {
                        let mut t = yg_initiator
                            .initiate_handshake(initiator, acceptor_public_key)
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
