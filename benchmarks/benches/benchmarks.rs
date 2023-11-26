#![allow(elided_lifetimes_in_paths)]

use divan::counter::BytesCount;
use rand::rngs::OsRng;
use tokio::io::{self, AsyncReadExt};
use yrgourd::{Acceptor, Initiator, PrivateKey};

#[divan::bench]
fn handshake(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("should have tokio/rt-multi-thread enabled");
            let acceptor_key = PrivateKey::random(OsRng);
            let acceptor_pub = acceptor_key.public_key;
            let acceptor = Acceptor::new(OsRng, acceptor_key);
            let initiator_key = PrivateKey::random(OsRng);
            let initiator = Initiator::new(OsRng, initiator_key);
            let (initiator_conn, acceptor_conn) = io::duplex(1024 * 1024);
            (rt, acceptor, initiator, acceptor_pub, initiator_conn, acceptor_conn)
        })
        .bench_values(
            |(rt, mut acceptor, mut initiator, acceptor_pub, initiator_conn, acceptor_conn)| {
                rt.block_on(async {
                    let acceptor = tokio::spawn(async move {
                        let t = acceptor.accept_handshake(acceptor_conn).await?;
                        t.shutdown().await
                    });

                    let initiator = tokio::spawn(async move {
                        let t = initiator.initiate_handshake(initiator_conn, acceptor_pub).await?;
                        t.shutdown().await
                    });

                    acceptor.await??;
                    initiator.await?
                })
                .expect("should handshake successfully");
            },
        );
}

#[divan::bench]
fn transfer(bencher: divan::Bencher) {
    const LEN: u64 = 100 * 1024 * 1024;
    bencher
        .with_inputs(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("should have tokio/rt-multi-thread enabled");
            let acceptor_key = PrivateKey::random(OsRng);
            let acceptor_pub = acceptor_key.public_key;
            let acceptor = Acceptor::new(OsRng, acceptor_key);
            let initiator_key = PrivateKey::random(OsRng);
            let initiator = Initiator::new(OsRng, initiator_key);
            let (initiator_conn, acceptor_conn) = io::duplex(1024 * 1024);
            (rt, acceptor, initiator, acceptor_pub, initiator_conn, acceptor_conn)
        })
        .counter(BytesCount::new(LEN))
        .bench_values(
            |(rt, mut acceptor, mut initiator, acceptor_pub, initiator_conn, acceptor_conn)| {
                rt.block_on(async {
                    let acceptor = tokio::spawn(async move {
                        let mut t = acceptor.accept_handshake(acceptor_conn).await?;
                        io::copy(&mut t, &mut io::sink()).await?;
                        t.shutdown().await
                    });

                    let initiator = tokio::spawn(async move {
                        let mut t =
                            initiator.initiate_handshake(initiator_conn, acceptor_pub).await?;
                        io::copy(&mut io::repeat(0xed).take(LEN), &mut t).await?;
                        t.shutdown().await
                    });

                    acceptor.await??;
                    initiator.await?
                })
                .expect("should transfer successfully");
            },
        );
}

fn main() {
    divan::main();
}
