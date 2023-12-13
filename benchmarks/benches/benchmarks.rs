#![allow(elided_lifetimes_in_paths)]

use divan::counter::BytesCount;
use rand::rngs::OsRng;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, BufReader};
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
            let acceptor = Acceptor::new(acceptor_key);
            let initiator_key = PrivateKey::random(OsRng);
            let initiator = Initiator::new(initiator_key);
            let (client, server) = io::duplex(1024 * 1024);
            (rt, acceptor, initiator, acceptor_pub, client, server)
        })
        .bench_values(|(rt, mut acceptor, mut initiator, acceptor_pub, client, server)| {
            rt.block_on(async {
                let acceptor = tokio::spawn(async move {
                    let mut t = acceptor.accept_handshake(OsRng, server).await?;
                    t.shutdown().await
                });

                let initiator = tokio::spawn(async move {
                    let mut t = initiator.initiate_handshake(OsRng, client, acceptor_pub).await?;
                    t.shutdown().await
                });

                acceptor.await??;
                initiator.await?
            })
            .expect("should handshake successfully");
        });
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
            let acceptor = Acceptor::new(acceptor_key);
            let initiator_key = PrivateKey::random(OsRng);
            let initiator = Initiator::new(initiator_key);
            let (client, server) = io::duplex(1024 * 1024);
            (rt, acceptor, initiator, acceptor_pub, client, server)
        })
        .counter(BytesCount::new(LEN))
        .bench_values(|(rt, mut acceptor, mut initiator, acceptor_pub, client, server)| {
            rt.block_on(async {
                let acceptor = tokio::spawn(async move {
                    let mut t = acceptor.accept_handshake(OsRng, server).await?;
                    io::copy(&mut t, &mut io::sink()).await?;
                    t.shutdown().await
                });

                let initiator = tokio::spawn(async move {
                    let mut t = initiator.initiate_handshake(OsRng, client, acceptor_pub).await?;
                    io::copy_buf(
                        &mut BufReader::with_capacity(64 * 1024, io::repeat(0xed).take(LEN)),
                        &mut t,
                    )
                    .await?;
                    t.shutdown().await
                });

                acceptor.await??;
                initiator.await?
            })
            .expect("should transfer successfully");
        });
}

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}
