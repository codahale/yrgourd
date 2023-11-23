#![allow(elided_lifetimes_in_paths)]

use rand::rngs::OsRng;
use tokio::io;
use yrgourd::{PrivateKey, Transport};

#[divan::bench]
fn handshake(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let acceptor_key = PrivateKey::random(OsRng);
            let acceptor_public_key = acceptor_key.public_key;
            let initiator_key = PrivateKey::random(OsRng);
            (rt, acceptor_key, initiator_key, acceptor_public_key)
        })
        .bench_values(|(rt, acceptor_key, initiator_key, acceptor_public_key)| {
            rt.block_on(async {
                let (initiator_conn, acceptor_conn) = io::duplex(64);

                let acceptor = tokio::spawn(async move {
                    let t = Transport::accept_handshake(acceptor_conn, OsRng, &acceptor_key)
                        .await
                        .unwrap();

                    t.shutdown().await.unwrap();
                });

                let initiator = tokio::spawn(async move {
                    let t = Transport::initiate_handshake(
                        initiator_conn,
                        OsRng,
                        &initiator_key,
                        acceptor_public_key,
                    )
                    .await
                    .unwrap();

                    t.shutdown().await.unwrap();
                });

                acceptor.await.unwrap();
                initiator.await.unwrap();
            });
        });
}

fn main() {
    divan::main();
}
