#![allow(elided_lifetimes_in_paths)]

use rand::rngs::OsRng;
use tokio::io;
use yrgourd::{PrivateKey, Transport};

#[divan::bench]
fn handshake(bencher: divan::Bencher) {
    bencher
        .with_inputs(|| {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            let server_key = PrivateKey::random(OsRng);
            let server_public_key = server_key.public_key;
            let client_key = PrivateKey::random(OsRng);
            (rt, server_key, client_key, server_public_key)
        })
        .bench_values(|(rt, server_key, client_key, server_public_key)| {
            rt.block_on(async {
                let (client_conn, server_conn) = io::duplex(64);

                let server = tokio::spawn(async move {
                    let t =
                        Transport::accept_handshake(server_conn, OsRng, &server_key).await.unwrap();

                    t.shutdown().await.unwrap();
                });

                let client = tokio::spawn(async move {
                    let t = Transport::initiate_handshake(
                        client_conn,
                        OsRng,
                        &client_key,
                        server_public_key,
                    )
                    .await
                    .unwrap();

                    t.shutdown().await.unwrap();
                });

                server.await.unwrap();
                client.await.unwrap();
            });
        });
}

fn main() {
    divan::main();
}
