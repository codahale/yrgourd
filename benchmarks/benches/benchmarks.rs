#![allow(elided_lifetimes_in_paths)]

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::rngs::OsRng;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, BufReader};
use yrgourd::{Initiator, PrivateKey, Responder};

fn setup() -> (Responder, Initiator, yrgourd::PublicKey, io::DuplexStream, io::DuplexStream) {
    let responder_key = PrivateKey::random(OsRng);
    let responder_pub = responder_key.public_key;
    let responder = Responder::new(responder_key);
    let initiator_key = PrivateKey::random(OsRng);
    let initiator = Initiator::new(initiator_key);
    let (client, server) = io::duplex(1024 * 1024);
    (responder, initiator, responder_pub, client, server)
}

fn handshake(c: &mut Criterion) {
    c.bench_function("handshake", move |b| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("should have tokio/rt-multi-thread enabled");
        b.to_async(rt).iter_batched(
            setup,
            |(mut responder, mut initiator, responder_pub, client, server)| async move {
                let responder = tokio::spawn(async move {
                    let mut t = responder.handshake(OsRng, server).await?;
                    t.shutdown().await
                });

                let initiator = tokio::spawn(async move {
                    let mut t = initiator.handshake(OsRng, client, responder_pub).await?;
                    t.shutdown().await
                });

                responder.await??;
                initiator.await?
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

const LENS: &[(u64, &str)] = &[
    (1024 * 1024, "1MiB"),
    (10 * 1024 * 1024, "10MiB"),
    (100 * 1024 * 1024, "100MiB"),
    (1024 * 1024 * 1024, "1GiB"),
];

fn transfer(c: &mut Criterion) {
    let mut g = c.benchmark_group("transfer");
    for &(len, id) in LENS {
        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(id, &len, |b, &len| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("should have tokio/rt-multi-thread enabled");
            b.to_async(rt).iter_batched(
                setup,
                |(mut responder, mut initiator, responder_pub, client, server)| async move {
                    let responder = tokio::spawn(async move {
                        let mut t = responder.handshake(OsRng, server).await?;
                        io::copy(&mut t, &mut io::sink()).await?;
                        t.shutdown().await
                    });

                    let initiator = tokio::spawn(async move {
                        let mut t = initiator.handshake(OsRng, client, responder_pub).await?;
                        io::copy_buf(
                            &mut BufReader::with_capacity(64 * 1024, io::repeat(0xed).take(len)),
                            &mut t,
                        )
                        .await?;
                        t.shutdown().await
                    });

                    responder.await??;
                    initiator.await?
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, handshake, transfer);
criterion_main!(benches);

// #[divan::bench]
// fn handshake(bencher: divan::Bencher) {
//     bencher
//         .with_inputs(|| {
//             let rt = tokio::runtime::Builder::new_multi_thread()
//                 .enable_all()
//                 .build()
//                 .expect("should have tokio/rt-multi-thread enabled");
//             let responder_key = PrivateKey::random(OsRng);
//             let responder_pub = responder_key.public_key;
//             let responder = Responder::new(responder_key);
//             let initiator_key = PrivateKey::random(OsRng);
//             let initiator = Initiator::new(initiator_key);
//             let (client, server) = io::duplex(1024 * 1024);
//             (rt, responder, initiator, responder_pub, client, server)
//         })
//         .bench_values(|(rt, mut responder, mut initiator, responder_pub, client, server)| {
//             rt.block_on(async {
//                 let responder = tokio::spawn(async move {
//                     let mut t = responder.handshake(OsRng, server).await?;
//                     t.shutdown().await
//                 });

//                 let initiator = tokio::spawn(async move {
//                     let mut t = initiator.handshake(OsRng, client, responder_pub).await?;
//                     t.shutdown().await
//                 });

//                 responder.await??;
//                 initiator.await?
//             })
//             .expect("should handshake successfully");
//         });
// }

// #[divan::bench]
// fn transfer(bencher: divan::Bencher) {
//     const LEN: u64 = 100 * 1024 * 1024;
//     bencher
//         .with_inputs(|| {
//             let rt = tokio::runtime::Builder::new_multi_thread()
//                 .enable_all()
//                 .build()
//                 .expect("should have tokio/rt-multi-thread enabled");
//             let responder_key = PrivateKey::random(OsRng);
//             let responder_pub = responder_key.public_key;
//             let responder = Responder::new(responder_key);
//             let initiator_key = PrivateKey::random(OsRng);
//             let initiator = Initiator::new(initiator_key);
//             let (client, server) = io::duplex(1024 * 1024);
//             (rt, responder, initiator, responder_pub, client, server)
//         })
//         .counter(BytesCount::new(LEN))
//         .bench_values(|(rt, mut responder, mut initiator, responder_pub, client, server)| {
//             rt.block_on(async {
//                 let responder = tokio::spawn(async move {
//                     let mut t = responder.handshake(OsRng, server).await?;
//                     io::copy(&mut t, &mut io::sink()).await?;
//                     t.shutdown().await
//                 });

//                 let initiator = tokio::spawn(async move {
//                     let mut t = initiator.handshake(OsRng, client, responder_pub).await?;
//                     io::copy_buf(
//                         &mut BufReader::with_capacity(64 * 1024, io::repeat(0xed).take(LEN)),
//                         &mut t,
//                     )
//                     .await?;
//                     t.shutdown().await
//                 });

//                 responder.await??;
//                 initiator.await?
//             })
//             .expect("should transfer successfully");
//         });
// }

// #[global_allocator]
// static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

// fn main() {
//     divan::main();
// }
