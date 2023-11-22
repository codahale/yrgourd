use futures::{SinkExt, StreamExt};
use rand_chacha::rand_core::{OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::bytes::Bytes;
use tokio_util::sync::CancellationToken;
use yrgourd::curve25519_dalek::{RistrettoPoint, Scalar};
use yrgourd::Transport;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let addr = "127.0.0.1:4040".to_string();
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    // Generate some key pairs.
    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
    let server_static_priv = Scalar::random(&mut rng);
    let server_static_pub = RistrettoPoint::mul_base(&server_static_priv);
    let client_static_priv = Scalar::random(&mut rng);

    tokio::spawn(async move {
        // Connect to the server.
        let conn = TcpStream::connect(&addr).await.unwrap();

        // Initiate a handshake.
        let mut client =
            Transport::initiate_handshake(conn, OsRng, client_static_priv, server_static_pub)
                .await
                .unwrap();

        // Send a stupid message.
        client.send(Bytes::from_static(b"hey man, I'm a client")).await.unwrap();

        // Receive a stupid message;
        if let Some(Ok(packet)) = client.next().await {
            dbg!(packet);
        }

        // Disconnect.
        client.shutdown().await.unwrap()
    });
    let listening = CancellationToken::new();
    loop {
        // Wait for an incoming connection.
        tokio::select! {
            Ok((socket, _)) = listener.accept() => {
                let listening = listening.clone();
                tokio::spawn(async move {
                    // Accept the client's handshake.
                    let mut server =
                        Transport::accept_handshake(socket, OsRng, server_static_priv)
                            .await
                            .unwrap();

                    // Send a stupid message.
                    server.send(Bytes::from_static(b"it's me, a server")).await.unwrap();

                    // Receive a stream of stupid messages.
                    if let Some(Ok(packet)) = server.next().await {
                        dbg!(packet);
                    }

                    // Shut down the server.
                    listening.cancel();
                });
            },
            _ = listening.cancelled() => {
                break;
            }
        };
    }

    Ok(())
}
