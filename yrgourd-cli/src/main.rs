use std::time::Duration;

use anyhow::bail;
use futures::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite, LengthDelimitedCodec};
use yrgourd::curve25519_dalek::{RistrettoPoint, Scalar};
use yrgourd::lockstitch::{Protocol, TAG_LEN};
use yrgourd::{
    ClientHandshake, HandshakeRequest, HandshakeResponse, ServerHandshake, HANDSHAKE_REQ_LEN,
    HANDSHAKE_RESP_LEN,
};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let addr = "127.0.0.1:4040".to_string();
    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
    let static_priv = Scalar::random(&mut rng);
    let static_pub = RistrettoPoint::mul_base(&static_priv);
    let server = ServerHandshake::new(static_priv);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut client = ClientHandshake::new(&mut rng, static_priv, static_pub);
        let mut conn = TcpStream::connect(&addr).await.expect("unable to connect");
        dbg!("client requesting handshake");
        let req = client.request(&mut rng);
        conn.write_all(&req.to_bytes()).await.expect("should send handshake");

        dbg!("client receiving handshake");
        let mut resp = [0u8; HANDSHAKE_RESP_LEN];
        conn.read_exact(&mut resp).await.expect("should receive handshake");
        let resp = HandshakeResponse::from_bytes(resp);

        dbg!("client switching to duplex");
        let (recv, send) = client.finalize(&resp).expect("should handshake successfully");

        let sender = Sender::new(send);
        let receiver = Receiver::new(recv);
        let (r, w) = conn.into_split();
        let mut r = FramedRead::new(r, receiver);
        let mut w = FramedWrite::new(w, sender);

        dbg!("client starting read loop");
        let h = tokio::spawn(async move {
            while let Some(Ok(packet)) = r.next().await {
                dbg!(packet);
            }
        });

        dbg!("client sending message");
        w.send(Bytes::from_static(b"hello, it's a client")).await.expect("send is good");

        h.await.expect("ok");

        dbg!("client shutting down");
        w.into_inner().shutdown().await.expect("should shut down");
    });

    loop {
        // Wait for an incoming connection, then clone the pre-handshake protocol state.
        let (mut socket, _) = listener.accept().await?;
        let mut server = server.clone();

        tokio::spawn(async move {
            // Receive and parse the handshake request.
            dbg!("server reading handshake");
            let mut request = [0u8; HANDSHAKE_REQ_LEN];
            let Ok(_) = socket.read_exact(&mut request).await else {
                println!("unable to read handshake");
                return;
            };
            let handshake = HandshakeRequest::from_bytes(request);

            // Process the handshake and generate a response.
            let Some((recv, send, resp)) = server.respond(OsRng, &handshake) else {
                println!("bad handshake");
                return;
            };

            // Send the handshake response.
            dbg!("server sending handshake");
            let Ok(_) = socket.write_all(&resp.to_bytes()).await else {
                println!("unable to write response");
                return;
            };

            dbg!("server switching to mux");
            let sender = Sender::new(send);
            let receiver = Receiver::new(recv);
            let (r, w) = socket.into_split();
            let mut r = FramedRead::new(r, receiver);
            let mut w = FramedWrite::new(w, sender);

            dbg!("server starting read loop");
            let h = tokio::spawn(async move {
                while let Some(Ok(packet)) = r.next().await {
                    dbg!(packet);
                }
            });

            dbg!("server sending message");
            if let Err(e) = w.send(Bytes::from_static(b"this is a server")).await {
                println!("error sending: {}", e);
            }

            h.await.expect("woot");
        });
    }
}

pub struct Sender {
    protocol: Protocol,
    codec: LengthDelimitedCodec,
}

impl Sender {
    pub fn new(protocol: Protocol) -> Sender {
        Sender { protocol, codec: Self::codec() }
    }

    fn codec() -> LengthDelimitedCodec {
        LengthDelimitedCodec::builder().new_codec()
    }
}

impl Encoder<Bytes> for Sender {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut ciphertext = item.to_vec();
        ciphertext.extend_from_slice(&[0u8; TAG_LEN]);
        self.protocol.seal(b"message", &mut ciphertext);
        self.codec.encode(Bytes::copy_from_slice(&ciphertext), dst).map_err(anyhow::Error::new)
    }
}

pub struct Receiver {
    protocol: Protocol,
    codec: LengthDelimitedCodec,
}

impl Receiver {
    pub fn new(protocol: Protocol) -> Receiver {
        Receiver { protocol, codec: Sender::codec() }
    }
}

impl Decoder for Receiver {
    type Item = BytesMut;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(mut item) = self.codec.decode(src).map_err(anyhow::Error::new)? else {
            return Ok(None);
        };

        let Some(len) = self.protocol.open(b"message", &mut item).map(|p| p.len()) else {
            bail!("invalid ciphertext");
        };

        Ok(Some(item.split_to(len)))
    }
}
