use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use curve25519_dalek::{RistrettoPoint, Scalar};
use futures::{Sink, Stream};
use pin_project_lite::pin_project;
use rand::{CryptoRng, RngCore};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::codec::Codec;
use crate::handshake::{ClientHandshake, HandshakeRequest, HandshakeResponse, ServerHandshake};

pin_project! {
    pub struct Transport<S> {
        frame: Framed<S, Codec>,
    }
}

impl<S> Transport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn initiate_handshake(
        mut conn: S,
        mut rng: impl RngCore + CryptoRng,
        static_priv: Scalar,
        server_static_pub: RistrettoPoint,
    ) -> io::Result<Transport<S>> {
        // Initialize a client handshake state and initiate a handshake.
        let mut handshake = ClientHandshake::new(&mut rng, static_priv, server_static_pub);
        let req = handshake.initiate(&mut rng);
        conn.write_all(&req.to_bytes()).await?;

        // Read and parse the handshake response from the server.
        let mut resp = [0u8; HandshakeResponse::LEN];
        conn.read_exact(&mut resp).await?;
        let resp = HandshakeResponse::from_bytes(resp);

        // Validate the server response.
        let Some((recv, send)) = handshake.finalize(&resp) else {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "invalid handshake"));
        };

        Ok(Transport { frame: Framed::new(conn, Codec::new(recv, send)) })
    }

    pub async fn accept_handshake(
        mut conn: S,
        mut rng: impl RngCore + CryptoRng,
        static_priv: Scalar,
    ) -> io::Result<Transport<S>> {
        // Initialize a server handshake state.
        let mut handshake = ServerHandshake::new(static_priv);

        // Read and parse the handshake request from the client.
        let mut request = [0u8; HandshakeRequest::LEN];
        conn.read_exact(&mut request).await?;
        let req = HandshakeRequest::from_bytes(request);

        // Process the handshake and generate a response.
        let (recv, send, resp) = handshake
            .respond(&mut rng, &req)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad handshake"))?;

        // Send the handshake response.
        conn.write_all(&resp.to_bytes()).await?;

        Ok(Transport { frame: Framed::new(conn, Codec::new(recv, send)) })
    }

    pub async fn shutdown(self) -> io::Result<()> {
        self.frame.into_inner().shutdown().await
    }
}

impl<S> Stream for Transport<S>
where
    S: AsyncRead + Unpin,
{
    type Item = Result<BytesMut, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(self.project().frame).poll_next(cx)
    }
}

impl<S> Sink<Bytes> for Transport<S>
where
    S: AsyncWrite + Unpin,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(self.project().frame).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(self.project().frame).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(self.project().frame).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(self.project().frame).poll_close(cx)
    }
}
