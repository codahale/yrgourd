use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use pin_project_lite::pin_project;
use rand_core::{CryptoRng, RngCore};
use tokio::io::{self, AsyncBufRead, AsyncReadExt, AsyncWriteExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::codec::Codec;
use crate::handshake::{Acceptor, Initiator, Request, Response};
use crate::keys::{PrivateKey, PublicKey};

pin_project! {
    /// A yrgourd connection.
    pub struct Transport<S> {
        #[pin]
        frame: Framed<S, Codec>,
        chunk: Option<BytesMut>,
    }
}

impl<S> Transport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Initiate a handshake via the given stream. Returns a [`Transport`] over the given stream if
    /// the handshake is successful.
    pub async fn initiate_handshake(
        mut stream: S,
        mut rng: impl RngCore + CryptoRng,
        private_key: &PrivateKey,
        acceptor_public_key: PublicKey,
    ) -> io::Result<Transport<S>> {
        // Initialize a handshake initiator state and initiate a handshake.
        let mut handshake = Initiator::new(&mut rng, private_key, acceptor_public_key);
        let req = handshake.initiate(&mut rng);
        stream.write_all(&req.to_bytes()).await?;

        // Read and parse the handshake response from the acceptor.
        let mut resp = [0u8; Response::LEN];
        stream.read_exact(&mut resp).await?;
        let resp = Response::from_bytes(resp);

        // Validate the acceptor response.
        let Some((recv, send)) = handshake.finalize(&resp) else {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "invalid handshake"));
        };

        Ok(Transport { frame: Framed::new(stream, Codec::new(recv, send)), chunk: None })
    }

    /// Accept a handshake request over the given stream. Returns a [`Transport`] over the given
    /// stream if the handshake is successful.
    pub async fn accept_handshake(
        mut stream: S,
        mut rng: impl RngCore + CryptoRng,
        private_key: &PrivateKey,
    ) -> io::Result<Transport<S>> {
        // Initialize a handshake acceptor state.
        let mut handshake = Acceptor::new(private_key);

        // Read and parse the handshake request from the initiator.
        let mut request = [0u8; Request::LEN];
        stream.read_exact(&mut request).await?;
        let req = Request::from_bytes(request);

        // Process the handshake and generate a response.
        let (recv, send, resp) = handshake
            .respond(&mut rng, &req)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad handshake"))?;

        // Send the handshake response.
        stream.write_all(&resp.to_bytes()).await?;

        Ok(Transport { frame: Framed::new(stream, Codec::new(recv, send)), chunk: None })
    }

    /// Shuts down the output stream, ensuring that the value can be dropped cleanly.
    pub async fn shutdown(self) -> io::Result<()> {
        self.frame.into_inner().shutdown().await
    }

    fn has_chunk(&self) -> bool {
        if let Some(ref chunk) = self.chunk {
            chunk.remaining() > 0
        } else {
            false
        }
    }
}

impl<S> Stream for Transport<S>
where
    S: AsyncRead + Unpin,
{
    type Item = Result<BytesMut, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().frame.poll_next(cx)
    }
}

impl<S> Sink<Bytes> for Transport<S>
where
    S: AsyncWrite + Unpin,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.project().frame.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().frame.poll_close(cx)
    }
}

impl<S> AsyncBufRead for Transport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        loop {
            if self.as_mut().has_chunk() {
                // This unwrap is very sad, but it can't be avoided.
                let buf = self.project().chunk.as_ref().unwrap().chunk();
                return Poll::Ready(Ok(buf));
            } else {
                match self.as_mut().project().frame.poll_next(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        // Go around the loop in case the chunk is empty.
                        *self.as_mut().project().chunk = Some(chunk);
                    }
                    Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                    Poll::Ready(None) => return Poll::Ready(Ok(&[])),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        if amt > 0 {
            self.project().chunk.as_mut().expect("No chunk present").advance(amt);
        }
    }
}

impl<S> AsyncRead for Transport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let inner_buf = match self.as_mut().poll_fill_buf(cx) {
            Poll::Ready(Ok(buf)) => buf,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        let len = std::cmp::min(inner_buf.len(), buf.remaining());
        buf.put_slice(&inner_buf[..len]);

        self.consume(len);
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for Transport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut this = self.project();
        ready!(this.frame.as_mut().poll_ready(cx))?;
        match Pin::new(this.frame).as_mut().start_send(Bytes::copy_from_slice(buf)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().frame.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().frame.poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::{OsRng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn round_trip() -> io::Result<()> {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let initiator_key = PrivateKey::random(&mut rng);
        let acceptor_key = PrivateKey::random(&mut rng);
        let acceptor_public_key = acceptor_key.public_key;

        let (initiator_conn, acceptor_conn) = io::duplex(64);

        let acceptor = tokio::spawn(async move {
            let mut t =
                Transport::accept_handshake(acceptor_conn, OsRng, &acceptor_key).await.unwrap();

            t.write_all(b"this is a server").await.unwrap();
            t.flush().await.unwrap();

            let mut buf = Vec::new();
            t.read_to_end(&mut buf).await.unwrap();
            assert_eq!(&buf, b"this is a client");

            t.shutdown().await.unwrap();
        });

        let initiator = tokio::spawn(async move {
            let mut t = Transport::initiate_handshake(
                initiator_conn,
                OsRng,
                &initiator_key,
                acceptor_public_key,
            )
            .await
            .unwrap();

            t.write_all(b"this is a client").await.unwrap();
            t.flush().await.unwrap();

            let mut buf = [0u8; 16];
            t.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"this is a server");

            t.shutdown().await.unwrap();
        });

        acceptor.await.unwrap();
        initiator.await.unwrap();

        Ok(())
    }
}
