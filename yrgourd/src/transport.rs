use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use pin_project_lite::pin_project;
use rand_core::CryptoRngCore;
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::codec::Codec;

// This whole type is a bit of a bummer. I'd really like to compose StreamReader and SinkWriter
// around a Framed instance to provide Stream+Sink+AsyncRead+AsyncWrite, but you can't do that. So,
// this pulls all the weird bits of boilerplate into a single type.

pin_project! {
    #[derive(Debug)]
    /// A Yrgourd connection. Mutually authenticated and confidential.
    pub struct Transport<S, R> {
        #[pin]
        frame: Framed<S, Codec<R>>,
        chunk: Option<BytesMut>,
    }
}

impl<S, R> Transport<S, R>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: CryptoRngCore,
{
    pub(crate) const fn new(frame: Framed<S, Codec<R>>) -> Transport<S, R> {
        Transport { frame, chunk: None }
    }

    /// Consumes the [`Transport`], returning its underlying I/O stream.
    ///
    /// Note that any leftover data in the internal buffer is lost.  If you additionally want access
    /// to the internal buffer use [`into_inner_with_chunk`].
    pub fn into_inner(self) -> S {
        self.frame.into_inner()
    }

    /// Consumes the [`Transport`], returning a tuple consisting of the underlying stream and an
    /// `Option` of the internal buffer, which is `Some` in case the buffer contains elements.
    pub fn into_inner_with_chunk(self) -> (S, Option<BytesMut>) {
        (self.frame.into_inner(), self.chunk)
    }
}

impl<S, R> Stream for Transport<S, R>
where
    S: AsyncRead + Unpin,
    R: CryptoRngCore,
{
    type Item = Result<BytesMut, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().frame.poll_next(cx)
    }
}

impl<S, R> Sink<Bytes> for Transport<S, R>
where
    S: AsyncWrite + Unpin,
    R: CryptoRngCore,
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

impl<S, R> AsyncBufRead for Transport<S, R>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: CryptoRngCore,
{
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        loop {
            if self.as_mut().chunk.as_ref().map_or(false, |b| !b.is_empty()) {
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
            self.project().chunk.as_mut().expect("should have a chunk").advance(amt);
        }
    }
}

impl<S, R> AsyncRead for Transport<S, R>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: CryptoRngCore,
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

impl<S, R> AsyncWrite for Transport<S, R>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: CryptoRngCore,
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
