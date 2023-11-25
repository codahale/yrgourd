use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use lockstitch::{Protocol, TAG_LEN};
use rand_core::{CryptoRng, RngCore};
use tokio::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::{PrivateKey, PublicKey};

const DATA: u8 = 1;
const DATA_WITH_KEY: u8 = 2;

/// A duplex codec for encrypted frames. Each frame has a 3-byte little-endian length prefix, then
/// an encrypted payload, then a 16-byte authenticator tag.
#[derive(Debug)]
pub struct Codec<R> {
    rng: R,
    sender: PrivateKey,
    receiver: PublicKey,
    recv: Protocol,
    send: Protocol,
    codec: LengthDelimitedCodec,
    next_ratchet_at_time: Instant,
    next_ratchet_at_bytes: u64,
    max_ratchet_time: Duration,
    max_ratchet_bytes: u64,
}

impl<R> Codec<R>
where
    R: RngCore + CryptoRng,
{
    /// Create a new [`Codec`] with the sender's private key, the receiver's public key, and the
    /// given `recv` and `send` protocols.
    pub fn new(
        rng: R,
        sender: PrivateKey,
        receiver: PublicKey,
        recv: Protocol,
        send: Protocol,
        max_ratchet_time: Duration,
        max_ratchet_bytes: u64,
    ) -> Codec<R> {
        Codec {
            rng,
            sender,
            receiver,
            recv,
            send,
            codec: LengthDelimitedCodec::builder()
                .little_endian()
                .length_field_length(3)
                .new_codec(),
            next_ratchet_at_time: Instant::now() + max_ratchet_time,
            max_ratchet_time,
            next_ratchet_at_bytes: max_ratchet_bytes,
            max_ratchet_bytes,
        }
    }
}

impl<R> Encoder<Bytes> for Codec<R>
where
    R: RngCore + CryptoRng,
{
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Decrement the ratchet bytes counter, stopping at zero.
        self.next_ratchet_at_bytes = self.next_ratchet_at_bytes.saturating_sub(item.len() as u64);

        // Check to see if our ratchet deadline has passed or our counter has exceeded the maximum.
        let ratchet =
            if self.next_ratchet_at_time < Instant::now() || self.next_ratchet_at_bytes == 0 {
                // If so, generate an ephemeral key and reset the deadline and counter.
                self.next_ratchet_at_time = Instant::now() + self.max_ratchet_time;
                self.next_ratchet_at_bytes = self.max_ratchet_bytes;
                Some(PrivateKey::random(&mut self.rng))
            } else {
                None
            };

        let mut frame = if let Some(ref ephemeral) = ratchet {
            // If there is an ephemeral key, prepend the DATA_WITH_KEY frame typeand the
            // ephemeral public key to the data.
            let mut output = BytesMut::with_capacity(1 + 32 + item.len() + TAG_LEN);
            output.put_u8(DATA_WITH_KEY);
            output.extend_from_slice(&ephemeral.public_key.encoded);
            output
        } else {
            // Otherwise, prepend the DATA frame type.
            let mut output = BytesMut::with_capacity(1 + item.len() + TAG_LEN);
            output.put_u8(DATA);
            output
        };

        // Append the actual data and room for an authenticator tag.
        frame.extend_from_slice(&item);
        frame.extend_from_slice(&[0u8; TAG_LEN]);

        // Seal the frame.
        self.send.seal(b"frame", &mut frame);

        // Do any necessary ratcheting after the frame has been sealed.
        if let Some(ephemeral) = ratchet {
            self.send.mix(b"ratchet-shared", (ephemeral.d * self.receiver.q).compress().as_bytes());
        }

        // Prepend the length delimiter for the frame.
        self.codec.encode(Bytes::from(frame), dst)
    }
}

impl<R> Decoder for Codec<R> {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // If there is no full frame to process, exit early.
        let Some(mut frame) = self.codec.decode(src)? else {
            return Ok(None);
        };

        // Open the sealed frame as long as it's as longer than an authenticator tag. It must be at
        // least one byte long.
        if self.recv.open(b"frame", &mut frame).is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ciphertext"));
        }

        // Remove the tag.
        frame.truncate(frame.len() - TAG_LEN);

        // Remove the frame type.
        match frame.split_to(1)[0] {
            // If it's just data, return it.
            DATA => Ok(Some(frame)),
            // If it's data with a key, parse the key and if possible, ratchet the recv protocol with
            // the ephemeral shared secret.
            DATA_WITH_KEY => {
                if let Ok(pk) = PublicKey::try_from(frame.split_to(32).as_ref()) {
                    self.recv.mix(b"ratchet-shared", (self.sender.d * pk.q).compress().as_bytes());
                }
                Ok(Some(frame))
            }
            // Otherwise, return an error.
            unknown => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame type: {}", unknown),
            )),
        }
    }
}
