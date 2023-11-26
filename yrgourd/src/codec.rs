use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use lockstitch::{Protocol, TAG_LEN};
use rand_core::{CryptoRng, RngCore};
use tokio::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// A duplex codec for encrypted frames. Each frame has an encrypted 3-byte little-endian length
/// prefix, then an encrypted payload, then a 16-byte authenticator tag.
#[derive(Debug)]
pub struct Codec<R> {
    rng: R,
    local: PrivateKey,
    remote: PublicKey,
    recv: Protocol,
    send: Protocol,
    codec: LengthDelimitedCodec,
    recv_len: bool,
    buf: BytesMut,
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
        local: PrivateKey,
        remote: PublicKey,
        recv: Protocol,
        send: Protocol,
        max_ratchet_time: Duration,
        max_ratchet_bytes: u64,
    ) -> Codec<R> {
        Codec {
            rng,
            local,
            remote,
            recv,
            send,
            codec: LengthDelimitedCodec::builder()
                .little_endian()
                .length_field_length(LENGTH_FIELD_LEN)
                .max_frame_length(usize::MAX)
                .new_codec(),
            recv_len: false,
            buf: BytesMut::with_capacity(8 * 1024),
            next_ratchet_at_time: Instant::now() + max_ratchet_time,
            next_ratchet_at_bytes: max_ratchet_bytes,
            max_ratchet_bytes,
            max_ratchet_time,
        }
    }
}

impl<R> Encoder<Bytes> for Codec<R>
where
    R: RngCore + CryptoRng,
{
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Decrement the ratchet data counter.
        self.next_ratchet_at_bytes = self.next_ratchet_at_bytes.saturating_sub(item.len() as u64);

        // Check to see if we need to ratchet the protocol state.
        let (ratchet, frame_type) =
            if self.next_ratchet_at_bytes == 0 || self.next_ratchet_at_time < Instant::now() {
                // Reset the ratchet data counter and timestamp.
                self.next_ratchet_at_bytes = self.max_ratchet_bytes;
                self.next_ratchet_at_time = Instant::now() + self.max_ratchet_time;

                // Generate an ephemeral key pair.
                let ephemeral = PrivateKey::random(&mut self.rng);

                (Some(ephemeral), FrameType::KeyAndData)
            } else {
                (None, FrameType::Data)
            };

        // Calculate and validate the full frame length.
        let n = frame_type.len() + item.len() + TAG_LEN;
        if n > 1 << (LENGTH_FIELD_LEN * 8) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize frame"));
        }

        // Reserve enough capacity for the length field and the full frame.
        dst.reserve(LENGTH_FIELD_LEN + n);

        // Encode the length field as a 3-byte little endian integer and then encrypt it.
        let mut length_field = (n as u32).to_le_bytes();
        self.send.encrypt(b"len", &mut length_field[..LENGTH_FIELD_LEN]);
        dst.extend_from_slice(&length_field[..LENGTH_FIELD_LEN]);

        // Copy the frame data to the encoder's buffer, add an empty tag, and seal it.
        self.buf.reserve(n);
        self.buf.put_u8(frame_type.into());
        if let Some(ref ephemeral) = ratchet {
            // Add the ephemeral public key if we're ratcheting.
            self.buf.extend_from_slice(&ephemeral.public_key.encoded);
        };
        self.buf.extend_from_slice(&item);
        self.buf.extend_from_slice(&[0u8; TAG_LEN]);
        self.send.seal(b"frame", &mut self.buf);

        // Append the sealed frame data and reset the buffer.
        dst.extend_from_slice(&self.buf);
        self.buf.clear();

        // Ratchet the protocol state, if needed.
        if let Some(ephemeral) = ratchet {
            self.send.mix(b"ratchet-shared", (ephemeral.d * self.remote.q).compress().as_bytes());
        }

        Ok(())
    }
}

impl<R> Decoder for Codec<R> {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Wait for the length field.
        if src.len() < LENGTH_FIELD_LEN {
            return Ok(None);
        }

        // If the length field hasn't been received yet and we have enough data for it, decrypt the
        // length field in place and flag that it's been received.
        if !self.recv_len {
            self.recv.decrypt(b"len", &mut src[..LENGTH_FIELD_LEN]);
            self.recv_len = true;
        }

        // Use LengthDelimitedCodec to decode the plaintext length field.
        let mut data = match self.codec.decode(src) {
            // If a full frame has been received, reset the length field receipt flag.
            Ok(Some(data)) => {
                self.recv_len = false;
                data
            }
            // Return errors and incomplete frames back to Framed.
            other => return other,
        };

        // Open the frame data and strip the tag or return an error.
        if self.recv.open(b"frame", &mut data).is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ciphertext"));
        }
        data.truncate(data.len() - TAG_LEN);

        // Parse the frame type and handle the data.
        match FrameType::try_from(data.split_to(1)[0]) {
            // If it's data, return the data directly.
            Ok(FrameType::Data) => Ok(Some(data)),
            // If it's a key and data, parse the ephemeral public key and ratchet the recv state.
            Ok(FrameType::KeyAndData) => {
                let ephemeral = data.split_to(PUBLIC_KEY_LEN);
                if let Ok(ephemeral) = PublicKey::try_from(ephemeral.as_ref()) {
                    self.recv
                        .mix(b"ratchet-shared", (self.local.d * ephemeral.q).compress().as_bytes());
                    Ok(Some(data))
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ratchet key"))
                }
            }
            // If it's an unknown frame type, return an error.
            Err(unknown) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame type {unknown}"),
            )),
        }
    }
}

const LENGTH_FIELD_LEN: usize = 3; // use a 24-bit length field to cap frames at 16MiB

/// The types of frames which can be sent and received.
#[derive(Debug)]
enum FrameType {
    /// Purely data.
    Data = 0x01,
    /// An ephemeral public key for ratcheting and data.
    KeyAndData = 0x02,
}

impl FrameType {
    const fn len(&self) -> usize {
        1 + match self {
            FrameType::Data => 0,
            FrameType::KeyAndData => PUBLIC_KEY_LEN,
        }
    }
}

impl From<FrameType> for u8 {
    fn from(value: FrameType) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for FrameType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FrameType::Data),
            0x02 => Ok(FrameType::KeyAndData),
            other => Err(other),
        }
    }
}
