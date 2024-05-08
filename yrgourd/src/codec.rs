use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use fips203::{
    ml_kem_768,
    traits::{Decaps, Encaps, SerDes},
};
use lockstitch::{Protocol, TAG_LEN};
use rand_core::CryptoRngCore;
use tokio::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::keys::{PrivateKey, PublicKey};

const RATCHET_PAYLOAD_LEN: usize = 1088 + 32;

/// A duplex codec for encrypted frames. Each frame has an encrypted 3-byte big-endian length
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
    R: CryptoRngCore,
{
    /// Creates a new [`Codec`] with the local party's private key, the remote party's public key,
    /// a pair of `recv` and `send` [`Protocol`] values, the maximum time between ratchets and the
    /// maximum number of bytes between ratchets.
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
                .big_endian()
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
    R: CryptoRngCore,
{
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Decrement the ratchet data counter.
        self.next_ratchet_at_bytes = self.next_ratchet_at_bytes.saturating_sub(item.len() as u64);

        // Check to see if we need to ratchet the protocol state.
        let (ratchet, frame_type) = if self.next_ratchet_at_bytes == 0
            || self.next_ratchet_at_time < Instant::now()
        {
            // Reset the ratchet data counter and timestamp.
            self.next_ratchet_at_bytes = self.max_ratchet_bytes;
            self.next_ratchet_at_time = Instant::now() + self.max_ratchet_time;

            // Generate a new ephemeral X25519 private key.
            let dk = x25519_dalek::EphemeralSecret::random_from_rng(&mut self.rng);
            let ek = x25519_dalek::PublicKey::from(&dk);

            // Generate a new ML-KEM-768 encapsulated key.
            let (ss, ct) =
                self.remote.ek_pq.try_encaps_with_rng(&mut self.rng).expect("should encapsulate");

            // Collect the X25519 key pair and the ML-KEM-768 ciphertext/shared secret pair.
            (Some((dk, ek, ct.into_bytes(), ss.into_bytes())), FrameType::KeyAndData)
        } else {
            (None, FrameType::Data)
        };

        // Calculate and validate the full frame length.
        let n = frame_type.len() + item.len() + TAG_LEN;
        if n > MAX_FRAME_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize frame"));
        }

        // Reserve enough capacity for the length field and the full frame.
        dst.reserve(LENGTH_FIELD_LEN + n);

        // Encode the length field as a 3-byte big endian integer and then encrypt it.
        let mut buf = (n as u32).to_be_bytes();
        self.send.encrypt("len", &mut buf[4 - LENGTH_FIELD_LEN..]);
        dst.extend_from_slice(&buf[4 - LENGTH_FIELD_LEN..]);

        // Add the frame type, the ratchet payload, the payload, and an empty tag, then seal it.
        self.buf.reserve(n);
        self.buf.put_u8(frame_type.into());
        if let Some((_, ek, ct, _)) = ratchet.as_ref() {
            // Send the X25519 public key and the ML-KEM-768 ciphertext.
            self.buf.extend_from_slice(ek.as_bytes());
            self.buf.extend_from_slice(ct);
        };
        self.buf.extend_from_slice(&item);
        self.buf.extend_from_slice(&[0u8; TAG_LEN]);
        self.send.seal("frame", &mut self.buf);

        // Append the sealed frame data and reset the buffer.
        dst.extend_from_slice(&self.buf);
        self.buf.clear();

        // Ratchet the protocol state, if needed.
        if let Some((dk, _, _, ss)) = ratchet {
            self.send.mix("ratchet-x25519", dk.diffie_hellman(&self.remote.ek_c).as_bytes());
            self.send.mix("ratchet-ml-kem-768", &ss);
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
            self.recv.decrypt("len", &mut src[..LENGTH_FIELD_LEN]);
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
        if self.recv.open("frame", &mut data).is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ciphertext"));
        }
        data.truncate(data.len() - TAG_LEN);

        // Parse the frame type and handle the data.
        match FrameType::try_from(data.split_to(1)[0]) {
            Ok(FrameType::Data) => Ok(Some(data)), // Just return the frame's payload.
            Ok(FrameType::KeyAndData) => {
                // Split off and decode the ratchet payload.
                let ratchet = data.split_to(RATCHET_PAYLOAD_LEN);
                let (ek, ct) = ratchet.split_at(32);
                let ek = x25519_dalek::PublicKey::from(
                    <[u8; 32]>::try_from(ek).expect("should be 32 bytes"),
                );
                let ct = ml_kem_768::CipherText::try_from_bytes(
                    ct.try_into().expect("should be 1088 bytes"),
                )
                .expect("should be valid ciphertext");
                let ss = self.local.dk_pq.try_decaps(&ct).expect("should decapsulate");

                // Mix the ratchet shared secret into the recv protocol.
                self.recv.mix("ratchet-x25519", self.local.dk_c.diffie_hellman(&ek).as_bytes());
                self.recv.mix("ratchet-ml-kem-768", &ss.into_bytes());

                // Return the frame's payload.
                Ok(Some(data))
            }
            Err(unknown) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame type {unknown}"),
            )),
        }
    }
}

const LENGTH_FIELD_LEN: usize = 3; // use a 24-bit length field to cap frames at 16MiB
const MAX_FRAME_LEN: usize = 1 << (LENGTH_FIELD_LEN * 8);

/// The types of frames which can be sent and received.
#[derive(Debug)]
enum FrameType {
    /// Purely data.
    Data = 0x01,
    /// A public key for ratcheting and data.
    KeyAndData = 0x02,
}

impl FrameType {
    const fn len(&self) -> usize {
        1 + match self {
            FrameType::Data => 0,
            FrameType::KeyAndData => RATCHET_PAYLOAD_LEN,
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
