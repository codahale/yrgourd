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
pub struct Codec {
    sender: PrivateKey,
    receiver: PublicKey,
    recv: Protocol,
    send: Protocol,
    codec: LengthDelimitedCodec,
    ratchet: Option<PrivateKey>,
}

impl Codec {
    /// Create a new [`Codec`] with the sender's private key, the receiver's public key, and the
    /// given `recv` and `send` protocols.
    pub fn new(sender: PrivateKey, receiver: PublicKey, recv: Protocol, send: Protocol) -> Codec {
        Codec {
            sender,
            receiver,
            recv,
            send,
            codec: LengthDelimitedCodec::builder()
                .little_endian()
                .length_field_length(3)
                .new_codec(),
            ratchet: None,
        }
    }

    /// Generate an ephemeral key pair and use it to ratchet the `send` protocol after the next
    /// frame is sent.
    pub fn ratchet(&mut self, rng: impl RngCore + CryptoRng) {
        if self.ratchet.is_some() {
            return;
        }
        self.ratchet = Some(PrivateKey::random(rng));
    }
}

impl Encoder<Bytes> for Codec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Pop any ephemeral key off for ratcheting.
        let ratchet = self.ratchet.take();

        let mut output = if let Some(ref ephemeral) = ratchet {
            // If there is an ephemeral key, prepend the DATA_WITH_KEY message code and the
            // ephemeral public key to the data.
            let mut output = BytesMut::with_capacity(1 + 32 + item.len() + TAG_LEN);
            output.put_u8(DATA_WITH_KEY);
            output.extend_from_slice(&ephemeral.public_key.encoded);
            output
        } else {
            // Otherwise, prepend the DATA message code.
            let mut output = BytesMut::with_capacity(1 + item.len() + TAG_LEN);
            output.put_u8(DATA);
            output
        };

        // Append the actual data and room for an authenticator tag.
        output.extend_from_slice(&item);
        output.extend_from_slice(&[0u8; TAG_LEN]);

        // Seal the whole message.
        self.send.seal(b"message", &mut output);

        // Do any necessary ratcheting after the message has been sealed.
        if let Some(ephemeral) = ratchet {
            self.send.mix(b"ratchet-shared", (ephemeral.d * self.receiver.q).compress().as_bytes());
        }

        // Prepend the length delimiter for the frame.
        self.codec.encode(Bytes::from(output), dst)
    }
}

impl Decoder for Codec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // If there is no full frame to process, exit early.
        let Some(mut item) = self.codec.decode(src)? else {
            return Ok(None);
        };

        // Open the sealed frame as long as it's as longer than an authenticator tag. It must be at
        // least one byte long.
        let Some(len) = (item.len() > TAG_LEN)
            .then_some(&mut item)
            .and_then(|i| self.recv.open(b"message", i).map(|p| p.len()))
        else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ciphertext"));
        };

        // Remove the tag.
        item.truncate(len);

        // Remove the message type.
        let message_type = item.split_to(1)[0];
        if message_type == DATA {
            // If it's just data, return it.
            Ok(Some(item))
        } else if message_type == DATA_WITH_KEY {
            // If it's data with a key, parse the key and if possible, ratchet the recv protocol with
            // the ephemeral shared secret.
            if let Ok(pk) = PublicKey::try_from(item.split_to(32).as_ref()) {
                self.recv.mix(b"ratchet-shared", (self.sender.d * pk.q).compress().as_bytes());
            }
            // Return the data without the key.
            Ok(Some(item))
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "invalid message type"))
        }
    }
}
