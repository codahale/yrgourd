use bytes::{Bytes, BytesMut};
use lockstitch::{Protocol, TAG_LEN};
use tokio::io;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

pub struct Codec {
    recv: Protocol,
    send: Protocol,
    codec: LengthDelimitedCodec,
}

impl Codec {
    pub fn new(recv: Protocol, send: Protocol) -> Codec {
        Codec {
            recv,
            send,
            codec: LengthDelimitedCodec::builder()
                .little_endian()
                .length_field_length(3)
                .new_codec(),
        }
    }
}

impl Encoder<Bytes> for Codec {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut ciphertext = BytesMut::with_capacity(item.len() + TAG_LEN);
        ciphertext.extend_from_slice(&item);
        ciphertext.extend_from_slice(&[0u8; TAG_LEN]);
        self.send.seal(b"message", &mut ciphertext);
        self.codec.encode(Bytes::from(ciphertext), dst)
    }
}

impl Decoder for Codec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(mut item) = self.codec.decode(src)? else {
            return Ok(None);
        };

        if item.len() < TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ciphertext"));
        }

        let Some(len) = self.recv.open(b"message", &mut item).map(|p| p.len()) else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ciphertext"));
        };

        Ok(Some(item.split_to(len)))
    }
}
