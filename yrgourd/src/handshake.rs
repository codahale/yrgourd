use lockstitch::{Protocol, TAG_LEN};

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// The length of an initiator's request in bytes.
pub const REQUEST_LEN: usize = PUBLIC_KEY_LEN + PUBLIC_KEY_LEN + TAG_LEN;

/// The length of an responder's response in bytes.
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN + TAG_LEN;

/// Begins a handshake, returning a [`Protocol`] and an opaque array of bytes to be sent to the
/// responder.
pub fn initiate(is: &PrivateKey, ie: &PrivateKey, rs: &PublicKey) -> (Protocol, [u8; REQUEST_LEN]) {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Allocate and split a request buffer.
    let mut resp = [0u8; REQUEST_LEN];
    let (resp_ie, resp_is) = resp.split_at_mut(PUBLIC_KEY_LEN);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"rs", &rs.encoded);

    // Mix the initiator's ephemeral public key into the protocol.
    resp_ie.copy_from_slice(&ie.public_key.encoded);
    yr.mix(b"re", resp_ie);

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"ie-rs", &(ie.d * rs.q).encode());

    // Seal the initiator's static public key.
    resp_is[..PUBLIC_KEY_LEN].copy_from_slice(&is.public_key.encoded);
    yr.seal(b"is", resp_is);

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"is-rs", &(is.d * rs.q).encode());

    (yr, resp)
}

/// Accepts a handshake given the initiator's request. If valid, returns the initiator's public key,
/// a protocol, and a response to be sent to the initiator.
pub fn accept(
    rs: &PrivateKey,
    re: &PrivateKey,
    mut req: [u8; REQUEST_LEN],
) -> Option<(PublicKey, (Protocol, Protocol), [u8; RESPONSE_LEN])> {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Split the request buffer.
    let (req_ie, req_is) = req.split_at_mut(PUBLIC_KEY_LEN);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"rs", &rs.public_key.encoded);

    // Mix the initiator's ephemeral public key into the protocol and parse it.
    yr.mix(b"re", req_ie);
    let ie = PublicKey::try_from(<&[u8]>::from(req_ie)).ok()?;

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"ie-rs", &(ie.q * rs.d).encode());

    // Open and decode the initiator's static public key.
    let is = PublicKey::try_from(yr.open(b"is", req_is)?).ok()?;

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"is-rs", &(is.q * rs.d).encode());

    // Allocate and split a response buffer.
    let mut resp = [0u8; RESPONSE_LEN];

    // Encrypt the responder's ephemeral public key.
    resp[..PUBLIC_KEY_LEN].copy_from_slice(&re.public_key.encoded);
    yr.seal(b"re", &mut resp);

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"ie-re", &(ie.q * re.d).encode());

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"is-re", &(is.q * re.d).encode());

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix(b"sender", b"initiator");
    send.mix(b"sender", b"responder");

    Some((is, (recv, send), resp))
}

/// Finalizes an initiated handshake given the responder's response. If valid, returns a `(recv,
/// send)` pair of [`Protocol`]s for transport.
pub fn finalize(
    is: &PrivateKey,
    ie: &PrivateKey,
    mut yr: Protocol,
    mut req: [u8; RESPONSE_LEN],
) -> Option<(Protocol, Protocol)> {
    // Decrypt and decode the responder's ephemeral public key.
    let re = PublicKey::try_from(yr.open(b"re", &mut req)?).ok()?;

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"ie-re", &(ie.d * re.q).encode());

    // Calculate the shared secret and mix it into the protocol.
    yr.mix(b"is-re", &(is.d * re.q).encode());

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix(b"sender", b"responder");
    send.mix(b"sender", b"initiator");

    Some((recv, send))
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);

        let (yr_init, req) =
            initiate(&initiator_static, &initiator_ephemeral, &responder_static.public_key);

        let (pk, (mut responder_recv, mut responder_send), resp) =
            accept(&responder_static, &responder_ephemeral, req)
                .expect("should begin successfully");
        assert_eq!(initiator_static.public_key, pk);

        let (mut initiator_recv, mut initiator_send) =
            finalize(&initiator_static, &initiator_ephemeral, yr_init, resp)
                .expect("should finalize successfully");

        assert_eq!(
            responder_recv.derive_array::<8>(b"test"),
            initiator_send.derive_array::<8>(b"test")
        );
        assert_eq!(
            initiator_recv.derive_array::<8>(b"test"),
            responder_send.derive_array::<8>(b"test")
        );
    }

    #[test]
    fn fuzz_accept() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);

        bolero::check!().with_type().cloned().for_each(|req| {
            assert!(accept(&responder_static, &responder_ephemeral, req).is_none());
        });
    }

    #[test]
    fn fuzz_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);
        let responder_static = PrivateKey::random(&mut rng);

        let (yr, _) =
            initiate(&initiator_static, &initiator_ephemeral, &responder_static.public_key);

        bolero::check!().with_type().cloned().for_each(|resp| {
            assert!(finalize(&initiator_static, &initiator_ephemeral, yr.clone(), resp).is_none());
        });
    }
}
