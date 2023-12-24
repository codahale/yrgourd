use crrl::gls254::Scalar;
use lockstitch::{subtle::ConstantTimeEq, Protocol, TAG_LEN};

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// The length of an encoded request in bytes.
pub const REQUEST_LEN: usize = PUBLIC_KEY_LEN + PUBLIC_KEY_LEN + TAG_LEN;

/// The length of an encoded response in bytes.
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN + TAG_LEN;

/// Initiates a handshake, returning a [`Protocol`] and an opaque array of bytes to be sent to the
/// responder.
pub fn initiate(
    initiator_static: &PrivateKey,
    initiator_ephemeral: &PrivateKey,
    responder_static: &PublicKey,
) -> (Protocol, [u8; REQUEST_LEN]) {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Allocate and split a request buffer.
    let mut req = [0u8; REQUEST_LEN];
    let (ephemeral_pub, static_pub) = req.split_at_mut(PUBLIC_KEY_LEN);
    let (static_pub, tag) = static_pub.split_at_mut(PUBLIC_KEY_LEN);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"responder-static-pub", &responder_static.encoded);

    // Mix the initiator's ephemeral public key into the protocol.
    ephemeral_pub.copy_from_slice(&initiator_ephemeral.public_key.encoded);
    yr.mix(b"initiator-ephemeral-pub", ephemeral_pub);

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let zz = (initiator_ephemeral.d * responder_static.q).encode();
    yr.mix(b"ecdh-shared-secret", &zz);

    // Encrypt the initiator's static public key.
    static_pub.copy_from_slice(&initiator_static.public_key.encoded);
    yr.encrypt(b"initiator-static-pub", static_pub);

    // Calculate the initiator's shared secret: [x+ae]B
    let e = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"initiator-challenge")));
    let k = responder_static.q * (initiator_ephemeral.d + initiator_static.d * e);
    yr.mix(b"initiator-shared-secret", &k.encode());

    // Derive a key confirmation tag.
    yr.derive(b"initiator-confirmation", tag);

    // Send the initiator's ephemeral public key and the initiator's encrypted static public key.
    (yr, req)
}

/// Accepts a handshake given the initiator's request. If valid, returns the initiator's public key,
/// a `(recv, send)` pair of protocols, and a response to be sent to the initiator.
pub fn accept(
    responder_static: &PrivateKey,
    responder_ephemeral: &PrivateKey,
    mut req: [u8; REQUEST_LEN],
) -> Option<(PublicKey, (Protocol, Protocol), [u8; RESPONSE_LEN])> {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Split the request buffer.
    let (initiator_ephemeral, initiator_static) = req.split_at_mut(PUBLIC_KEY_LEN);
    let (initiator_static, initiator_tag) = initiator_static.split_at_mut(PUBLIC_KEY_LEN);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"responder-static-pub", &responder_static.public_key.encoded);

    // Mix the initiator's ephemeral public key into the protocol and parse it.
    yr.mix(b"initiator-ephemeral-pub", initiator_ephemeral);
    let initiator_ephemeral = PublicKey::try_from(<&[u8]>::from(initiator_ephemeral)).ok()?;

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let zz = (responder_static.d * initiator_ephemeral.q).encode();
    yr.mix(b"ecdh-shared-secret", &zz);

    // Decrypt and parse the initiator's static public key.
    yr.decrypt(b"initiator-static-pub", initiator_static);
    let initiator_static = PublicKey::try_from(<&[u8]>::from(initiator_static)).ok()?;

    // Calculate the initiator's shared secret: [b](X+[e]A)
    let e = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"initiator-challenge")));
    let k = (initiator_ephemeral.q + (initiator_static.q * e)) * responder_static.d;
    yr.mix(b"initiator-shared-secret", &k.encode());

    // Check the initiator's key confirmation tag.
    let initiator_tag_p = yr.derive_array::<TAG_LEN>(b"initiator-confirmation");
    if initiator_tag.ct_ne(&initiator_tag_p).into() {
        return None;
    }

    // Allocate and split a response buffer.
    let mut resp = [0u8; RESPONSE_LEN];
    let (ephemeral_pub, tag) = resp.split_at_mut(PUBLIC_KEY_LEN);

    // Encrypt the responder's ephemeral public key.
    ephemeral_pub.copy_from_slice(&responder_ephemeral.public_key.encoded);
    yr.encrypt(b"responder-ephemeral-pub", ephemeral_pub);

    // Calculate the responder's shared secret: [y+ae]B
    let e = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"responder-challenge")));
    let k = initiator_static.q * (responder_ephemeral.d + responder_static.d * e);
    yr.mix(b"responder-shared-secret", &k.encode());

    // Derive a key confirmation tag.
    yr.derive(b"responder-confirmation", tag);

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix(b"sender", b"initiator");
    send.mix(b"sender", b"responder");

    // Return the initiator's public key, a pair of forked protocols, and a response to the initiator.
    Some((initiator_static, (recv, send), resp))
}

/// Finalizes an initiated handshake given the responder's response. If valid, returns a `(recv,
/// send)` pair of [`Protocol`]s for transport.
pub fn finalize(
    initiator_static: &PrivateKey,
    responder_static: &PublicKey,
    mut yr: Protocol,
    mut resp: [u8; RESPONSE_LEN],
) -> Option<(Protocol, Protocol)> {
    // Split the response buffer.
    let (responder_ephemeral, responder_tag) = resp.split_at_mut(PUBLIC_KEY_LEN);

    // Decrypt the responder's ephemeral public key.
    yr.decrypt(b"responder-ephemeral-pub", responder_ephemeral);
    let responder_ephemeral = PublicKey::try_from(<&[u8]>::from(responder_ephemeral)).ok()?;

    // Calculate the responder's shared secret: [a](Y+[e]B)
    let e = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"responder-challenge")));
    let k = (responder_ephemeral.q + (responder_static.q * e)) * initiator_static.d;
    yr.mix(b"responder-shared-secret", &k.encode());

    // Check the responder's key confirmation tag.
    let responder_tag_p = yr.derive_array::<TAG_LEN>(b"responder-confirmation");
    if responder_tag.ct_ne(&responder_tag_p).into() {
        return None;
    }

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
                .expect("should successfully begin response");
        assert_eq!(initiator_static.public_key, pk);

        let (mut initiator_recv, mut initiator_send) =
            finalize(&initiator_static, &responder_static.public_key, yr_init, resp)
                .expect("should successfully finalize request");

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

        bolero::check!().with_type::<[u8; REQUEST_LEN]>().cloned().for_each(|req| {
            assert!(accept(&responder_static, &responder_ephemeral, req).is_none());
        });
    }

    #[test]
    fn fuzz_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);

        let (yr_init, _) =
            initiate(&initiator_static, &initiator_ephemeral, &responder_static.public_key);

        bolero::check!().with_type::<[u8; RESPONSE_LEN]>().cloned().for_each(|resp| {
            assert!(finalize(
                &initiator_static,
                &responder_static.public_key,
                yr_init.clone(),
                resp,
            )
            .is_none());
        });
    }
}
