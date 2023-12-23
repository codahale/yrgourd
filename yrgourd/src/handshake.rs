use crrl::gls254::{Point, Scalar};
use lockstitch::{subtle::ConstantTimeEq, Protocol, TAG_LEN};

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// The length of an encoded request in bytes.
pub const REQUEST_LEN: usize = PUBLIC_KEY_LEN + PUBLIC_KEY_LEN;

/// The length of an encoded response in bytes.
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN + CONFIRM_LEN;

/// The length of a final confirmation tag.
pub const CONFIRM_LEN: usize = TAG_LEN;

/// Initiates a handshake, returning a [`Protocol`] and an opaque array of bytes to be sent to the
/// responder.
pub fn initiator_begin(
    initiator_static: &PrivateKey,
    initiator_ephemeral: &PrivateKey,
    responder: &PublicKey,
) -> (Protocol, [u8; REQUEST_LEN]) {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Allocate and split a request buffer.
    let mut req = [0u8; REQUEST_LEN];
    let (ephemeral_pub, static_pub) = req.split_at_mut(PUBLIC_KEY_LEN);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"responder-static-pub", &responder.encoded);

    // Mix the initiator's ephemeral public key into the protocol.
    ephemeral_pub.copy_from_slice(&initiator_ephemeral.public_key.encoded);
    yr.mix(b"initiator-ephemeral-pub", ephemeral_pub);

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let ephemeral_shared = (responder.q * initiator_ephemeral.d).encode();
    yr.mix(b"ecdh-shared-secret", &ephemeral_shared);

    // Encrypt the initiator's static public key.
    static_pub.copy_from_slice(&initiator_static.public_key.encoded);
    yr.encrypt(b"initiator-static-pub", static_pub);

    // Send the initiator's ephemeral public key and the initiator's encrypted static public key.
    (yr, req)
}

/// Accepts a handshake given the initiator's request. If valid, returns the initiator's public key
/// and a response to be sent to the initiator.
pub fn responder_begin(
    responder_static: &PrivateKey,
    responder_ephemeral: &PrivateKey,
    mut req: [u8; REQUEST_LEN],
) -> Option<(PublicKey, Protocol, [u8; RESPONSE_LEN])> {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Split the request buffer.
    let (initiator_ephemeral, initiator_static) = req.split_at_mut(PUBLIC_KEY_LEN);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"responder-static-pub", &responder_static.public_key.encoded);

    // Mix the initiator's ephemeral public key into the protocol and parse it.
    yr.mix(b"initiator-ephemeral-pub", initiator_ephemeral);
    let initiator_ephemeral = Point::decode(initiator_ephemeral)?;

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let ephemeral_shared = (initiator_ephemeral * responder_static.d).encode();
    yr.mix(b"ecdh-shared-secret", &ephemeral_shared);

    // Decrypt and parse the initiator's static public key.
    yr.decrypt(b"initiator-static-pub", initiator_static);
    let initiator_static = PublicKey::try_from(<&[u8]>::from(initiator_static)).ok()?;

    // Allocate and split a response buffer.
    let mut resp = [0u8; RESPONSE_LEN];
    let (ephemeral, confirm) = resp.split_at_mut(PUBLIC_KEY_LEN);

    // Encrypt the responder's ephemeral public key.
    ephemeral.copy_from_slice(&responder_ephemeral.public_key.encoded);
    yr.encrypt(b"responder-ephemeral-pub", ephemeral);

    // Calculate and mix in the shared secret: (g^y+(g^be))^(x+da)
    let d = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-d")));
    let e = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-e")));
    let shared_secret = (initiator_ephemeral + (initiator_static.q * d))
        * (responder_ephemeral.d + e * responder_static.d);
    yr.mix(b"shared-secret", &shared_secret.encode());

    // Generate an authentication tag.
    yr.derive(b"responder-confirmation", confirm);

    // Return the initiator's public key  and a response to the initiator.
    Some((initiator_static, yr, resp))
}

/// Finalizes an initiated handshake given the responder's response. If valid, returns a `(recv,
/// send)` pair of [`Protocol`]s for transport and a confirmation to be sent to the responder.
pub fn initiator_finalize(
    initiator_static: &PrivateKey,
    initiator_ephemeral: &PrivateKey,
    responder_static: &PublicKey,
    mut yr: Protocol,
    mut resp: [u8; RESPONSE_LEN],
) -> Option<(Protocol, Protocol, [u8; CONFIRM_LEN])> {
    // Split the response buffer.
    let (ephemeral, confirm) = resp.split_at_mut(PUBLIC_KEY_LEN);

    // Decrypt the responder's ephemeral public key.
    yr.decrypt(b"responder-ephemeral-pub", ephemeral);
    let responder_ephemeral = PublicKey::try_from(<&[u8]>::from(ephemeral)).ok()?;

    // Calculate and mix in the shared secret: g^((x+da)(y+eb))
    let d = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-d")));
    let e = Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-e")));
    let shared_secret = (responder_ephemeral.q + (responder_static.q * e))
        * (initiator_ephemeral.d + d * initiator_static.d);
    yr.mix(b"shared-secret", &shared_secret.encode());

    // Confirm the responder's key.
    let confirm_p = yr.derive_array::<CONFIRM_LEN>(b"responder-confirmation");
    if confirm.ct_ne(&confirm_p).into() {
        return None;
    }

    // Generate a tag confirmation.
    let mut confirm = [0u8; CONFIRM_LEN];
    yr.derive(b"initiator-confirmation", &mut confirm);

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix(b"sender", b"responder");
    send.mix(b"sender", b"initiator");

    Some((recv, send, confirm))
}

/// Finalizes an accepted handshake with the initiator's confirmation. If valid, returns a `(recv,
/// send)` pair of [`Protocol`]s for transport.
pub fn responder_finalize(
    mut yr: Protocol,
    confirm: [u8; CONFIRM_LEN],
) -> Option<(Protocol, Protocol)> {
    // Confirm the initiator's key.
    let confirm_p = yr.derive_array::<CONFIRM_LEN>(b"initiator-confirmation");
    if confirm.ct_ne(&confirm_p).into() {
        return None;
    }

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix(b"sender", b"initiator");
    send.mix(b"sender", b"responder");

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
            initiator_begin(&initiator_static, &initiator_ephemeral, &responder_static.public_key);

        let (pk, yr_resp, resp) = responder_begin(&responder_static, &responder_ephemeral, req)
            .expect("should successfully begin response");
        assert_eq!(initiator_static.public_key, pk);

        let (mut initiator_recv, mut initiator_send, confirm) = initiator_finalize(
            &initiator_static,
            &initiator_ephemeral,
            &responder_static.public_key,
            yr_init,
            resp,
        )
        .expect("should successfully finalize request");

        let (mut responder_recv, mut responder_send) =
            responder_finalize(yr_resp, confirm).expect("should successfully finalize response");

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
    fn fuzz_responder_begin() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);

        bolero::check!().with_type::<[u8; REQUEST_LEN]>().cloned().for_each(|req| {
            // Some random values will decrypt into valid ephemeral public keys. That's ok.
            let _ = responder_begin(&responder_static, &responder_ephemeral, req);
        });
    }

    #[test]
    fn fuzz_initiator_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);

        let (yr_init, _) =
            initiator_begin(&initiator_static, &initiator_ephemeral, &responder_static.public_key);

        bolero::check!().with_type::<[u8; RESPONSE_LEN]>().cloned().for_each(|resp| {
            assert!(initiator_finalize(
                &initiator_static,
                &initiator_ephemeral,
                &responder_static.public_key,
                yr_init.clone(),
                resp,
            )
            .is_none());
        });
    }

    #[test]
    fn fuzz_responder_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);

        let (_, req) =
            initiator_begin(&initiator_static, &initiator_ephemeral, &responder_static.public_key);

        let (_, yr_resp, _) =
            responder_begin(&responder_static, &responder_ephemeral, req).expect("should succeed");

        bolero::check!().with_type::<[u8; CONFIRM_LEN]>().cloned().for_each(|confirm| {
            assert!(responder_finalize(yr_resp.clone(), confirm).is_none());
        });
    }
}
