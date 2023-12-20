use std::collections::HashSet;

use crrl::gls254::{Point, Scalar};
use lockstitch::Protocol;

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// The length of an encoded request in bytes.
pub const REQUEST_LEN: usize = PUBLIC_KEY_LEN + PUBLIC_KEY_LEN;

/// The length of an encoded response in bytes.
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN;

/// Initiates a handshake, returning a [`Protocol`] and an opaque array of bytes to be sent to the
/// responder.
pub fn initiate(
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

/// Accepts a handshake given the initiator's request. If valid, returns the initiator's public key,
/// a `(recv, send)` pair of [`Protocol`]s for transport, and a response to be sent to the
/// initiator.
pub fn accept(
    responder_static: &PrivateKey,
    responder_ephemeral: &PrivateKey,
    allowed_initiators: Option<&HashSet<PublicKey>>,
    mut req: [u8; REQUEST_LEN],
) -> Option<(PublicKey, Protocol, Protocol, [u8; RESPONSE_LEN])> {
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

    // If initiators are restricted, check that the initiator is in the allowed set.
    if allowed_initiators.is_some_and(|keys| !keys.contains(&initiator_static)) {
        return None;
    }

    // Allocate and split a response buffer.
    let mut resp = [0u8; RESPONSE_LEN];

    // Encrypt the responder's ephemeral public key.
    resp.copy_from_slice(&responder_ephemeral.public_key.encoded);
    yr.encrypt(b"responder-ephemeral-pub", &mut resp);

    // Calculate and mix in the shared secret: g^((x+da)(y+eb))
    let shared_secret = fhmqv_resp(
        &initiator_static.q,
        &initiator_ephemeral,
        &responder_static.d,
        &responder_ephemeral.d,
        Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-d"))),
        Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-e"))),
    );
    yr.mix(b"shared-secret", &shared_secret.encode());

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix(b"sender", b"initiator");
    send.mix(b"sender", b"responder");

    // Return the initiator's public key, recv and send protocols, and a response to the
    // initiator.
    Some((initiator_static, recv, send, resp))
}

/// Finalizes an initiated handshake given the responder's response. If valid, returns a `(recv,
/// send)` pair of [`Protocol`]s for transport.
pub fn finalize(
    initiator_static: &PrivateKey,
    initiator_ephemeral: &PrivateKey,
    responder_static: &PublicKey,
    mut yr: Protocol,
    mut resp: [u8; RESPONSE_LEN],
) -> Option<(Protocol, Protocol)> {
    // Decrypt the responder's ephemeral public key.
    yr.decrypt(b"responder-ephemeral-pub", &mut resp);
    let responder_ephemeral = PublicKey::try_from(<&[u8]>::from(&resp)).ok()?;

    // Calculate and mix in the shared secret: g^((x+da)(y+eb))
    let shared_secret = fhmqv_init(
        &responder_static.q,
        &responder_ephemeral.q,
        &initiator_static.d,
        &initiator_ephemeral.d,
        Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-d"))),
        Scalar::from_u128(u128::from_le_bytes(yr.derive_array(b"challenge-scalar-e"))),
    );
    yr.mix(b"shared-secret", &shared_secret.encode());

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix(b"sender", b"responder");
    send.mix(b"sender", b"initiator");

    Some((recv, send))
}

#[inline]
fn fhmqv_init(g_b: &Point, g_y: &Point, a: &Scalar, x: &Scalar, d: Scalar, e: Scalar) -> Point {
    (g_y + (g_b * e)) * (x + d * a)
}

#[inline]
fn fhmqv_resp(g_a: &Point, g_x: &Point, b: &Scalar, y: &Scalar, d: Scalar, e: Scalar) -> Point {
    (g_x + (g_a * d)) * (y + e * b)
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

        let (yr, req) =
            initiate(&initiator_static, &initiator_ephemeral, &responder_static.public_key);

        let (pk, mut responder_recv, mut responder_send, resp) =
            accept(&responder_static, &responder_ephemeral, None, req)
                .expect("should handle initiator request successfully");
        assert_eq!(initiator_static.public_key, pk);

        let (mut initiator_recv, mut initiator_send) = finalize(
            &initiator_static,
            &initiator_ephemeral,
            &responder_static.public_key,
            yr,
            resp,
        )
        .expect("should handle responder response successfully");

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
    fn allowed_initiator() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);

        let mut allowed_initiators = HashSet::new();
        allowed_initiators.insert(initiator_static.public_key);

        let (yr, req) =
            initiate(&initiator_static, &initiator_ephemeral, &responder_static.public_key);
        let (pk, mut responder_recv, mut responder_send, resp) =
            accept(&responder_static, &responder_ephemeral, Some(&allowed_initiators), req)
                .expect("should handle initiator request successfully");
        assert_eq!(initiator_static.public_key, pk);

        let (mut initiator_recv, mut initiator_send) = finalize(
            &initiator_static,
            &initiator_ephemeral,
            &responder_static.public_key,
            yr,
            resp,
        )
        .expect("should handle responder response successfully");

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
    fn restricted_initiator() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);
        let bad_initiator = PrivateKey::random(&mut rng);

        let mut allowed_initiators = HashSet::new();
        allowed_initiators.insert(initiator_static.public_key);

        let (_, req) = initiate(&bad_initiator, &initiator_ephemeral, &responder_static.public_key);
        assert!(
            accept(&responder_static, &responder_ephemeral, Some(&allowed_initiators), req)
                .is_none(),
            "should not allow a handshake with an initiator not in the set"
        );
    }

    #[test]
    fn fuzz_responder_respond() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);

        bolero::check!().with_type::<[u8; REQUEST_LEN]>().cloned().for_each(|req| {
            // It doesn't matter if the handshake is accepted, since the key confirmation happens
            // via the first frame of data.
            let _ = accept(&responder_static, &responder_ephemeral, None, req);
        });
    }

    #[test]
    fn fuzz_initiator_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);
        let responder_ephemeral = PrivateKey::random(&mut rng);
        let initiator_static = PrivateKey::random(&mut rng);
        let initiator_ephemeral = PrivateKey::random(&mut rng);

        let (yr_init, req) =
            initiate(&initiator_static, &initiator_ephemeral, &responder_static.public_key);
        let (_, _, _, resp) = accept(&responder_static, &responder_ephemeral, None, req)
            .expect("regular handshake should succeed");
        let (mut init_recv, mut init_send) = finalize(
            &initiator_static,
            &initiator_ephemeral,
            &responder_static.public_key,
            yr_init.clone(),
            resp,
        )
        .expect("regular handshake should succeed");

        let init_recv_good = init_recv.derive_array::<8>(b"test");
        let init_send_good = init_send.derive_array::<8>(b"test");

        bolero::check!().with_type::<[u8; RESPONSE_LEN]>().cloned().for_each(|resp| {
            // If the responder sends gibberish, the response may actually produce a valid point.
            // That's ok, because the key confirmation happens on the first frame.
            if let Some((mut init_recv, mut init_send)) = finalize(
                &initiator_static,
                &initiator_ephemeral,
                &responder_static.public_key,
                yr_init.clone(),
                resp,
            ) {
                // If the responder sends gibberish, key confirmation should absolutely not succeed.
                assert_ne!(init_recv_good, init_recv.derive_array::<8>(b"test"));
                assert_ne!(init_send_good, init_send.derive_array::<8>(b"test"));
            }
        });
    }
}
