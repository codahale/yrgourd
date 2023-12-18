use std::collections::HashSet;

use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand_core::CryptoRngCore;

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// The length of an encoded request in bytes.
pub const REQUEST_LEN: usize = PUBLIC_KEY_LEN + PUBLIC_KEY_LEN + 32 + 32;

/// The length of an encoded response in bytes.
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN + 32 + 32;

/// Initiates a handshake, returning a [`Protocol`] and an opaque array of bytes to be sent to the
/// responder.
pub fn initiate(
    initiator: &PrivateKey,
    responder: &PublicKey,
    mut rng: impl CryptoRngCore,
) -> (Protocol, [u8; REQUEST_LEN]) {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Allocate and split a request buffer.
    let mut req = [0u8; REQUEST_LEN];
    let (ephemeral_pub, static_pub) = req.split_at_mut(PUBLIC_KEY_LEN);
    let (static_pub, i_enc) = static_pub.split_at_mut(PUBLIC_KEY_LEN);
    let (i_enc, s_enc) = i_enc.split_at_mut(32);

    // Generate an ephemeral private key.
    let ephemeral = PrivateKey::random(&mut rng);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"responder-static-pub", &responder.encoded);

    // Mix the initiator's ephemeral public key into the protocol.
    ephemeral_pub.copy_from_slice(&ephemeral.public_key.encoded);
    yr.mix(b"initiator-ephemeral-pub", ephemeral_pub);

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let ephemeral_shared = (responder.q * ephemeral.d).compress().to_bytes();
    yr.mix(b"initiator-ephemeral-shared", &ephemeral_shared);

    // Encrypt the initiator's static public key.
    static_pub.copy_from_slice(&initiator.public_key.encoded);
    yr.encrypt(b"initiator-static-pub", static_pub);

    // Calculate the static shared secret and mix it into the protocol.
    let static_shared = (responder.q * initiator.d).compress().to_bytes();
    yr.mix(b"static-shared", &static_shared);

    // Generate a hedged commitment scalar and commitment point.
    let k = yr.hedge(&mut rng, &[initiator.d.as_bytes()], 10_000, |clone| {
        Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
    });
    let i = RistrettoPoint::mul_base(&k);

    // Encode and encrypt the commitment point of the initiator's signature.
    i_enc.copy_from_slice(i.compress().as_bytes());
    yr.encrypt(b"initiator-commitment-point", i_enc);

    // Derive a challenge scalar for the initiator's signature.
    let r = Scalar::from_bytes_mod_order_wide(&yr.derive_array(b"initiator-challenge-scalar"));

    // Calculate and encrypt the proof scalar for the initiator's signature.
    s_enc.copy_from_slice(((initiator.d * r) + k).as_bytes());
    yr.encrypt(b"initiator-proof-scalar", s_enc);

    // Send the initiator's ephemeral public key, the initiator's encrypted static public key,
    // and the two signature components: the encrypted commitment point and the encrypted proof
    // scalar.
    (yr, req)
}

/// Accepts a handshake given the initiator's request. If valid, returns the initiator's public key,
/// a `(recv, send)` pair of [`Protocol`]s for transport, and a response to be sent to the
/// initiator.
pub fn accept(
    responder: &PrivateKey,
    allowed_initiators: Option<&HashSet<PublicKey>>,
    mut rng: impl CryptoRngCore,
    mut req: [u8; REQUEST_LEN],
) -> Option<(PublicKey, Protocol, Protocol, [u8; RESPONSE_LEN])> {
    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Split the request buffer.
    let (ephemeral_pub, static_pub) = req.split_at_mut(PUBLIC_KEY_LEN);
    let (static_pub, i) = static_pub.split_at_mut(PUBLIC_KEY_LEN);
    let (i, s) = i.split_at_mut(32);

    // Mix the responder's static public key into the protocol.
    yr.mix(b"responder-static-pub", &responder.public_key.encoded);

    // Mix the initiator's ephemeral public key into the protocol and parse it.
    yr.mix(b"initiator-ephemeral-pub", ephemeral_pub);
    let ephemeral_pub = CompressedRistretto::from_slice(ephemeral_pub).ok()?.decompress()?;

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let ephemeral_shared = (ephemeral_pub * responder.d).compress().to_bytes();
    yr.mix(b"initiator-ephemeral-shared", &ephemeral_shared);

    // Decrypt and parse the initiator's static public key.
    yr.decrypt(b"initiator-static-pub", static_pub);
    let static_pub = PublicKey::try_from(<&[u8]>::from(static_pub)).ok()?;

    // If initiators are restricted, check that the initiator is in the allowed set.
    if allowed_initiators.is_some_and(|keys| !keys.contains(&static_pub)) {
        return None;
    }

    // Calculate the static shared secret and mix it into the protocol.
    let static_shared = (static_pub.q * responder.d).compress().to_bytes();
    yr.mix(b"static-shared", &static_shared);

    // Decrypt the initiator's encoded commitment point of the initiator's signature.
    yr.decrypt(b"initiator-commitment-point", i);

    // Derive the counterfactual challenge scalar for the initiator's signature.
    let r_p = Scalar::from_bytes_mod_order_wide(&yr.derive_array(b"initiator-challenge-scalar"));

    // Decrypt and decode the proof scalar of the initiator's signature.
    yr.decrypt(b"initiator-proof-scalar", s);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        s.try_into().expect("should be 32 bytes"),
    ))?;

    // Verify the initiator's signature and early exit if invalid.
    if !verify(i, &r_p, &static_pub.q, &s) {
        return None;
    }

    // Allocate and split a response buffer.
    let mut resp = [0u8; RESPONSE_LEN];
    let (ephemeral_pub, i) = resp.split_at_mut(PUBLIC_KEY_LEN);
    let (i_enc, s_enc) = i.split_at_mut(32);

    // Generate an ephemeral key pair;
    let ephemeral = PrivateKey::random(&mut rng);

    // Encrypt the responder's ephemeral public key.
    ephemeral_pub.copy_from_slice(&ephemeral.public_key.encoded);
    yr.encrypt(b"responder-ephemeral-pub", ephemeral_pub);

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let ephemeral_shared = (static_pub.q * ephemeral.d).compress().to_bytes();
    yr.mix(b"responder-ephemeral-shared", &ephemeral_shared);

    // Generate a hedged commitment scalar and commitment point.
    let k = yr.hedge(&mut rng, &[responder.d.as_bytes()], 10_000, |clone| {
        Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
    });
    let i = RistrettoPoint::mul_base(&k);

    // Encode and encrypt the commitment point of the responder's signature.
    i_enc.copy_from_slice(i.compress().as_bytes());
    yr.encrypt(b"responder-commitment-point", i_enc);

    // Derive a challenge scalar for the responder's signature.
    let r = Scalar::from_bytes_mod_order_wide(&yr.derive_array(b"responder-challenge-scalar"));

    // Calculate and encrypt the proof scalar for the responder's signature.
    s_enc.copy_from_slice(((responder.d * r) + k).as_bytes());
    yr.encrypt(b"responder-proof-scalar", s_enc);

    // Fork the protocol into recv and send clones.
    let mut recv = yr.clone();
    recv.mix(b"sender", b"initiator");
    let mut send = yr.clone();
    send.mix(b"sender", b"responder");

    // Return the initiator's public key, recv and send protocols, and a response to the
    // initiator.
    Some((static_pub, recv, send, resp))
}

/// Finalizes an initiated handshake given the responder's response. If valid, returns a `(recv,
/// send)` pair of [`Protocol`]s for transport.
pub fn finalize(
    initiator: &PrivateKey,
    responder: &PublicKey,
    mut yr: Protocol,
    mut resp: [u8; RESPONSE_LEN],
) -> Option<(Protocol, Protocol)> {
    // Split the response into its components.
    let (ephemeral_pub, i) = resp.split_at_mut(PUBLIC_KEY_LEN);
    let (i, s) = i.split_at_mut(32);

    // Decrypt the responder's ephemeral public key.
    yr.decrypt(b"responder-ephemeral-pub", ephemeral_pub);
    let ephemeral_pub = PublicKey::try_from(<&[u8]>::from(ephemeral_pub)).ok()?;

    // Calculate the ephemeral shared secret and mix it into the protocol.
    let ephemeral_shared = (initiator.d * ephemeral_pub.q).compress().to_bytes();
    yr.mix(b"responder-ephemeral-shared", &ephemeral_shared);

    // Decrypt the initiator's encoded commitment point of the responder's signature.
    yr.decrypt(b"responder-commitment-point", i);

    // Derive the counterfactual challenge scalar for the responder's signature.
    let r_p = Scalar::from_bytes_mod_order_wide(&yr.derive_array(b"responder-challenge-scalar"));

    // Decrypt and decode the proof scalar of the responder's signature.
    yr.decrypt(b"responder-proof-scalar", s);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        s.try_into().expect("should be 32 bytes"),
    ))?;

    // Verify the responder's signature and early exit if invalid.
    if !verify(i, &r_p, &responder.q, &s) {
        return None;
    }

    // Fork the protocol into recv and send clones.
    let mut recv = yr.clone();
    recv.mix(b"sender", b"responder");
    let mut send = yr;
    send.mix(b"sender", b"initiator");

    Some((recv, send))
}

/// Given an encoded commitment point `I`, a counterfactual challenge scalar `r′`, a public key `Q`,
/// and a proof scalar `s`, returns true iff `I == [s]G - [r']Q`. Compares the encoded forms of `I`
/// and `I′` for performance and security.
fn verify(i: &[u8], r_p: &Scalar, q: &RistrettoPoint, s: &Scalar) -> bool {
    RistrettoPoint::vartime_double_scalar_mul_basepoint(r_p, &-q, s).compress().as_bytes() == i
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder = PrivateKey::random(&mut rng);
        let initiator = PrivateKey::random(&mut rng);

        let (yr, req) = initiate(&initiator, &responder.public_key, &mut rng);

        let (pk, mut responder_recv, mut responder_send, resp) =
            accept(&responder, None, &mut rng, req)
                .expect("should handle initiator request successfully");
        assert_eq!(initiator.public_key, pk);

        let (mut initiator_recv, mut initiator_send) =
            finalize(&initiator, &responder.public_key, yr, resp)
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
        let responder = PrivateKey::random(&mut rng);
        let initiator = PrivateKey::random(&mut rng);

        let mut allowed_initiators = HashSet::new();
        allowed_initiators.insert(initiator.public_key);

        let (yr, req) = initiate(&initiator, &responder.public_key, &mut rng);
        let (pk, mut responder_recv, mut responder_send, resp) =
            accept(&responder, Some(&allowed_initiators), &mut rng, req)
                .expect("should handle initiator request successfully");
        assert_eq!(initiator.public_key, pk);

        let (mut initiator_recv, mut initiator_send) =
            finalize(&initiator, &responder.public_key, yr, resp)
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
        let responder = PrivateKey::random(&mut rng);
        let initiator = PrivateKey::random(&mut rng);
        let bad_initiator = PrivateKey::random(&mut rng);

        let mut allowed_initiators = HashSet::new();
        allowed_initiators.insert(initiator.public_key);

        let (_, req) = initiate(&bad_initiator, &responder.public_key, &mut rng);
        assert!(
            accept(&responder, Some(&allowed_initiators), &mut rng, req).is_none(),
            "should not allow a handshake with an initiator not in the set"
        );
    }

    #[test]
    fn fuzz_responder_respond() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder = PrivateKey::random(rng);

        bolero::check!().with_type::<(u64, [u8; REQUEST_LEN])>().cloned().for_each(
            |(seed, req)| {
                let mut rng = ChaChaRng::seed_from_u64(seed);
                assert!(accept(&responder, None, &mut rng, req).is_none());
            },
        );
    }

    #[test]
    fn fuzz_initiator_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder = PrivateKey::random(&mut rng);
        let initiator = PrivateKey::random(&mut rng);

        let (yr, _) = initiate(&initiator, &responder.public_key, &mut rng);

        bolero::check!().with_type::<[u8; RESPONSE_LEN]>().cloned().for_each(|resp| {
            assert!(finalize(&initiator, &responder.public_key, yr.clone(), resp).is_none());
        });
    }
}
