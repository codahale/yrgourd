use std::collections::HashSet;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand_core::CryptoRngCore;

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// The length of an encoded request in bytes.
pub const REQUEST_LEN: usize = PUBLIC_KEY_LEN + PUBLIC_KEY_LEN + 32 + 32;

/// The length of an encoded response in bytes.
pub const RESPONSE_LEN: usize = PUBLIC_KEY_LEN + 32 + 32;

/// A handshake initiator's state.
#[derive(Debug)]
pub struct InitiatorState<'a> {
    protocol: Protocol,
    private_key: &'a PrivateKey,
    acceptor_public_key: PublicKey,
}

impl<'a> InitiatorState<'a> {
    /// Creates a new [`InitiatorState`] with the given private key and the given acceptor's public
    /// key.
    pub fn new(private_key: &'a PrivateKey, acceptor_public_key: PublicKey) -> InitiatorState<'a> {
        InitiatorState { protocol: Protocol::new("yrgourd.v1"), private_key, acceptor_public_key }
    }

    /// Initiates a handshake, returning an opaque array of bytes to be sent to the acceptor.
    pub fn initiate(&mut self, mut rng: impl CryptoRngCore) -> [u8; REQUEST_LEN] {
        // Allocate and split a request buffer.
        let mut req = [0u8; REQUEST_LEN];
        let (ephemeral_pub, static_pub) = req.split_at_mut(PUBLIC_KEY_LEN);
        let (static_pub, i_enc) = static_pub.split_at_mut(PUBLIC_KEY_LEN);
        let (i_enc, s_enc) = i_enc.split_at_mut(32);

        // Generate an ephemeral private key.
        let ephemeral = PrivateKey::random(&mut rng);

        // Mix the acceptor's static public key into the protocol.
        self.protocol.mix(b"acceptor-static-pub", &self.acceptor_public_key.encoded);

        // Mix the initiator's ephemeral public key into the protocol.
        ephemeral_pub.copy_from_slice(&ephemeral.public_key.encoded);
        self.protocol.mix(b"initiator-ephemeral-pub", ephemeral_pub);

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (self.acceptor_public_key.q * ephemeral.d).compress().to_bytes();
        self.protocol.mix(b"initiator-ephemeral-shared", &ephemeral_shared);

        // Encrypt the initiator's static public key.
        static_pub.copy_from_slice(&self.private_key.public_key.encoded);
        self.protocol.encrypt(b"initiator-static-pub", static_pub);

        // Calculate the static shared secret and mix it into the protocol.
        let static_shared = (self.acceptor_public_key.q * self.private_key.d).compress().to_bytes();
        self.protocol.mix(b"static-shared", &static_shared);

        // Generate a hedged commitment scalar and commitment point.
        let k = self.protocol.hedge(&mut rng, &[self.private_key.d.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        // Encode and encrypt the commitment point of the initiator's signature.
        i_enc.copy_from_slice(i.compress().as_bytes());
        self.protocol.encrypt(b"initiator-commitment-point", i_enc);

        // Derive a challenge scalar for the initiator's signature.
        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"initiator-challenge-scalar"),
        );

        // Calculate and encrypt the proof scalar for the initiator's signature.
        s_enc.copy_from_slice(((self.private_key.d * r) + k).as_bytes());
        self.protocol.encrypt(b"initiator-proof-scalar", s_enc);

        // Send the initiator's ephemeral public key, the initiator's encrypted static public key,
        // and the two signature components: the encrypted commitment point and the encrypted proof
        // scalar.
        req
    }

    /// Finalizes a handshake given the acceptor's response. If valid, returns a `(recv, send)`
    /// pair of [`Protocol`]s for transport.
    pub fn finalize(mut self, mut resp: [u8; RESPONSE_LEN]) -> Option<(Protocol, Protocol)> {
        // Split the response into its components.
        let (ephemeral_pub, i) = resp.split_at_mut(PUBLIC_KEY_LEN);
        let (i, s) = i.split_at_mut(32);

        // Decrypt the acceptor's ephemeral public key.
        self.protocol.decrypt(b"acceptor-ephemeral-pub", ephemeral_pub);
        let ephemeral_pub = PublicKey::try_from(<&[u8]>::from(ephemeral_pub)).ok()?;

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (self.private_key.d * ephemeral_pub.q).compress().to_bytes();
        self.protocol.mix(b"acceptor-ephemeral-shared", &ephemeral_shared);

        // Decrypt the initiator's encoded commitment point of the acceptor's signature.
        self.protocol.decrypt(b"acceptor-commitment-point", i);

        // Derive the counterfactual challenge scalar for the acceptor's signature.
        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"acceptor-challenge-scalar"),
        );

        // Decrypt and decode the proof scalar of the acceptor's signature.
        self.protocol.decrypt(b"acceptor-proof-scalar", s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            s.try_into().expect("should be 32 bytes"),
        ))?;

        // Verify the acceptor's signature and early exit if invalid.
        if !verify(i, &r_p, &self.acceptor_public_key.q, &s) {
            return None;
        }

        // Fork the protocol into recv and send clones.
        let mut recv = self.protocol.clone();
        recv.mix(b"sender", b"acceptor");
        let mut send = self.protocol.clone();
        send.mix(b"sender", b"initiator");

        Some((recv, send))
    }
}

/// A handshake acceptor's state.
#[derive(Debug, Clone)]
pub struct AcceptorState<'a, 'b> {
    protocol: Protocol,
    private_key: &'a PrivateKey,
    allowed_initiators: Option<&'b HashSet<PublicKey>>,
}

impl<'a, 'b> AcceptorState<'a, 'b> {
    /// Creates a new [`Acceptor`] with the given private key with initiators optionally restricted
    /// to the given set of public keys.
    pub fn new(
        private_key: &'a PrivateKey,
        allowed_initiators: Option<&'b HashSet<PublicKey>>,
    ) -> AcceptorState<'a, 'b> {
        AcceptorState { protocol: Protocol::new("yrgourd.v1"), private_key, allowed_initiators }
    }

    /// Responds to a handshake given the initiator's request. If valid, returns the initiator's
    /// public key, a `(recv, send)` pair of [`Protocol`]s for transport, and a response to be sent
    /// to the initiator.
    pub fn respond(
        &mut self,
        mut rng: impl CryptoRngCore,
        mut req: [u8; REQUEST_LEN],
    ) -> Option<(PublicKey, Protocol, Protocol, [u8; RESPONSE_LEN])> {
        // Split the request buffer.
        let (ephemeral_pub, static_pub) = req.split_at_mut(PUBLIC_KEY_LEN);
        let (static_pub, i) = static_pub.split_at_mut(PUBLIC_KEY_LEN);
        let (i, s) = i.split_at_mut(32);

        // Mix the acceptor's static public key into the protocol.
        self.protocol.mix(b"acceptor-static-pub", &self.private_key.public_key.encoded);

        // Mix the initiator's ephemeral public key into the protocol and parse it.
        self.protocol.mix(b"initiator-ephemeral-pub", ephemeral_pub);
        let ephemeral_pub = CompressedRistretto::from_slice(ephemeral_pub).ok()?.decompress()?;

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (ephemeral_pub * self.private_key.d).compress().to_bytes();
        self.protocol.mix(b"initiator-ephemeral-shared", &ephemeral_shared);

        // Decrypt and parse the initiator's static public key.
        self.protocol.decrypt(b"initiator-static-pub", static_pub);
        let static_pub = PublicKey::try_from(<&[u8]>::from(static_pub)).ok()?;

        // If initiators are restricted, check that the initiator is in the allowed set.
        if self.allowed_initiators.is_some_and(|keys| !keys.contains(&static_pub)) {
            return None;
        }

        // Calculate the static shared secret and mix it into the protocol.
        let static_shared = (static_pub.q * self.private_key.d).compress().to_bytes();
        self.protocol.mix(b"static-shared", &static_shared);

        // Decrypt the initiator's encoded commitment point of the initiator's signature.
        self.protocol.decrypt(b"initiator-commitment-point", i);

        // Derive the counterfactual challenge scalar for the initiator's signature.
        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"initiator-challenge-scalar"),
        );

        // Decrypt and decode the proof scalar of the initiator's signature.
        self.protocol.decrypt(b"initiator-proof-scalar", s);
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

        // Encrypt the acceptor's ephemeral public key.
        ephemeral_pub.copy_from_slice(&ephemeral.public_key.encoded);
        self.protocol.encrypt(b"acceptor-ephemeral-pub", ephemeral_pub);

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (static_pub.q * ephemeral.d).compress().to_bytes();
        self.protocol.mix(b"acceptor-ephemeral-shared", &ephemeral_shared);

        // Generate a hedged commitment scalar and commitment point.
        let k = self.protocol.hedge(&mut rng, &[self.private_key.d.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        // Encode and encrypt the commitment point of the acceptor's signature.
        i_enc.copy_from_slice(i.compress().as_bytes());
        self.protocol.encrypt(b"acceptor-commitment-point", i_enc);

        // Derive a challenge scalar for the acceptor's signature.
        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"acceptor-challenge-scalar"),
        );

        // Calculate and encrypt the proof scalar for the acceptor's signature.
        s_enc.copy_from_slice(((self.private_key.d * r) + k).as_bytes());
        self.protocol.encrypt(b"acceptor-proof-scalar", s_enc);

        // Fork the protocol into recv and send clones.
        let mut recv = self.protocol.clone();
        recv.mix(b"sender", b"initiator");
        let mut send = self.protocol.clone();
        send.mix(b"sender", b"acceptor");

        // Return the initiator's public key, recv and send protocols, and a response to the
        // initiator.
        Some((static_pub, recv, send, resp))
    }
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
        let acceptor_key = PrivateKey::random(&mut rng);
        let initiator_key = PrivateKey::random(&mut rng);

        let mut acceptor = AcceptorState::new(&acceptor_key, None);
        let mut initiator = InitiatorState::new(&initiator_key, acceptor_key.public_key);

        let handshake_req = initiator.initiate(&mut rng);
        let (pk, mut acceptor_recv, mut acceptor_send, handshake_resp) = acceptor
            .respond(&mut rng, handshake_req)
            .expect("should handle initiator request successfully");
        assert_eq!(initiator_key.public_key, pk);

        let (mut initiator_recv, mut initiator_send) = initiator
            .finalize(handshake_resp)
            .expect("should handle acceptor response successfully");

        assert_eq!(
            acceptor_recv.derive_array::<8>(b"test"),
            initiator_send.derive_array::<8>(b"test")
        );
        assert_eq!(
            initiator_recv.derive_array::<8>(b"test"),
            acceptor_send.derive_array::<8>(b"test")
        );
    }

    #[test]
    fn allowed_initiator() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let acceptor_key = PrivateKey::random(&mut rng);
        let initiator_key = PrivateKey::random(&mut rng);

        let mut allowed_initiators = HashSet::new();
        allowed_initiators.insert(initiator_key.public_key);

        let mut initiator = InitiatorState::new(&initiator_key, acceptor_key.public_key);
        let mut acceptor = AcceptorState::new(&acceptor_key, Some(&allowed_initiators));
        let handshake_req = initiator.initiate(&mut rng);
        let (pk, mut acceptor_recv, mut acceptor_send, handshake_resp) = acceptor
            .respond(&mut rng, handshake_req)
            .expect("should handle initiator request successfully");
        assert_eq!(initiator_key.public_key, pk);

        let (mut initiator_recv, mut initiator_send) = initiator
            .finalize(handshake_resp)
            .expect("should handle acceptor response successfully");

        assert_eq!(
            acceptor_recv.derive_array::<8>(b"test"),
            initiator_send.derive_array::<8>(b"test")
        );
        assert_eq!(
            initiator_recv.derive_array::<8>(b"test"),
            acceptor_send.derive_array::<8>(b"test")
        );
    }

    #[test]
    fn restricted_initiator() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let acceptor_key = PrivateKey::random(&mut rng);
        let initiator_key = PrivateKey::random(&mut rng);
        let bad_initiator_key = PrivateKey::random(&mut rng);

        let mut allowed_initiators = HashSet::new();
        allowed_initiators.insert(initiator_key.public_key);

        let mut bad_initiator = InitiatorState::new(&bad_initiator_key, acceptor_key.public_key);

        let mut acceptor = AcceptorState::new(&acceptor_key, Some(&allowed_initiators));
        let bad_handshake_req = bad_initiator.initiate(&mut rng);
        assert!(
            acceptor.respond(&mut rng, bad_handshake_req).is_none(),
            "should not allow a handshake with an initiator not in the set"
        );
    }

    #[test]
    fn fuzz_acceptor_respond() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let acceptor_key = PrivateKey::random(rng);

        bolero::check!().with_type::<(u64, [u8; REQUEST_LEN])>().cloned().for_each(
            |(seed, req)| {
                let mut rng = ChaChaRng::seed_from_u64(seed);
                let mut acceptor = AcceptorState::new(&acceptor_key, None);
                assert!(acceptor.respond(&mut rng, req).is_none());
            },
        );
    }

    #[test]
    fn fuzz_initiator_finalize() {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let initiator_key = PrivateKey::random(rng);

        bolero::check!().with_type::<[u8; RESPONSE_LEN]>().cloned().for_each(|req| {
            let initiator = InitiatorState::new(&initiator_key, initiator_key.public_key);
            assert!(initiator.finalize(req).is_none());
        });
    }
}
