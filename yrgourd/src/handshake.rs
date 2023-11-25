use std::collections::HashSet;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand_core::{CryptoRng, RngCore};

use crate::keys::{PrivateKey, PublicKey};

/// A request sent by a handshake initiator.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    /// The initiator's ephemeral public key.
    pub ephemeral_pub: [u8; 32],
    /// The initiator's encrypted static public key.
    pub static_pub: [u8; 32],
    /// The encrypted commitment point of the initiator's signature.
    pub i: [u8; 32],
    /// The encrypted proof scalar of the initiator's signature.
    pub s: [u8; 32],
}

impl Request {
    /// The length of an encoded request in bytes.
    pub const LEN: usize = 32 + 32 + 32 + 32;

    /// Decodes a serialized request.
    pub fn from_bytes(b: [u8; Self::LEN]) -> Request {
        Request {
            ephemeral_pub: b[..32].try_into().expect("should be 32 bytes"),
            static_pub: b[32..64].try_into().expect("should be 32 bytes"),
            i: b[64..96].try_into().expect("should be 32 bytes"),
            s: b[96..].try_into().expect("should be 32 bytes"),
        }
    }

    /// Encodes a serialized request.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut req = [0u8; Self::LEN];
        req[..32].copy_from_slice(&self.ephemeral_pub);
        req[32..64].copy_from_slice(&self.static_pub);
        req[64..96].copy_from_slice(&self.i);
        req[96..].copy_from_slice(&self.s);
        req
    }
}

/// A response sent by a handshake acceptor.
#[derive(Debug, Clone, Copy)]
pub struct Response {
    /// The acceptor's encrypted ephemeral public key.
    pub ephemeral_pub: [u8; 32],
    /// The encrypted commitment point of the acceptor's signature.
    pub i: [u8; 32],
    /// The encrypted proof scalar of the acceptor's signature.
    pub s: [u8; 32],
}

impl Response {
    /// The length of an encoded response in bytes.
    pub const LEN: usize = 32 + 32 + 32;

    /// Decodes a serialized response.
    pub fn from_bytes(b: [u8; Self::LEN]) -> Response {
        Response {
            ephemeral_pub: b[..32].try_into().expect("should be 32 bytes"),
            i: b[32..64].try_into().expect("should be 32 bytes"),
            s: b[64..].try_into().expect("should be 32 bytes"),
        }
    }

    /// Encodes a serialized response.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut resp = [0u8; Self::LEN];
        resp[..32].copy_from_slice(&self.ephemeral_pub);
        resp[32..64].copy_from_slice(&self.i);
        resp[64..].copy_from_slice(&self.s);
        resp
    }
}

/// A handshake initiator's state.
#[derive(Debug)]
pub struct InitiatorState<'a> {
    protocol: Protocol,
    private_key: &'a PrivateKey,
    acceptor_public_key: PublicKey,
    ephemeral_private_key: PrivateKey,
}

impl<'a> InitiatorState<'a> {
    /// Creates a new [`InitiatorState`] with the given private key and the given acceptor's public
    /// key.
    pub fn new(
        rng: impl RngCore + CryptoRng,
        private_key: &'a PrivateKey,
        acceptor_public_key: PublicKey,
    ) -> InitiatorState<'a> {
        InitiatorState {
            protocol: Protocol::new("yrgourd.v1"),
            private_key,
            acceptor_public_key,
            ephemeral_private_key: PrivateKey::random(rng),
        }
    }

    /// Initiates a handshake, returning the [`Request`] to be sent to the acceptor.
    pub fn initiate(&mut self, mut rng: impl RngCore + CryptoRng) -> Request {
        // Mix the acceptor's static public key into the protocol.
        self.protocol.mix(b"acceptor-static-pub", &self.acceptor_public_key.encoded);

        // Mix the initiator's ephemeral public key into the protocol.
        self.protocol
            .mix(b"initiator-ephemeral-pub", &self.ephemeral_private_key.public_key.encoded);

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared =
            (self.acceptor_public_key.q * self.ephemeral_private_key.d).compress().to_bytes();
        self.protocol.mix(b"initiator-ephemeral-shared", &ephemeral_shared);

        // Encrypt the initiator's static public key.
        let mut static_pub = self.private_key.public_key.encoded;
        self.protocol.encrypt(b"initiator-static-pub", &mut static_pub);

        // Calculate the static shared secret and mix it into the protocol.
        let static_shared = (self.acceptor_public_key.q * self.private_key.d).compress().to_bytes();
        self.protocol.mix(b"static-shared", &static_shared);

        // Generate a hedged commitment scalar and commitment point.
        let k = self.protocol.hedge(&mut rng, &[self.private_key.d.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        // Encode and encrypt the commitment point of the initiator's signature.
        let mut i = i.compress().to_bytes();
        self.protocol.encrypt(b"initiator-commitment-point", &mut i);

        // Derive a challenge scalar for the initiator's signature.
        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"initiator-challenge-scalar"),
        );

        // Calculate and encrypt the proof scalar for the initiator's signature.
        let mut s = ((self.private_key.d * r) + k).to_bytes();
        self.protocol.encrypt(b"initiator-proof-scalar", &mut s);

        // Send the initiator's ephemeral public key, the initiator's encrypted static public key,
        // and the two signature components: the encrypted commitment point and the encrypted proof
        // scalar.
        Request { ephemeral_pub: self.ephemeral_private_key.public_key.encoded, static_pub, i, s }
    }

    /// Finalizes a handshake given the acceptor's [`Response`]. If valid, returns a `(recv, send)`
    /// pair of [`Protocol`]s for transport.
    pub fn finalize(&mut self, response: &Response) -> Option<(Protocol, Protocol)> {
        // Decrypt the acceptor's ephemeral public key.
        let mut ephemeral_pub = response.ephemeral_pub;
        self.protocol.decrypt(b"acceptor-ephemeral-pub", &mut ephemeral_pub);
        let ephemeral_pub = PublicKey::try_from(ephemeral_pub.as_ref()).ok()?;

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (self.private_key.d * ephemeral_pub.q).compress().to_bytes();
        self.protocol.mix(b"acceptor-ephemeral-shared", &ephemeral_shared);

        // Decrypt the initiator's encoded commitment point of the acceptor's signature.
        let mut i = response.i;
        self.protocol.decrypt(b"acceptor-commitment-point", &mut i);

        // Derive the counterfactual challenge scalar for the acceptor's signature.
        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"acceptor-challenge-scalar"),
        );

        // Decrypt and decode the proof scalar of the acceptor's signature.
        let mut s = response.s;
        self.protocol.decrypt(b"acceptor-proof-scalar", &mut s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;

        // Verify the initiator's signature and early exit if invalid.
        if !verify(&i, &r_p, &self.acceptor_public_key.q, &s) {
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
    /// Create a new [`Acceptor`] with the given private key with initiators optionally restricted
    /// to the given set of public keys.
    pub fn new(
        private_key: &'a PrivateKey,
        allowed_initiators: Option<&'b HashSet<PublicKey>>,
    ) -> AcceptorState<'a, 'b> {
        AcceptorState { protocol: Protocol::new("yrgourd.v1"), private_key, allowed_initiators }
    }

    /// Responds to a handshake given the initiator's [`Request`]. If valid, returns the initiator's
    /// public key, a `(recv, send)` pair of [`Protocol`]s for transport, and a [`Response`] to be
    /// sent to the initiator.
    pub fn respond(
        &mut self,
        mut rng: impl RngCore + CryptoRng,
        handshake: &Request,
    ) -> Option<(PublicKey, Protocol, Protocol, Response)> {
        // Mix the acceptor's static public key into the protocol.
        self.protocol.mix(b"acceptor-static-pub", &self.private_key.public_key.encoded);

        // Parse the initiator's ephemeral public key and mix it into the protocol.
        let ephemeral_pub =
            CompressedRistretto::from_slice(&handshake.ephemeral_pub).ok()?.decompress()?;
        self.protocol.mix(b"initiator-ephemeral-pub", &handshake.ephemeral_pub);

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (ephemeral_pub * self.private_key.d).compress().to_bytes();
        self.protocol.mix(b"initiator-ephemeral-shared", &ephemeral_shared);

        // Decrypt and parse the initiator's static public key.
        let mut initiator_pub = handshake.static_pub;
        self.protocol.decrypt(b"initiator-static-pub", &mut initiator_pub);
        let initiator_pub = PublicKey::try_from(initiator_pub.as_ref()).ok()?;

        // If initiators are restricted, check that the initiator is in the allowed set.
        if self.allowed_initiators.is_some_and(|keys| !keys.contains(&initiator_pub)) {
            return None;
        }

        // Calculate the static shared secret and mix it into the protocol.
        let static_shared = (initiator_pub.q * self.private_key.d).compress().to_bytes();
        self.protocol.mix(b"static-shared", &static_shared);

        // Decrypt the initiator's encoded commitment point of the initiator's signature.
        let mut i = handshake.i;
        self.protocol.decrypt(b"initiator-commitment-point", &mut i);

        // Derive the counterfactual challenge scalar for the initiator's signature.
        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"initiator-challenge-scalar"),
        );

        // Decrypt and decode the proof scalar of the initiator's signature.
        let mut s = handshake.s;
        self.protocol.decrypt(b"initiator-proof-scalar", &mut s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;

        // Verify the initiator's signature and early exit if invalid.
        if !verify(&i, &r_p, &initiator_pub.q, &s) {
            return None;
        }

        // Generate an ephemeral key pair;
        let ephemeral = PrivateKey::random(&mut rng);

        // Encrypt the acceptor's ephemeral public key.
        let mut ephemeral_pub = ephemeral.public_key.encoded;
        self.protocol.encrypt(b"acceptor-ephemeral-pub", &mut ephemeral_pub);

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (initiator_pub.q * ephemeral.d).compress().to_bytes();
        self.protocol.mix(b"acceptor-ephemeral-shared", &ephemeral_shared);

        // Generate a hedged commitment scalar and commitment point.
        let k = self.protocol.hedge(&mut rng, &[self.private_key.d.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        // Encode and encrypt the commitment point of the acceptor's signature.
        let mut i = i.compress().to_bytes();
        self.protocol.encrypt(b"acceptor-commitment-point", &mut i);

        // Derive a challenge scalar for the acceptor's signature.
        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"acceptor-challenge-scalar"),
        );

        // Calculate and encrypt the proof scalar for the acceptor's signature.
        let mut s = ((self.private_key.d * r) + k).to_bytes();
        self.protocol.encrypt(b"acceptor-proof-scalar", &mut s);

        // Fork the protocol into recv and send clones.
        let mut recv = self.protocol.clone();
        recv.mix(b"sender", b"initiator");
        let mut send = self.protocol.clone();
        send.mix(b"sender", b"acceptor");

        // Return the initiator's public key, recv and send protocols, and a response to the
        // initiator.
        Some((initiator_pub, recv, send, Response { ephemeral_pub, i, s }))
    }
}

/// Given an encoded commitment point `I`, a counterfactual challenge scalar `r′`, a public key `Q`,
/// and a proof scalar `s`, return true iff `I == [s]G - [r']Q`. Compares the encoded forms of `I`
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
        let mut initiator = InitiatorState::new(&mut rng, &initiator_key, acceptor_key.public_key);

        let handshake_req = initiator.initiate(&mut rng);
        let (pk, mut acceptor_recv, mut acceptor_send, handshake_resp) = acceptor
            .respond(&mut rng, &handshake_req)
            .expect("should handle initiator request successfully");
        assert_eq!(initiator_key.public_key, pk);

        let (mut initiator_recv, mut initiator_send) = initiator
            .finalize(&handshake_resp)
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

        let mut initiator = InitiatorState::new(&mut rng, &initiator_key, acceptor_key.public_key);
        let mut acceptor = AcceptorState::new(&acceptor_key, Some(&allowed_initiators));
        let handshake_req = initiator.initiate(&mut rng);
        let (pk, mut acceptor_recv, mut acceptor_send, handshake_resp) = acceptor
            .respond(&mut rng, &handshake_req)
            .expect("should handle initiator request successfully");
        assert_eq!(initiator_key.public_key, pk);

        let (mut initiator_recv, mut initiator_send) = initiator
            .finalize(&handshake_resp)
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

        let mut bad_initiator =
            InitiatorState::new(&mut rng, &bad_initiator_key, acceptor_key.public_key);

        let mut acceptor = AcceptorState::new(&acceptor_key, Some(&allowed_initiators));
        let bad_handshake_req = bad_initiator.initiate(&mut rng);
        assert!(
            acceptor.respond(&mut rng, &bad_handshake_req).is_none(),
            "should not allow a handshake with an initiator not in the set"
        );
    }
}
