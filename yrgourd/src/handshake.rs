use fips203::{
    ml_kem_768,
    traits::{Decaps, Encaps, SerDes},
};
use lockstitch::{Protocol, TAG_LEN};
use rand_core::CryptoRngCore;

use crate::keys::{PrivateKey, PublicKey, PUBLIC_KEY_LEN};

/// The length of an initiator's request in bytes.
pub const REQUEST_LEN: usize = 1088 + 32 + PUBLIC_KEY_LEN + TAG_LEN;

/// The length of an responder's response in bytes.
pub const RESPONSE_LEN: usize = 1088 + 32 + TAG_LEN;

/// An ephemeral X25519 private key.
pub type EphemeralPrivateKey = x25519_dalek::ReusableSecret;

/// An ephemeral X25519 public key.
pub type EphemeralPublicKey = x25519_dalek::PublicKey;

/// Begins a handshake, returning a [`Protocol`] and an opaque array of bytes to be sent to the
/// responder.
pub fn initiate(
    mut rng: impl CryptoRngCore,
    is: &PrivateKey,
    rs: &PublicKey,
) -> (Protocol, EphemeralPrivateKey, [u8; REQUEST_LEN]) {
    // Generate an ephemeral X25519 key.
    let ie = EphemeralPrivateKey::random_from_rng(&mut rng);

    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Allocate and split a request buffer.
    let mut resp = [0u8; REQUEST_LEN];
    let (resp_ct, resp_ie) = resp.split_at_mut(1088);
    let (resp_ie, resp_is) = resp_ie.split_at_mut(32);

    // Mix the responder's static public key into the protocol.
    yr.mix("rs", &rs.encoded);

    // Generate a new ML-KEM-768 encapsulated key.
    let (ss, ct) = rs.ek_pq.try_encaps_with_rng(&mut rng).expect("should encapsulate");
    yr.mix("rs-ml-kem-ct", &ct.clone().into_bytes());
    yr.mix("rs-ml-kem-ss", &ss.into_bytes());
    resp_ct.copy_from_slice(&ct.into_bytes());

    // Encrypt the initiator's ephemeral public key.
    resp_ie.copy_from_slice(EphemeralPublicKey::from(&ie).as_bytes());
    yr.encrypt("re", resp_ie);

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("ie-rs", ie.diffie_hellman(&rs.ek_c).as_bytes());

    // Seal the initiator's static public key.
    resp_is[..PUBLIC_KEY_LEN].copy_from_slice(&is.public_key.encoded);
    yr.seal("is", resp_is);

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("is-rs", is.dk_c.diffie_hellman(&rs.ek_c).as_bytes());

    (yr, ie, resp)
}

/// Accepts a handshake given the initiator's request. If valid, returns the initiator's public key,
/// a protocol, and a response to be sent to the initiator.
pub fn accept(
    mut rng: impl CryptoRngCore,
    rs: &PrivateKey,
    mut req: [u8; REQUEST_LEN],
) -> Option<(PublicKey, (Protocol, Protocol), [u8; RESPONSE_LEN])> {
    // Generate an ephemeral X25519 key pair.
    let re = EphemeralPrivateKey::random_from_rng(&mut rng);

    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Split the request buffer.
    let (req_ct, req_ie) = req.split_at_mut(1088);
    let (req_ie, req_is) = req_ie.split_at_mut(32);

    // Mix the responder's static public key into the protocol.
    yr.mix("rs", &rs.public_key.encoded);

    // Decapsulate the ML-KEM-768 shared secret.
    let ct =
        ml_kem_768::CipherText::try_from_bytes(req_ct.try_into().expect("should be 1088 bytes"))
            .expect("should be valid ciphertext");
    let ss = rs.dk_pq.try_decaps(&ct).expect("should decapsulate");
    yr.mix("rs-ml-kem-ct", &ct.into_bytes());
    yr.mix("rs-ml-kem-ss", &ss.into_bytes());

    // Decrypt the initiator's ephemeral public key into the protocol and parse it.
    yr.decrypt("re", req_ie);
    let ie = EphemeralPublicKey::from(<[u8; 32]>::try_from(req_ie).expect("should be 32 bytes"));

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("ie-rs", rs.dk_c.diffie_hellman(&ie).as_bytes());

    // Open and decode the initiator's static public key.
    let is = PublicKey::try_from(yr.open("is", req_is)?).ok()?;

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("is-rs", rs.dk_c.diffie_hellman(&is.ek_c).as_bytes());

    // Allocate and split a response buffer.
    let mut resp = [0u8; RESPONSE_LEN];
    let (resp_ct, resp_re) = resp.split_at_mut(1088);

    // Generate a new ML-KEM-768 encapsulated key.
    let (ss, ct) = is.ek_pq.try_encaps_with_rng(&mut rng).expect("should encapsulate");
    yr.mix("is-ml-kem-ct", &ct.clone().into_bytes());
    yr.mix("is-ml-kem-ss", &ss.into_bytes());
    resp_ct.copy_from_slice(&ct.into_bytes());

    // Encrypt the responder's ephemeral public key.
    resp_re[..32].copy_from_slice(EphemeralPublicKey::from(&re).as_bytes());
    yr.seal("re", resp_re);

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("ie-re", re.diffie_hellman(&ie).as_bytes());

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("is-re", re.diffie_hellman(&is.ek_c).as_bytes());

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix("sender", b"initiator");
    send.mix("sender", b"responder");

    Some((is, (recv, send), resp))
}

/// Finalizes an initiated handshake given the responder's response. If valid, returns a `(recv,
/// send)` pair of [`Protocol`]s for transport.
pub fn finalize(
    is: &PrivateKey,
    ie: EphemeralPrivateKey,
    mut yr: Protocol,
    mut resp: [u8; RESPONSE_LEN],
) -> Option<(Protocol, Protocol)> {
    // Split the response buffer.
    let (resp_ct, resp_re) = resp.split_at_mut(1088);

    // Decapsulate the ML-KEM-768 shared secret.
    let ct =
        ml_kem_768::CipherText::try_from_bytes(resp_ct.try_into().expect("should be 1088 bytes"))
            .expect("should be valid ciphertext");
    let ss = is.dk_pq.try_decaps(&ct).expect("should decapsulate");
    yr.mix("is-ml-kem-ct", &ct.into_bytes());
    yr.mix("is-ml-kem-ss", &ss.into_bytes());

    // Decrypt and decode the responder's ephemeral public key.
    let re = EphemeralPublicKey::from(
        <[u8; 32]>::try_from(yr.open("re", resp_re)?).expect("should be 32 bytes"),
    );

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("ie-re", ie.diffie_hellman(&re).as_bytes());

    // Calculate the shared secret and mix it into the protocol.
    yr.mix("is-re", is.dk_c.diffie_hellman(&re).as_bytes());

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix("sender", b"responder");
    send.mix("sender", b"initiator");

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
        let initiator_static = PrivateKey::random(&mut rng);

        let (yr_init, ie, req) =
            initiate(&mut rng, &initiator_static, &responder_static.public_key);

        let (pk, (mut responder_recv, mut responder_send), resp) =
            accept(&mut rng, &responder_static, req).expect("should begin successfully");
        assert_eq!(initiator_static.public_key, pk);

        let (mut initiator_recv, mut initiator_send) =
            finalize(&initiator_static, ie, yr_init, resp).expect("should finalize successfully");

        assert_eq!(
            responder_recv.derive_array::<8>("test"),
            initiator_send.derive_array::<8>("test")
        );
        assert_eq!(
            initiator_recv.derive_array::<8>("test"),
            responder_send.derive_array::<8>("test")
        );
    }

    #[test]
    fn fuzz_accept() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let responder_static = PrivateKey::random(&mut rng);

        bolero::check!().with_type().cloned().for_each(|req| {
            assert!(accept(&mut rng, &responder_static, req).is_none());
        });
    }

    #[test]
    fn fuzz_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let initiator_static = PrivateKey::random(&mut rng);
        let responder_static = PrivateKey::random(&mut rng);

        let (yr, ie, _) = initiate(&mut rng, &initiator_static, &responder_static.public_key);

        bolero::check!().with_type().cloned().for_each(|resp| {
            assert!(finalize(&initiator_static, ie.clone(), yr.clone(), resp).is_none());
        });
    }
}
