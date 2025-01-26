//! Implements the yrgourd handshake.

use fips203::{
    ml_kem_768::{CipherText, DecapsKey, KG},
    traits::{Decaps, Encaps as _, KeyGen as _, SerDes as _},
};
use lockstitch::{Protocol, TAG_LEN};
use rand_core::CryptoRngCore;

use crate::{PrivateKey, PublicKey};

/// The size in bytes of an initiator's request: `rs-ct + is + ie + tag`.
pub const REQ_LEN: usize = 1088 + 1184 + 1184 + TAG_LEN;

/// The size in bytes of a responder's response: `is-ct + ie-ct + tag`.
pub const RESP_LEN: usize = 1088 + 1088 + TAG_LEN;

pub fn initiate(
    mut rng: impl CryptoRngCore,
    is: &PublicKey,
    rs: &PublicKey,
) -> ((Protocol, DecapsKey), [u8; REQ_LEN]) {
    // Generate an ephemeral key pair.
    let (ie_enc, ie) = KG::try_keygen_with_rng(&mut rng).expect("should generate key");

    // Allocate and split a buffer for the request.
    let mut req = [0u8; REQ_LEN];
    let (req_rs_ct, req_is) = req.split_at_mut(1088);
    let (req_is, req_ie) = req_is.split_at_mut(1184);

    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Mix the responder's static public key into the protocol.
    yr.mix("rs", &rs.encoded);

    // Encapsulate a shared secret with the responser's static key.
    let (rs_ss, rs_ct) = rs.ek.try_encaps_with_rng(&mut rng).expect("should encapsulate");
    req_rs_ct.copy_from_slice(&rs_ct.into_bytes());

    // Mix the ciphertext and shared secret into the protocol.
    yr.mix("rs-ct", req_rs_ct);
    yr.mix("rs-ss", &rs_ss.into_bytes());

    // Encrypt the initiator's static public key.
    req_is.copy_from_slice(&is.encoded);
    yr.encrypt("is", req_is);

    // Seal the initiator's ephemeral public key.
    req_ie[..1184].copy_from_slice(&ie_enc.into_bytes());
    yr.seal("ie", req_ie);

    ((yr, ie), req)
}

pub fn accept(
    mut rng: impl CryptoRngCore,
    rs: &PrivateKey,
    mut req: [u8; REQ_LEN],
) -> Option<((Protocol, Protocol), PublicKey, [u8; RESP_LEN])> {
    // Split the request into pieces.
    let (req_rs_ct, req_is) = req.split_at_mut(1088);
    let (req_is, req_ie) = req_is.split_at_mut(1184);

    // Initialize a protocol.
    let mut yr = Protocol::new("yrgourd.v1");

    // Mix the responder's static public key into the protocol.
    yr.mix("rs", &rs.public_key.encoded);

    // Decapsulate the shared secret.
    yr.mix("rs-ct", req_rs_ct);
    let rs_ct = CipherText::try_from_bytes(req_rs_ct.try_into().expect("should be 1088 bytes"))
        .expect("should be valid ciphertext");
    let rs_ss = rs.dk.try_decaps(&rs_ct).expect("should decapsulate").into_bytes();
    yr.mix("rs-ss", &rs_ss);

    // Decrypt and decode the initiator's static key.
    yr.decrypt("is", req_is);
    let is = PublicKey::try_from(<&[u8]>::from(req_is)).ok()?;

    // Open and decode the initiator's ephemeral public key.
    let ie = PublicKey::try_from(yr.open("ie", req_ie)?).ok()?;

    // Allocate and split a buffer for the response.
    let mut resp = [0u8; RESP_LEN];
    let (resp_is_ct, resp_ie_ct) = resp.split_at_mut(1088);

    // Encapsulate a shared secret with the initiator's static key and encrypt it.
    let (is_ss, is_ct) = is.ek.try_encaps_with_rng(&mut rng).expect("should encapsulate key");
    resp_is_ct.copy_from_slice(&is_ct.into_bytes());
    yr.encrypt("is-ct", resp_is_ct);
    yr.mix("is-ss", &is_ss.into_bytes());

    // Encapsulate a shared secret with the initiator's ephemeral key and seal it.
    let (ie_ss, ie_ct) = ie.ek.try_encaps_with_rng(&mut rng).expect("should encapsulate key");
    resp_ie_ct[..1088].copy_from_slice(&ie_ct.into_bytes());
    yr.seal("ie-ct", resp_ie_ct);
    yr.mix("ie-ss", &ie_ss.into_bytes());

    // Fork the protocol into recv and send clones.
    let (mut recv, mut send) = (yr.clone(), yr);
    recv.mix("sender", b"initiator");
    send.mix("sender", b"responder");

    Some(((recv, send), is, resp))
}

pub fn finalize(
    (mut yr, ie): (Protocol, DecapsKey),
    is: &PrivateKey,
    mut resp: [u8; RESP_LEN],
) -> Option<(Protocol, Protocol)> {
    // Split up the response.
    let (resp_is_ct, resp_ie_ct) = resp.split_at_mut(1088);

    // Decrypt the ciphertext and decapsulate the static shared secret.
    yr.decrypt("is-ct", resp_is_ct);
    let is_ct = CipherText::try_from_bytes(resp_is_ct.try_into().expect("should be 1088 bytes"))
        .expect("should be valid ciphertext");
    let is_ss = is.dk.try_decaps(&is_ct).expect("should decapsulate").into_bytes();
    yr.mix("is-ss", &is_ss);

    // Open the ciphertext and decapsulate the ephemeral shared secret.
    let ie_ct = CipherText::try_from_bytes(
        yr.open("ie-ct", resp_ie_ct)?.try_into().expect("should be 1088 bytes"),
    )
    .expect("should be valid ciphertext");
    let ie_ss = ie.try_decaps(&ie_ct).expect("should decapsulate").into_bytes();
    yr.mix("ie-ss", &ie_ss);

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

        let rs = PrivateKey::random(&mut rng);
        let is = PrivateKey::random(&mut rng);

        let (init_state, init_msg) = initiate(&mut rng, &is.public_key, &rs.public_key);
        let ((mut resp_recv, mut resp_send), is_pub_p, resp_msg) =
            accept(&mut rng, &rs, init_msg).unwrap();
        assert_eq!(is.public_key, is_pub_p);
        let (mut init_recv, mut init_send) = finalize(init_state, &is, resp_msg).unwrap();

        assert_eq!(init_send.derive_array::<8>("test"), resp_recv.derive_array::<8>("test"));
        assert_eq!(resp_send.derive_array::<8>("test"), init_recv.derive_array::<8>("test"));
    }

    #[test]
    fn fuzz_accept() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let rs = PrivateKey::random(&mut rng);

        bolero::check!().with_type().cloned().for_each(|init_msg| {
            assert!(accept(&mut rng, &rs, init_msg).is_none());
        });
    }

    #[test]
    fn fuzz_finalize() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let rs = PrivateKey::random(&mut rng);
        let is = PrivateKey::random(&mut rng);

        let (init_state, _) = initiate(&mut rng, &is.public_key, &rs.public_key);

        bolero::check!().with_type().cloned().for_each(|resp_msg| {
            assert!(finalize(init_state.clone(), &is, resp_msg).is_none());
        });
    }
}
