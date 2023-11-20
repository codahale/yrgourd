use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

use crate::client::HandshakeRequest;
use crate::Connected;

pub struct HandshakeResponse {
    pub sig_i: [u8; 32],
    pub sig_s: [u8; 32],
}

pub struct Server {
    protocol: Protocol,
    static_priv: Scalar,
}

impl Server {
    pub fn new(static_priv: Scalar) -> Server {
        let protocol = Protocol::new("yrgourd.v1");
        Server { protocol, static_priv }
    }

    pub fn respond_handshake(
        &mut self,
        mut rng: impl RngCore + CryptoRng,
        handshake: &HandshakeRequest,
    ) -> Option<(Connected, HandshakeResponse)> {
        let ephemeral_pub =
            CompressedRistretto::from_slice(&handshake.ephemeral_pub).ok()?.decompress()?;
        self.protocol.mix(b"client-ephemeral-pub", &handshake.ephemeral_pub);

        let ephemeral_shared = (ephemeral_pub * self.static_priv).compress().to_bytes();
        self.protocol.mix(b"ephemeral-shared", &ephemeral_shared);

        let mut static_pub = handshake.static_pub;
        self.protocol.decrypt(b"client-static-pub", &mut static_pub);
        let static_pub = CompressedRistretto::from_slice(&static_pub).ok()?.decompress()?;

        let static_shared = (static_pub * self.static_priv).compress().to_bytes();
        self.protocol.mix(b"static-shared", &static_shared);

        let mut i = handshake.sig_i;
        self.protocol.decrypt(b"client-commitment-point", &mut i);

        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"client-challenge-scalar"),
        );

        let mut s = handshake.sig_s;
        self.protocol.decrypt(b"client-proof-scalar", &mut s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;

        if RistrettoPoint::vartime_double_scalar_mul_basepoint(&r_p, &-static_pub, &s)
            .compress()
            .as_bytes()
            != &i
        {
            return None;
        }

        let mut response = HandshakeResponse { sig_i: [0u8; 32], sig_s: [0u8; 32] };

        let k = self.protocol.hedge(&mut rng, &[self.static_priv.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        response.sig_i.copy_from_slice(i.compress().as_bytes());
        self.protocol.encrypt(b"server-commitment-point", &mut response.sig_i);

        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"server-challenge-scalar"),
        );

        let s = (self.static_priv * r) + k;
        response.sig_s.copy_from_slice(s.as_bytes());
        self.protocol.encrypt(b"server-proof-scalar", &mut response.sig_s);

        let mut connected =
            Connected { to_client: self.protocol.clone(), to_server: self.protocol.clone() };
        connected.to_client.mix(b"direction", b"send");
        connected.to_server.mix(b"direction", b"receive");

        Some((Connected::new(&self.protocol), response))
    }
}
