use curve25519_dalek::{RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

use crate::server::HandshakeResponse;
use crate::Connected;

pub struct HandshakeRequest {
    pub ephemeral_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub sig_i: [u8; 32],
    pub sig_s: [u8; 32],
}

pub struct Client {
    protocol: Protocol,
    static_priv: Scalar,
    static_pub: [u8; 32],
    ephemeral_priv: Scalar,
    ephemeral_pub: [u8; 32],
    server_static_pub: RistrettoPoint,
}

impl Client {
    pub fn new(
        mut rng: impl RngCore + CryptoRng,
        static_priv: Scalar,
        server_static_pub: RistrettoPoint,
    ) -> Client {
        let static_pub = RistrettoPoint::mul_base(&static_priv).compress().to_bytes();
        let ephemeral_priv = Scalar::random(&mut rng);
        let ephemeral_pub = RistrettoPoint::mul_base(&ephemeral_priv).compress().to_bytes();
        let protocol = Protocol::new("yrgourd.v1");
        Client {
            protocol,
            static_priv,
            static_pub,
            ephemeral_priv,
            ephemeral_pub,
            server_static_pub,
        }
    }

    pub fn request_handshake(&mut self, mut rng: impl RngCore + CryptoRng) -> HandshakeRequest {
        let ephemeral_shared = (self.server_static_pub * self.ephemeral_priv).compress().to_bytes();
        let static_shared = (self.server_static_pub * self.static_priv).compress().to_bytes();

        self.protocol.mix(b"client-ephemeral-pub", &self.ephemeral_pub);
        self.protocol.mix(b"ephemeral-shared", &ephemeral_shared);
        let mut static_pub = self.static_pub;
        self.protocol.encrypt(b"client-static-pub", &mut static_pub);
        self.protocol.mix(b"static-shared", &static_shared);

        let k = self.protocol.hedge(&mut rng, &[self.static_priv.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        let mut sig_i = i.compress().to_bytes();
        self.protocol.encrypt(b"client-commitment-point", &mut sig_i);

        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"client-challenge-scalar"),
        );

        let mut sig_s = ((self.static_priv * r) + k).to_bytes();
        self.protocol.encrypt(b"client-proof-scalar", &mut sig_s);

        HandshakeRequest { ephemeral_pub: self.ephemeral_pub, static_pub, sig_i, sig_s }
    }

    pub fn process_response(&mut self, response: &HandshakeResponse) -> Option<Connected> {
        let mut i = response.sig_i;
        self.protocol.decrypt(b"server-commitment-point", &mut i);

        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"server-challenge-scalar"),
        );

        let mut s = response.sig_s;
        self.protocol.decrypt(b"server-proof-scalar", &mut s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;

        (RistrettoPoint::vartime_double_scalar_mul_basepoint(&r_p, &-self.server_static_pub, &s)
            .compress()
            .as_bytes()
            == &i)
            .then(|| Connected::new(&self.protocol))
    }
}
