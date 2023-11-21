use curve25519_dalek::{RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

use crate::messages::{HandshakeRequest, HandshakeResponse};

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
        // Calculate and encode the client's static public key.
        let static_pub = RistrettoPoint::mul_base(&static_priv).compress().to_bytes();

        // Generate an ephemeral private key and calculate and encode the ephemeral public key.
        let ephemeral_priv = Scalar::random(&mut rng);
        let ephemeral_pub = RistrettoPoint::mul_base(&ephemeral_priv).compress().to_bytes();

        Client {
            protocol: Protocol::new("yrgourd.v1"),
            static_priv,
            static_pub,
            ephemeral_priv,
            ephemeral_pub,
            server_static_pub,
        }
    }

    pub fn request_handshake(&mut self, mut rng: impl RngCore + CryptoRng) -> HandshakeRequest {
        // Mix the server's static public key into the protocol.
        self.protocol.mix(b"server-static-pub", self.server_static_pub.compress().as_bytes());

        // Mix the client's ephemeral public key into the protocol.
        self.protocol.mix(b"client-ephemeral-pub", &self.ephemeral_pub);

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (self.server_static_pub * self.ephemeral_priv).compress().to_bytes();
        self.protocol.mix(b"ephemeral-shared", &ephemeral_shared);

        // Encrypt the client's static public key.
        let mut static_pub = self.static_pub;
        self.protocol.encrypt(b"client-static-pub", &mut static_pub);

        // Calculate the static shared secret and mix it into the protocol.
        let static_shared = (self.server_static_pub * self.static_priv).compress().to_bytes();
        self.protocol.mix(b"static-shared", &static_shared);

        // Generate a hedged commitment scalar and commitment point.
        let k = self.protocol.hedge(&mut rng, &[self.static_priv.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        // Encode and encrypt the commitment point of the client's signature.
        let mut i = i.compress().to_bytes();
        self.protocol.encrypt(b"client-commitment-point", &mut i);

        // Derive a challenge scalar for the client's signature.
        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"client-challenge-scalar"),
        );

        // Calculate and encrypt the proof scalar for the client's signature.
        let mut s = ((self.static_priv * r) + k).to_bytes();
        self.protocol.encrypt(b"client-proof-scalar", &mut s);

        // Send the client's ephemeral public key, the client's encrypted static public key, and the
        // two signature components: the encrypted commitment point and the encrypted proof scalar.
        HandshakeRequest { ephemeral_pub: self.ephemeral_pub, static_pub, i, s }
    }

    pub fn process_response(
        &mut self,
        response: &HandshakeResponse,
    ) -> Option<(Protocol, Protocol)> {
        // Decrypt the client's encoded commitment point of the server's signature.
        let mut i = response.i;
        self.protocol.decrypt(b"server-commitment-point", &mut i);

        // Derive the counterfactual challenge scalar for the server's signature.
        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"server-challenge-scalar"),
        );

        // Decrypt and decode the proof scalar of the server's signature.
        let mut s = response.s;
        self.protocol.decrypt(b"server-proof-scalar", &mut s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;

        // Verify the client's signature and return a connected state object if valid.
        (RistrettoPoint::vartime_double_scalar_mul_basepoint(&r_p, &-self.server_static_pub, &s)
            .compress()
            .as_bytes()
            == &i)
            .then(|| {
                // Fork the protocol into receiver and sender clones.
                let mut receiver = self.protocol.clone();
                receiver.mix(b"sender", b"server");
                let mut sender = self.protocol.clone();
                sender.mix(b"sender", b"client");

                (receiver, sender)
            })
    }
}
