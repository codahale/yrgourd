use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

use crate::messages::{HandshakeRequest, HandshakeResponse};

pub struct HandshakingServer {
    protocol: Protocol,
    static_priv: Scalar,
    static_pub: [u8; 32],
}

impl HandshakingServer {
    pub fn new(static_priv: Scalar) -> HandshakingServer {
        // Calculate and encode the server's static public key.
        let static_pub = RistrettoPoint::mul_base(&static_priv).compress().to_bytes();
        HandshakingServer { protocol: Protocol::new("yrgourd.v1"), static_priv, static_pub }
    }

    /// Response to a client handshake request. If the handshake request is valid, returns a
    /// connected state object and a handshake response to be sent to the client.
    pub fn respond_handshake(
        &mut self,
        mut rng: impl RngCore + CryptoRng,
        handshake: &HandshakeRequest,
    ) -> Option<(ConnectedServer, HandshakeResponse)> {
        // Mix the server's static public key into the protocol.
        self.protocol.mix(b"server-static-pub", &self.static_pub);

        // Parse the client's ephemeral public key and mix it into the protocol.
        let ephemeral_pub =
            CompressedRistretto::from_slice(&handshake.ephemeral_pub).ok()?.decompress()?;
        self.protocol.mix(b"client-ephemeral-pub", &handshake.ephemeral_pub);

        // Calculate the ephemeral shared secret and mix it into the protocol.
        let ephemeral_shared = (ephemeral_pub * self.static_priv).compress().to_bytes();
        self.protocol.mix(b"ephemeral-shared", &ephemeral_shared);

        // Decrypt and parse the client's static public key.
        let mut static_pub = handshake.static_pub;
        self.protocol.decrypt(b"client-static-pub", &mut static_pub);
        let static_pub = CompressedRistretto::from_slice(&static_pub).ok()?.decompress()?;

        // Calculate the static shared secret and mix it into the protocol.
        let static_shared = (static_pub * self.static_priv).compress().to_bytes();
        self.protocol.mix(b"static-shared", &static_shared);

        // Decrypt the client's encoded commitment point of the client's signature.
        let mut i = handshake.i;
        self.protocol.decrypt(b"client-commitment-point", &mut i);

        // Derive the counterfactual challenge scalar for the client's signature.
        let r_p = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"client-challenge-scalar"),
        );

        // Decrypt and decode the proof scalar of the client's signature.
        let mut s = handshake.s;
        self.protocol.decrypt(b"client-proof-scalar", &mut s);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;

        // Verify the client's signature and early exit if invalid.
        if RistrettoPoint::vartime_double_scalar_mul_basepoint(&r_p, &-static_pub, &s)
            .compress()
            .as_bytes()
            != &i
        {
            return None;
        }

        // Generate a hedged commitment scalar and commitment point.
        let k = self.protocol.hedge(&mut rng, &[self.static_priv.as_bytes()], 10_000, |clone| {
            Some(Scalar::from_bytes_mod_order_wide(&clone.derive_array(b"commitment-scalar")))
        });
        let i = RistrettoPoint::mul_base(&k);

        // Encode and encrypt the commitment point of the server's signature.
        let mut i = i.compress().to_bytes();
        self.protocol.encrypt(b"server-commitment-point", &mut i);

        // Derive a challenge scalar for the server's signature.
        let r = Scalar::from_bytes_mod_order_wide(
            &self.protocol.derive_array(b"server-challenge-scalar"),
        );

        // Calculate and encrypt the proof scalar for the server's signature.
        let mut s = ((self.static_priv * r) + k).to_bytes();
        self.protocol.encrypt(b"server-proof-scalar", &mut s);

        // Return a connected state object and a handshake response, containing the encrypted
        // commitment point and the encrypted proof scalar.
        Some((ConnectedServer::new(&self.protocol), HandshakeResponse { i, s }))
    }
}

pub struct ConnectedServer {
    send: Protocol,
    receive: Protocol,
}

impl ConnectedServer {
    pub fn new(protocol: &Protocol) -> ConnectedServer {
        let mut send = protocol.clone();
        send.mix(b"sender", b"server");

        let mut receive = protocol.clone();
        receive.mix(b"sender", b"client");

        ConnectedServer { send, receive }
    }

    pub fn send(&mut self, in_out: &mut [u8]) {
        self.send.seal(b"message", in_out);
    }

    pub fn receive<'a>(&mut self, in_out: &'a mut [u8]) -> Option<&'a [u8]> {
        self.receive.open(b"message", in_out)
    }
}
