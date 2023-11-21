use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use lockstitch::Protocol;
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone, Copy)]
pub struct HandshakeRequest {
    pub ephemeral_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub i: [u8; 32],
    pub s: [u8; 32],
}

impl HandshakeRequest {
    pub fn from_bytes(b: [u8; HANDSHAKE_REQ_LEN]) -> HandshakeRequest {
        HandshakeRequest {
            ephemeral_pub: b[..32].try_into().expect("should be 32 bytes"),
            static_pub: b[32..64].try_into().expect("should be 32 bytes"),
            i: b[64..96].try_into().expect("should be 32 bytes"),
            s: b[96..].try_into().expect("should be 32 bytes"),
        }
    }

    pub fn to_bytes(self) -> [u8; HANDSHAKE_REQ_LEN] {
        let mut req = [0u8; HANDSHAKE_REQ_LEN];
        req[..32].copy_from_slice(&self.ephemeral_pub);
        req[32..64].copy_from_slice(&self.static_pub);
        req[64..96].copy_from_slice(&self.i);
        req[96..].copy_from_slice(&self.s);
        req
    }
}

pub const HANDSHAKE_REQ_LEN: usize = 32 + 32 + 32 + 32;

#[derive(Debug, Clone, Copy)]
pub struct HandshakeResponse {
    pub i: [u8; 32],
    pub s: [u8; 32],
}

impl HandshakeResponse {
    pub fn from_bytes(b: [u8; HANDSHAKE_RESP_LEN]) -> HandshakeResponse {
        HandshakeResponse {
            i: b[..32].try_into().expect("should be 32 bytes"),
            s: b[32..].try_into().expect("should be 32 bytes"),
        }
    }

    pub fn to_bytes(self) -> [u8; HANDSHAKE_RESP_LEN] {
        let mut resp = [0u8; HANDSHAKE_RESP_LEN];
        resp[..32].copy_from_slice(&self.i);
        resp[32..].copy_from_slice(&self.s);
        resp
    }
}

pub const HANDSHAKE_RESP_LEN: usize = 32 + 32;

pub struct ClientHandshake {
    protocol: Protocol,
    static_priv: Scalar,
    static_pub: [u8; 32],
    ephemeral_priv: Scalar,
    ephemeral_pub: [u8; 32],
    server_static_pub: RistrettoPoint,
}

impl ClientHandshake {
    pub fn new(
        mut rng: impl RngCore + CryptoRng,
        static_priv: Scalar,
        server_static_pub: RistrettoPoint,
    ) -> ClientHandshake {
        // Calculate and encode the client's static public key.
        let static_pub = RistrettoPoint::mul_base(&static_priv).compress().to_bytes();

        // Generate an ephemeral private key and calculate and encode the ephemeral public key.
        let ephemeral_priv = Scalar::random(&mut rng);
        let ephemeral_pub = RistrettoPoint::mul_base(&ephemeral_priv).compress().to_bytes();

        ClientHandshake {
            protocol: Protocol::new("yrgourd.v1"),
            static_priv,
            static_pub,
            ephemeral_priv,
            ephemeral_pub,
            server_static_pub,
        }
    }

    pub fn request(&mut self, mut rng: impl RngCore + CryptoRng) -> HandshakeRequest {
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

    pub fn finalize(&mut self, response: &HandshakeResponse) -> Option<(Protocol, Protocol)> {
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

#[derive(Clone)]
pub struct ServerHandshake {
    protocol: Protocol,
    static_priv: Scalar,
    static_pub: [u8; 32],
}

impl ServerHandshake {
    pub fn new(static_priv: Scalar) -> ServerHandshake {
        // Calculate and encode the server's static public key.
        let static_pub = RistrettoPoint::mul_base(&static_priv).compress().to_bytes();
        ServerHandshake { protocol: Protocol::new("yrgourd.v1"), static_priv, static_pub }
    }

    /// Response to a client handshake request. If the handshake request is valid, returns a
    /// connected state object and a handshake response to be sent to the client.
    pub fn respond(
        &mut self,
        mut rng: impl RngCore + CryptoRng,
        handshake: &HandshakeRequest,
    ) -> Option<(Protocol, Protocol, HandshakeResponse)> {
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

        // Fork the protocol into receiver and sender clones.
        let mut receiver = self.protocol.clone();
        receiver.mix(b"sender", b"client");
        let mut sender = self.protocol.clone();
        sender.mix(b"sender", b"server");

        // Return a connected state object and a handshake response, containing the encrypted
        // commitment point and the encrypted proof scalar.
        Some((receiver, sender, HandshakeResponse { i, s }))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let server_priv = Scalar::random(&mut rng);
        let server_pub = RistrettoPoint::mul_base(&server_priv);
        let mut server = ServerHandshake::new(server_priv);

        let client_priv = Scalar::random(&mut rng);
        let mut client = ClientHandshake::new(&mut rng, client_priv, server_pub);

        let handshake_req = client.request(&mut rng);
        let (mut server_recv, mut server_send, handshake_resp) = server
            .respond(&mut rng, &handshake_req)
            .expect("should handle client request successfully");

        let (mut client_recv, mut client_send) =
            client.finalize(&handshake_resp).expect("should handle server response successfully");

        assert_eq!(server_recv.derive_array::<8>(b"test"), client_send.derive_array::<8>(b"test"));
        assert_eq!(client_recv.derive_array::<8>(b"test"), server_send.derive_array::<8>(b"test"));
    }
}
