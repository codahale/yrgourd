use lockstitch::Protocol;

pub mod client;
pub mod server;

pub struct Connected {
    to_client: Protocol,
    to_server: Protocol,
}

impl Connected {
    pub fn new(protocol: &Protocol) -> Connected {
        let mut connected = Connected { to_client: protocol.clone(), to_server: protocol.clone() };
        connected.to_client.mix(b"direction", b"client");
        connected.to_server.mix(b"direction", b"server");
        connected
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::client::Client;
    use crate::server::Server;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let server_priv = Scalar::random(&mut rng);
        let server_pub = RistrettoPoint::mul_base(&server_priv);
        let mut server = Server::new(server_priv);

        let client_priv = Scalar::random(&mut rng);
        let mut client = Client::new(&mut rng, client_priv, server_pub);

        let handshake_req = client.request_handshake(&mut rng);
        let (mut server_conn, handshake_resp) = server
            .respond_handshake(&mut rng, &handshake_req)
            .expect("should handle client request successfully");

        let mut client_conn = client
            .process_response(&handshake_resp)
            .expect("should handle server response successfully");

        assert_eq!(
            client_conn.to_server.derive_array::<8>(b"test"),
            server_conn.to_server.derive_array::<8>(b"test")
        );

        assert_eq!(
            server_conn.to_client.derive_array::<8>(b"test"),
            client_conn.to_client.derive_array::<8>(b"test")
        );
    }
}
