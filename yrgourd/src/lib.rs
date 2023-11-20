pub mod client;
mod messages;
pub mod server;

#[cfg(test)]
mod tests {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use lockstitch::TAG_LEN;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::client::HandshakingClient;
    use crate::server::HandshakingServer;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let server_priv = Scalar::random(&mut rng);
        let server_pub = RistrettoPoint::mul_base(&server_priv);
        let mut server = HandshakingServer::new(server_priv);

        let client_priv = Scalar::random(&mut rng);
        let mut client = HandshakingClient::new(&mut rng, client_priv, server_pub);

        let handshake_req = client.request_handshake(&mut rng);
        let (mut server_conn, handshake_resp) = server
            .respond_handshake(&mut rng, &handshake_req)
            .expect("should handle client request successfully");

        let mut client_conn = client
            .process_response(&handshake_resp)
            .expect("should handle server response successfully");

        let mut client_send = b"this is fine".to_vec();
        client_send.extend_from_slice(&[0u8; TAG_LEN]);
        client_conn.send(&mut client_send);

        let server_recv =
            server_conn.receive(&mut client_send).expect("should receive message successfully");
        assert_eq!(server_recv, b"this is fine");

        let mut server_send = b"yeah, it's ok".to_vec();
        server_send.extend_from_slice(&[0u8; TAG_LEN]);
        server_conn.send(&mut server_send);

        let client_recv =
            client_conn.receive(&mut server_send).expect("should receive message successfully");
        assert_eq!(client_recv, b"yeah, it's ok");
    }
}
