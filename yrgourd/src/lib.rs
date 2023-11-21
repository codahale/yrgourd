pub use curve25519_dalek;
pub use lockstitch;

mod client;
mod messages;
mod server;

pub use client::*;
pub use messages::*;
pub use server::*;

#[cfg(test)]
mod tests {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);

        let server_priv = Scalar::random(&mut rng);
        let server_pub = RistrettoPoint::mul_base(&server_priv);
        let mut server = Server::new(server_priv);

        let client_priv = Scalar::random(&mut rng);
        let mut client = Client::new(&mut rng, client_priv, server_pub);

        let handshake_req = client.request_handshake(&mut rng);
        let (mut server_recv, mut server_send, handshake_resp) = server
            .respond_handshake(&mut rng, &handshake_req)
            .expect("should handle client request successfully");

        let (mut client_recv, mut client_send) = client
            .process_response(&handshake_resp)
            .expect("should handle server response successfully");

        assert_eq!(server_recv.derive_array::<8>(b"test"), client_send.derive_array::<8>(b"test"));
        assert_eq!(client_recv.derive_array::<8>(b"test"), server_send.derive_array::<8>(b"test"));
    }
}
