pub struct HandshakeRequest {
    pub ephemeral_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub i: [u8; 32],
    pub s: [u8; 32],
}

pub struct HandshakeResponse {
    pub i: [u8; 32],
    pub s: [u8; 32],
}
