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
