# yrgourd

WARNING: You should, under no circumstances, use this.

yrgourd uses [Lockstitch](https://github.com/codahale/lockstitch) to establish mutually
authenticated, confidential connections. Like a toy Wireguard.

## Demo

First, generate a couple of key pairs:

```shell
yrgourd-cli generate-key
```

Second, start up a plaintext echo server:

```shell
yrgourd-cli echo
```

Third, start up an encrypted reverse proxy server:

```shell
yrgourd-cli reverse-proxy --private-key=${PRIVATE_KEY_A}
```

Fourth, start up an encrypted proxy server:

```shell
yrgourd-cli proxy --private-key=${PRIVATE_KEY_B} --server-public-key=${PUBLIC_KEY_A}
```

Finally, start up a plaintext connect client:

```shell
yrgourd-cli connect
```

Anything you write to `STDIN` will be sent via the proxy server and reverse proxy server to the echo
server and returned.

```text
connect <--plaintext--> proxy <--yrgourd encrypted--> reverse-proxy <--plaintext--> echo
```

## Design

Both client and server have Ristretto255 key pairs; the client knows the server's public key.

The client initiates a handshake by generating an ephemeral key pair and executing the following:

```text
function client_init(client, server.pub):
  ephemeral ← ristretto255::key_gen()                                // Generate an ephemeral key pair.
  yg ← init("yrgourd.v1")                                            // Initialize a protocol with a domain string.
  yg ← mix(yg, "server-static-pub", server.pub)                      // Mix the server's public key into the protocol.
  yg ← mix(yg, "client-ephemeral-pub", ephemeral.pub)                // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "ephemeral-shared", ecdh(server.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, a) ← encrypt(yg, "client-static-pub", client.pub)             // Encrypt the client's public key.
  yg ← mix(yg, "static-shared", ecdh(server.pub, client.priv))       // Mix the static ECDH shared secret into the protocol.
  (k, I) ← ristretto255::key_gen()                                   // Generate a commitment scalar and point.
  (yg, b) ← encrypt(yg, "client-commitment-point", I)                       // Encrypt the commitment point.
  (yg, r) ← ristretto255::scalar(derive(yg, "client-challenge-scalar", 64)) // Derive a challenge scalar.
  s ← client.priv * r + k                                            // Calculate the proof scalar.
  (yg, c) ← encrypt(yg, "client-proof-scalar", s)                           // Encrypt the proof scalar.
  return (yg, ephemeral.pub, a, b, c)
```

The client sends the plaintext ephemeral public key, the encrypted static public key, the encrypted
commitment point, and the encrypted proof scalar to the server.

The server executes the following:

```text
function server_accept(server.pub, ephemeral.pub, a, b, c):
  yg ← init("yrgourd.v1")                                                    // Initialize a protocol with a domain string.
  yg ← mix(yg, "server-static-pub", server.pub)                              // Mix the server's public key into the protocol.
  yg ← mix(yg, "client-ephemeral-pub", ephemeral.pub)                        // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "ephemeral-shared", ecdh(server.pub, ephemeral.priv))         // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, client.pub) ← decrypt(yg, "client-static-pub", a)                     // Decrypt the client's public key.
  yg ← mix(yg, "static-shared", ecdh(server.pub, client.priv))               // Mix the static ECDH shared secret into the protocol.
  (yg, I) ← encrypt(yg, "client-commitment-point", b)                        // Decrypt the commitment point.
  (yg, r′) ← ristretto255::scalar(derive(yg, "client-challenge-scalar", 64)) // Derive a counterfactual challenge scalar.
  (yg, s) ← decrypt(yg, "client-proof-scalar", c)                            // Decrypt the proof scalar.
  I′ ← [s]G - [r′]client.pub                                                 // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                 // Compare the two points.
    return ⊥                                                                 // Return an error if they're not equal.
  (k, I) ← ristretto255::key_gen()                                           // Generate a commitment scalar and point.
  (yg, B) ← encrypt(yg, "server-commitment-point", I)                        // Encrypt the commitment point.
  (yg, r) ← ristretto255::scalar(derive(yg, "server-challenge-scalar", 64))  // Derive a challenge scalar.
  s ← server.priv * r + k                                                    // Calculate the proof scalar.
  (yg, C) ← encrypt(yg, "server-proof-scalar", s)                            // Encrypt the proof scalar.
  return (yg, B, C)
```

The server sends the encrypted commitment point and the encrypted proof scalar to the client.

The client performs the following:

```text
function client_finalize(yg, server.pub, B, C):
  (yg, I) ← decrypt(yg, "server-commitment-point", B)                        // Decrypt the commitment point.
  (yg, r′) ← ristretto255::scalar(derive(yg, "server-challenge-scalar", 64)) // Derive a challenge scalar.
  (yg, s) ← encrypt(yg, "server-proof-scalar", C)                            // Decrypt the proof scalar.
  I′ ← [s]G - [r′]server.pub                                                 // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                 // Compare the two points.
    return ⊥                                                                 // Return an error if they're not equal.
  yg_recv ← mix(yg, "sender", "server")                                      // Clone a receive-specific protocol for transport.
  yg_send ← mix(yg, "sender", "client")                                      // Clone a send-specific protocol for transport.
  return (yg_recv, yg_send)
```

The server also performs the following:

```text
function server_finalize(yg):
  yg_recv ← mix(yg, "sender", "client") // Clone a receive-specific protocol for transport.
  yg_send ← mix(yg, "sender", "server") // Clone a send-specific protocol for transport.
  return (yg_recv, yg_send)
```

Now the client and server each have two protocols: `yg_recv` for decrypting received packets, and
`yg_send` for encrypting sent packets.

Transport between the client and server uses length-delimited frames with a 3-byte little-endian
length prepended to each packet. (The length does not include these 3 bytes.)

To send a packet, the client would perform the following:

```text
yg_send ← seal(yg_send, "message", message)
```

To receive a packet, the client would perform the following:

```text
yg_recv ← open(yg_recv, "message", message)
```

The client's `yg_send` and the server's `yg_recv` stay synchronized, likewise with the client's
`yg_recv` and the server's `yg_send`.

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
