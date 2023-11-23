# yrgourd

WARNING: You should, under no circumstances, use this.

yrgourd uses [Lockstitch][] to establish mutually authenticated, confidential connections. Like a
toy Wireguard.

[Lockstitch]: https://github.com/codahale/lockstitch

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

Both initiator and acceptor have Ristretto255 key pairs; the initiator knows the acceptor's public
key.

The initiator initiates a handshake by generating an ephemeral key pair and executing the following:

```text
function initiator_init(initiator, acceptor.pub):
  ephemeral ← ristretto255::key_gen()                                          // Generate an ephemeral key pair.
  yg ← init("yrgourd.v1")                                                      // Initialize a protocol with a domain string.
  yg ← mix(yg, "acceptor-static-pub", acceptor.pub)                            // Mix the acceptor's public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-pub", ephemeral.pub)                       // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "ephemeral-shared", ecdh(acceptor.pub, ephemeral.priv))         // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, a) ← encrypt(yg, "initiator-static-pub", initiator.pub)                 // Encrypt the initiator's public key.
  yg ← mix(yg, "static-shared", ecdh(acceptor.pub, initiator.priv))            // Mix the static ECDH shared secret into the protocol.
  (k, I) ← ristretto255::key_gen()                                             // Generate a commitment scalar and point.
  (yg, b) ← encrypt(yg, "initiator-commitment-point", I)                       // Encrypt the commitment point.
  (yg, r) ← ristretto255::scalar(derive(yg, "initiator-challenge-scalar", 64)) // Derive a challenge scalar.
  s ← initiator.priv * r + k                                                   // Calculate the proof scalar.
  (yg, c) ← encrypt(yg, "initiator-proof-scalar", s)                           // Encrypt the proof scalar.
  return (yg, ephemeral.pub, a, b, c)
```

The initiator sends the plaintext ephemeral public key, the encrypted static public key, the encrypted
commitment point, and the encrypted proof scalar to the acceptor.

The acceptor executes the following:

```text
function acceptor_accept(acceptor.pub, ephemeral.pub, a, b, c):
  yg ← init("yrgourd.v1")                                                       // Initialize a protocol with a domain string.
  yg ← mix(yg, "acceptor-static-pub", acceptor.pub)                             // Mix the acceptor's public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-pub", ephemeral.pub)                        // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "ephemeral-shared", ecdh(acceptor.pub, ephemeral.priv))          // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, initiator.pub) ← decrypt(yg, "initiator-static-pub", a)                  // Decrypt the initiator's public key.
  yg ← mix(yg, "static-shared", ecdh(acceptor.pub, initiator.priv))             // Mix the static ECDH shared secret into the protocol.
  (yg, I) ← encrypt(yg, "initiator-commitment-point", b)                        // Decrypt the commitment point.
  (yg, r′) ← ristretto255::scalar(derive(yg, "initiator-challenge-scalar", 64)) // Derive a counterfactual challenge scalar.
  (yg, s) ← decrypt(yg, "initiator-proof-scalar", c)                            // Decrypt the proof scalar.
  I′ ← [s]G - [r′]initiator.pub                                                 // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                    // Compare the two points.
    return ⊥                                                                    // Return an error if they're not equal.
  (k, I) ← ristretto255::key_gen()                                              // Generate a commitment scalar and point.
  (yg, B) ← encrypt(yg, "acceptor-commitment-point", I)                         // Encrypt the commitment point.
  (yg, r) ← ristretto255::scalar(derive(yg, "acceptor-challenge-scalar", 64))   // Derive a challenge scalar.
  s ← acceptor.priv * r + k                                                     // Calculate the proof scalar.
  (yg, C) ← encrypt(yg, "acceptor-proof-scalar", s)                             // Encrypt the proof scalar.
  return (yg, B, C)
```

The acceptor sends the encrypted commitment point and the encrypted proof scalar to the initiator.

The initiator performs the following:

```text
function initiator_finalize(yg, acceptor.pub, B, C):
  (yg, I) ← decrypt(yg, "acceptor-commitment-point", B)                        // Decrypt the commitment point.
  (yg, r′) ← ristretto255::scalar(derive(yg, "acceptor-challenge-scalar", 64)) // Derive a challenge scalar.
  (yg, s) ← encrypt(yg, "acceptor-proof-scalar", C)                            // Decrypt the proof scalar.
  I′ ← [s]G - [r′]acceptor.pub                                                 // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                   // Compare the two points.
    return ⊥                                                                   // Return an error if they're not equal.
  yg_recv ← mix(yg, "sender", "acceptor")                                      // Clone a receive-specific protocol for transport.
  yg_send ← mix(yg, "sender", "initiator")                                     // Clone a send-specific protocol for transport.
  return (yg_recv, yg_send)
```

The acceptor also performs the following:

```text
function acceptor_finalize(yg):
  yg_recv ← mix(yg, "sender", "initiator") // Clone a receive-specific protocol for transport.
  yg_send ← mix(yg, "sender", "acceptor")  // Clone a send-specific protocol for transport.
  return (yg_recv, yg_send)
```

Now the initiator and acceptor each have two protocols: `yg_recv` for decrypting received packets,
and `yg_send` for encrypting sent packets.

Transport between the initiator and acceptor uses length-delimited frames with a 3-byte
little-endian length prepended to each packet. (The length does not include these 3 bytes.)

To send a packet, the initiator would perform the following:

```text
yg_send ← seal(yg_send, "message", message)
```

To receive a packet, the initiator would perform the following:

```text
yg_recv ← open(yg_recv, "message", message)
```

The initiator's `yg_send` and the acceptor's `yg_recv` stay synchronized, likewise with the
initiator's `yg_recv` and the acceptor's `yg_send`.

## Performance

On my M2 MacBook Air:

```text
Timer precision: 41.66 ns
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  290.8 µs      │ 571.4 µs      │ 319.6 µs      │ 324 µs        │ 2276    │ 2276
╰─ transfer   24.28 ms      │ 26.66 ms      │ 25.31 ms      │ 25.35 ms      │ 100     │ 100
              4.317 GB/s    │ 3.933 GB/s    │ 4.141 GB/s    │ 4.135 GB/s    │         │
```

`handshake` measures the time it takes to establish a yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
