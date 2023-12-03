# Yrgourd

Yrgourd uses [Lockstitch][] to establish mutually-authenticated, forward-secure, confidential,
high-performance connections. Like a toy Wireguard.

[Lockstitch]: https://github.com/codahale/lockstitch

## ⚠️ WARNING: You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. It uses
very recent cryptographic algorithms in slightly heterodox ways and may well be just an absolutely
terrible idea. The design is documented [below](#design); read it and see if the arguments therein
are convincing.

In addition, there is absolutely no guarantee of backwards compatibility.

## Things It Does

* Uses [Ristretto255][] for asymmetric operations and SHA-256/[AEGIS-128L][] for symmetric operations.
* Capable of >10 Gb/sec throughput.
* Everything but the first 32 bytes of a connection is encrypted.
* Handshakes are both sender and receiver forward-secure.
* Handshakes are authenticated via Schnorr signatures from both initiator and acceptor.
* Uses ephemeral keys to ratchet the connection state every `N` seconds or `M` bytes.
* Acceptors can restrict handshakes to a set of valid initiator public keys.
* Core logic for handshakes and transport is <500 LoC.

[Ristretto255]: https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-08.html
[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-06.html

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
connect <--plaintext--> proxy <--encrypted--> reverse-proxy <--plaintext--> echo
```

## Design

Both initiator and acceptor have [Ristretto255][] key pairs; the initiator knows the acceptor's
public key.

The initiator initiates a handshake by generating an ephemeral key pair and executing the following:

```text
function initiator_init(initiator, acceptor.pub):
  ephemeral ← ristretto255::key_gen()                                            // Generate an ephemeral key pair.
  yg ← init("yrgourd.v1")                                                        // Initialize a protocol with a domain string.
  yg ← mix(yg, "acceptor-static-pub", acceptor.pub)                              // Mix the acceptor's public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-pub", ephemeral.pub)                         // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-shared", ecdh(acceptor.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, a) ← encrypt(yg, "initiator-static-pub", initiator.pub)                   // Encrypt the initiator's public key.
  yg ← mix(yg, "static-shared", ecdh(acceptor.pub, initiator.priv))              // Mix the static ECDH shared secret into the protocol.
  (k, I) ← ristretto255::key_gen()                                               // Generate a commitment scalar and point.
  (yg, b) ← encrypt(yg, "initiator-commitment-point", I)                         // Encrypt the commitment point.
  (yg, r) ← ristretto255::scalar(derive(yg, "initiator-challenge-scalar", 64))   // Derive a challenge scalar.
  s ← initiator.priv * r + k                                                     // Calculate the proof scalar.
  (yg, c) ← encrypt(yg, "initiator-proof-scalar", s)                             // Encrypt the proof scalar.
  return (yg, ephemeral.pub, a, b, c)
```

The initiator sends the plaintext ephemeral public key, the encrypted static public key, the
encrypted commitment point, and the encrypted proof scalar to the acceptor. The initiator discards
the ephemeral private key, providing forward secrecy for the handshake.

The acceptor executes the following:

```text
function acceptor_accept(acceptor, ephemeral.pub, a, b, c):
  yg ← init("yrgourd.v1")                                                        // Initialize a protocol with a domain string.
  yg ← mix(yg, "acceptor-static-pub", acceptor.pub)                              // Mix the acceptor's public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-pub", ephemeral.pub)                         // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-shared", ecdh(acceptor.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, initiator.pub) ← decrypt(yg, "initiator-static-pub", a)                   // Decrypt the initiator's public key.
  yg ← mix(yg, "static-shared", ecdh(acceptor.pub, initiator.priv))              // Mix the static ECDH shared secret into the protocol.
  (yg, I) ← encrypt(yg, "initiator-commitment-point", b)                         // Decrypt the commitment point.
  (yg, r′) ← ristretto255::scalar(derive(yg, "initiator-challenge-scalar", 64))  // Derive a counterfactual challenge scalar.
  (yg, s) ← decrypt(yg, "initiator-proof-scalar", c)                             // Decrypt the proof scalar.
  I′ ← [s]G - [r′]initiator.pub                                                  // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                     // Compare the two points.
    return ⊥                                                                     // Return an error if they're not equal.
  ephemeral ← ristretto255::key_gen()                                            // Generate an ephemeral key pair.
  (yg, A) ← encrypt(yg, "acceptor-ephemeral-pub", ephemeral.pub)                 // Encrypt the ephemeral public key.
  yg ← mix(yg, "acceptor-ephemeral-shared", ecdh(initiator.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, I) ← encrypt(yg, "initiator-commitment-point", b)                         // Decrypt the commitment point.
  (k, I) ← ristretto255::key_gen()                                               // Generate a commitment scalar and point.
  (yg, B) ← encrypt(yg, "acceptor-commitment-point", I)                          // Encrypt the commitment point.
  (yg, r) ← ristretto255::scalar(derive(yg, "acceptor-challenge-scalar", 64))    // Derive a challenge scalar.
  s ← acceptor.priv * r + k                                                      // Calculate the proof scalar.
  (yg, C) ← encrypt(yg, "acceptor-proof-scalar", s)                              // Encrypt the proof scalar.
  return (yg, A, B, C)
```

The acceptor sends the encrypted commitment point and the encrypted proof scalar to the initiator.
Finally, the acceptor discards the ephemeral private key, providing forward secrecy.

The initiator performs the following:

```text
function initiator_finalize(yg, initiator, acceptor.pub, A, B, C):
  (yg, ephemeral.pub) ← decrypt(yg, "acceptor-ephemeral-pub", A)                 // Decrypt the ephemeral public key.
  yg ← mix(yg, "acceptor-ephemeral-shared", ecdh(ephemeral.pub, initiator.priv)) // Mix the static ECDH shared secret into the protocol.
  (yg, I) ← decrypt(yg, "acceptor-commitment-point", B)                          // Decrypt the commitment point.
  (yg, r′) ← ristretto255::scalar(derive(yg, "acceptor-challenge-scalar", 64))   // Derive a challenge scalar.
  (yg, s) ← encrypt(yg, "acceptor-proof-scalar", C)                              // Decrypt the proof scalar.
  I′ ← [s]G - [r′]acceptor.pub                                                   // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                     // Compare the two points.
    return ⊥                                                                     // Return an error if they're not equal.
  yg_recv ← mix(yg, "sender", "acceptor")                                        // Clone a receive-specific protocol for transport.
  yg_send ← mix(yg, "sender", "initiator")                                       // Clone a send-specific protocol for transport.
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

Transport between the initiator and acceptor uses length-delimited frames with a 3-byte big-endian
length prepended to each packet. (The length does not include these 3 bytes.)

To send a frame, the sender would perform the following:

```text
(yg_send, len) ← encrypt(yg_send, "len", u24_le(|frame|))
(yg_send, frame) ← seal(yg_send, "frame", frame)
```

To receive a packet, the receiver would perform the following:

```text
(yg_recv, len) ← decrypt(yg_recv, "len", len)
(yg_recv, frame) ← open(yg_recv, "frame", frame)
```

The initiator's `yg_send` and the acceptor's `yg_recv` stay synchronized, likewise with the
initiator's `yg_recv` and the acceptor's `yg_send`.

Each frame begins with a frame type. A frame which begins with a `1` contains only data. A frame
with a `2` contains a Ristretto255 public key prepended to the data for ratcheting. To initiate a
ratchet, the transport sends a `2` frame and then performs the following:

```text
yg_send ← mix(yg_send, "ratchet-shared", ecdh(remote.pub, ratchet.priv))
```

The receiver, upon decrypting a `2` frame performs the following:

```text
yg_recv ← mix(yg_recv, "ratchet-shared", ecdh(ratchet.pub, local.priv))
```

Ratchets are performed every two minutes, or on every frame if fewer than one frame is sent every
two minutes.

## Performance

On my M2 MacBook Air:

```text
Timer precision: 41.66 ns
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  366.7 µs      │ 553.7 µs      │ 400.7 µs      │ 403.3 µs      │ 1945    │ 1945
╰─ transfer   27.14 ms      │ 30.25 ms      │ 28.15 ms      │ 28.18 ms      │ 100     │ 100
              3.598 GiB/s   │ 3.227 GiB/s   │ 3.468 GiB/s   │ 3.464 GiB/s   │         │
```

On a GCP `c3-standard-4`:

```text
Timer precision: 25.18 ns
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  508.5 µs      │ 869.6 µs      │ 558.3 µs      │ 561.8 µs      │ 1455    │ 1455
╰─ transfer   39.55 ms      │ 50.09 ms      │ 44.98 ms      │ 44.69 ms      │ 100     │ 100
              2.468 GiB/s   │ 1.949 GiB/s   │ 2.17 GiB/s    │ 2.184 GiB/s   │         │

```

`handshake` measures the time it takes to establish a Yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a Yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
