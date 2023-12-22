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

* Uses [GLS254][] for asymmetric operations and SHA-256/[AEGIS-128L][] for symmetric
  operations.
* Capable of >10 Gb/sec throughput.
* Everything but the first 32 bytes of a connection is encrypted.
* Handshakes are both sender and receiver forward-secure.
* Handshakes are authenticated via Schnorr signatures from both initiator and responder.
* Uses ephemeral keys to ratchet the connection state every `N` seconds or `M` bytes.
* Responders can restrict handshakes to a set of valid initiator public keys.
* Core logic for handshakes and transport is <500 LoC.

[GLS254]: https://eprint.iacr.org/2023/1688
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

Both initiator and responder have [GLS254][] key pairs; the initiator knows the responder's public
key.

The initiator initiates a handshake by generating an ephemeral key pair and executing the following:

```text
function initiator_init(initiator, responder.pub):
  ephemeral ← gls254::key_gen()                                                   // Generate an ephemeral key pair.
  yg ← init("yrgourd.v1")                                                         // Initialize a protocol with a domain string.
  yg ← mix(yg, "responder-static-pub", responder.pub)                             // Mix the responder's public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-pub", ephemeral.pub)                          // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-shared", ecdh(responder.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, a) ← encrypt(yg, "initiator-static-pub", initiator.pub)                    // Encrypt the initiator's public key.
  yg ← mix(yg, "static-shared", ecdh(responder.pub, initiator.priv))              // Mix the static ECDH shared secret into the protocol.
  (k, I) ← gls254::key_gen()                                                      // Generate a commitment scalar and point.
  (yg, b) ← encrypt(yg, "initiator-commitment-point", I)                          // Encrypt the commitment point.
  (yr, r₀ǁr₁) ← derive(yr, "initiator-challenge-scalar", 16)                      // Derive two short challenge scalars.
  r ← r₀ +️️ µ×r₁️                                                                   // Calculate the full challenge scalar using the zeta endomorphism.
  s ← initiator.priv * r + k                                                      // Calculate the proof scalar.
  (yg, c) ← encrypt(yg, "initiator-proof-scalar", s)                              // Encrypt the proof scalar.
  return (yg, ephemeral.pub, a, b, c)
```

The initiator sends the plaintext ephemeral public key, the encrypted static public key, the
encrypted commitment point, and the encrypted proof scalar to the responder. The initiator discards
the ephemeral private key, providing forward secrecy for the handshake.

The responder executes the following:

```text
function responder_accept(responder, ephemeral.pub, a, b, c):
  yg ← init("yrgourd.v1")                                                         // Initialize a protocol with a domain string.
  yg ← mix(yg, "responder-static-pub", responder.pub)                             // Mix the responder's public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-pub", ephemeral.pub)                          // Mix the ephemeral public key into the protocol.
  yg ← mix(yg, "initiator-ephemeral-shared", ecdh(responder.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, initiator.pub) ← decrypt(yg, "initiator-static-pub", a)                    // Decrypt the initiator's public key.
  yg ← mix(yg, "static-shared", ecdh(responder.pub, initiator.priv))              // Mix the static ECDH shared secret into the protocol.
  (yg, I) ← encrypt(yg, "initiator-commitment-point", b)                          // Decrypt the commitment point.
  (yr, r₀′ǁr₁′) ← derive(yr, "initiator-challenge-scalar", 16)                    // Derive two counterfactual short challenge scalars.
  (yg, s) ← decrypt(yg, "initiator-proof-scalar", c)                              // Decrypt the proof scalar.
  I′ ← [s]G - [r₀′]initiator.pub - [r₁'µ]initiator.pub                            // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                      // Compare the two points.
    return ⊥                                                                      // Return an error if they're not equal.
  ephemeral ← gls254::key_gen()                                                   // Generate an ephemeral key pair.
  (yg, A) ← encrypt(yg, "responder-ephemeral-pub", ephemeral.pub)                 // Encrypt the ephemeral public key.
  yg ← mix(yg, "responder-ephemeral-shared", ecdh(initiator.pub, ephemeral.priv)) // Mix the ephemeral ECDH shared secret into the protocol.
  (yg, I) ← encrypt(yg, "initiator-commitment-point", b)                          // Decrypt the commitment point.
  (k, I) ← gls254::key_gen()                                                      // Generate a commitment scalar and point.
  (yg, B) ← encrypt(yg, "responder-commitment-point", I)                          // Encrypt the commitment point.
  (yr, r₀ǁr₁) ← derive(yr, "responder-challenge-scalar", 16)                      // Derive two short challenge scalars.
  r ← r₀ +️️ µ×r₁️                                                                   // Calculate the full challenge scalar using the zeta endomorphism.
  s ← responder.priv * r + k                                                      // Calculate the proof scalar.
  (yg, C) ← encrypt(yg, "responder-proof-scalar", s)                              // Encrypt the proof scalar.
  return (yg, A, B, C)
```

The responder sends the encrypted commitment point and the encrypted proof scalar to the initiator.
Finally, the responder discards the ephemeral private key, providing forward secrecy.

The initiator performs the following:

```text
function initiator_finalize(yg, initiator, responder.pub, A, B, C):
  (yg, ephemeral.pub) ← decrypt(yg, "responder-ephemeral-pub", A)                 // Decrypt the ephemeral public key.
  yg ← mix(yg, "responder-ephemeral-shared", ecdh(ephemeral.pub, initiator.priv)) // Mix the static ECDH shared secret into the protocol.
  (yg, I) ← decrypt(yg, "responder-commitment-point", B)                          // Decrypt the commitment point.
  (yr, r₀′ǁr₁′) ← derive(yr, "responder-challenge-scalar", 16)                    // Derive two counterfactual short challenge scalars.
  (yg, s) ← decrypt(yg, "responder-proof-scalar", c)                              // Decrypt the proof scalar.
  I′ ← [s]G - [r₀′]responder.pub - [r₁'µ]responder.pub                            // Calculate the counterfactual commitment point.
  if I ≠ I′:                                                                      // Compare the two points.
    return ⊥                                                                      // Return an error if they're not equal.
  yg_recv ← mix(yg, "sender", "responder")                                        // Clone a receive-specific protocol for transport.
  yg_send ← mix(yg, "sender", "initiator")                                        // Clone a send-specific protocol for transport.
  return (yg_recv, yg_send)
```

The responder also performs the following:

```text
function responder_finalize(yg):
  yg_recv ← mix(yg, "sender", "initiator") // Clone a receive-specific protocol for transport.
  yg_send ← mix(yg, "sender", "responder") // Clone a send-specific protocol for transport.
  return (yg_recv, yg_send)
```

Now the initiator and responder each have two protocols: `yg_recv` for decrypting received packets,
and `yg_send` for encrypting sent packets. The initiator and responder discard their ephemeral keys,
ensuring forward secrecy for both parties.

Transport between the initiator and responder uses length-delimited frames with a 3-byte big-endian
length prepended to each packet. (The length does not include these 3 bytes.)

To send a frame, the sender would perform the following:

```text
(yg_send, len) ← encrypt(yg_send, "len", u24_le(|frame|))
(yg_send, frame) ← seal(yg_send, "frame", frame)
```

 The tag of the first frame in either direction serves to confirm key agreement.

To receive a packet, the receiver would perform the following:

```text
(yg_recv, len) ← decrypt(yg_recv, "len", len)
(yg_recv, frame) ← open(yg_recv, "frame", frame)
```

The initiator's `yg_send` and the responder's `yg_recv` stay synchronized, likewise with the
initiator's `yg_recv` and the responder's `yg_send`.

Each frame begins with a frame type. A frame which begins with a `1` contains only data. A frame
with a `2` contains a GLS254 public key prepended to the data for ratcheting. To initiate a ratchet,
the transport sends a `2` frame and then performs the following:

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
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  128 µs        │ 10.22 ms      │ 154.2 µs      │ 160.3 µs      │ 6235    │ 6235
╰─ transfer   21.45 ms      │ 25.57 ms      │ 22.07 ms      │ 22.11 ms      │ 100     │ 100
              4.551 GiB/s   │ 3.818 GiB/s   │ 4.423 GiB/s   │ 4.416 GiB/s   │         │
```

On a GCP `c3-standard-4` (`-C target-cpu=native`):

```text
Timer precision: 23.7 ns
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  166.7 µs      │ 1.49 ms       │ 193.7 µs      │ 195.9 µs      │ 5104    │ 5104
╰─ transfer   35.17 ms      │ 39.14 ms      │ 36.88 ms      │ 36.65 ms      │ 100     │ 100
              2.775 GiB/s   │ 2.494 GiB/s   │ 2.647 GiB/s   │ 2.664 GiB/s   │         │
```

`handshake` measures the time it takes to establish a Yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a Yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
