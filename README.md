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
* Handshakes use FHMQV-C to authenticate both sender and receiver with forward security for both.
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

The handshake combines three layers:

1. An ephemeral Diffie-Hellman KEM to encrypt the initiator's static public key.
2. An [HOMQV][] pass with key confirmation from the initiator to the responder.
3. An [HOMQV][] pass with key confirmation from the responder to the initiator.

[HOMQV]: https://eprint.iacr.org/2010/638.pdf

The initiator starts with a static private key `a` and the responder's static public key `B`. They
initiate a handshake by generating an ephemeral private key `x` and executing the following:

```text
function initiate(a, x, B):
  X ← [x]G
  yg ← init("yrgourd.v1")                             // Initialize a protocol.
  yg ← mix(yg, "responder-static-pub", B)             // Mix in the responder's static public key.
  yg ← mix(yg, "initiator-ephemeral-pub", X)          // Mix in the initiator's ephemeral public key.
  yg ← mix(yg, "ecdh-shared-secret", [x]B))           // Mix in the ephemeral ECDH shared secret.
  (yg, r) ← encrypt(yg, "initiator-static-pub", [a]G) // Encrypt the initiator's static public key.
  (yg, e₀) ← derive(yg, "initiator-challenge", 16)    // Derive the initiator's challenge scalar.
  k₀ ← [x + a * e₀]B                                  // Calculate the initiator's shared secret.
  yg ← mix(yg, "initiator-shared-secret", k₀)         // Mix in the initiator's shared secret.
  (yg, s) ← derive(yg, "initiator-confirmation", 16)  // Derive a key confirmation tag for the initiator.
  return (yg, X, r, s)
```

The initiator sends the plaintext ephemeral public key `X`, the encrypted static public key `r`, and
the confirmation tag `s` to the responder.

The responder starts with a static private key `b`. They accept a handshake by generating an
ephemeral private key `y` and executing the following:

```text
function accept(b, y, X, r, s):
  B ← [b]G
  yg ← init("yrgourd.v1")                                // Initialize a protocol.
  yg ← mix(yg, "responder-static-pub", B)                // Mix in the responder's static public key.
  yg ← mix(yg, "initiator-ephemeral-pub", X)             // Mix in the initiator's ephemeral public key.
  yg ← mix(yg, "ecdh-shared-secret", [b]X)               // Mix in the ephemeral ECDH shared secret.
  (yg, A) ← decrypt(yg, "initiator-static-pub", r)       // Decrypt the initiator's static public key.
  (yg, e₀) ← derive(yg, "initiator-challenge", 16)       // Re-derive the initiator's challenge scalar.
  k₀ ← [b](X + [e₀]A)                                    // Calculate the initiator's shared secret.
  yg ← mix(yg, "initiator-shared-secret", k₀)            // Mix in the initiator's shared secret.
  (yg, s′) ← derive(yg, "initiator-confirmation", 16)    // Derive a counterfactual key confirmation tag for the initiator.
  if s ≠ s′:                                             // Verify the initiator's key confirmation tag.
    return ⟂
  (yg, t) ← encrypt(yg, "responder-ephemeral-pub", [y]G) // Encrypt the responder's ephemeral public key.
  (yg, e₁) ← derive(yg, "responder-challenge", 16)       // Derive the responder's challenge scalar.
  k₁ ← [y + b * e₁]A                                     // Calculate the responder's shared secret.
  yg ← mix(yg, "responder-shared-secret", k₁)            // Mix in the responder's shared secret.
  (yg, u) ← derive(yg, "responder-confirmation", 16)     // Derive a key confirmation tag for the responder.
  yg_recv ← mix(yg, "sender", "initiator")               // Fork the protocol into a receive/send pair.
  yg_send ← mix(yg, "sender", "responder")
  return (yg_recv, yg_send, t, u)
```

The responder sends the encrypted ephemeral public key `t` and the key confirmation tag `u` to the
initiator.

The initiator performs the following:

```text
function finalize(yg, a, B, t, u):
  (yg, Y) ← decrypt(yg, "responder-static-pub", t)    // Decrypt the responder's ephemeral public key.
  (yg, e₁) ← derive(yg, "responder-challenge", 16)    // Re-derive the responder's challenge scalar.
  k₁ ← [a](Y + [e₁]B)                                 // Calculate the responder's shared secret.
  yg ← mix(yg, "responder-shared-secret", k₁)         // Mix in the responder's shared secret.
  (yg, u′) ← derive(yg, "responder-confirmation", 16) // Derive a counterfactual key confirmation tag for the responder.
  if u ≠ u′:                                          // Verify the responder's key confirmation tag.
    return ⟂
  yg_recv ← mix(yg, "sender", "responder")            // Fork the protocol into a receive/send.
  yg_send ← mix(yg, "sender", "initiator")
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
Timer precision: 41.66 ns
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  106.9 µs      │ 365.8 µs      │ 125.8 µs      │ 129.4 µs      │ 7723    │ 7723
╰─ transfer   21.42 ms      │ 23.75 ms      │ 22.04 ms      │ 22.1 ms       │ 100     │ 100
              4.557 GiB/s   │ 4.11 GiB/s    │ 4.429 GiB/s   │ 4.418 GiB/s   │         │
```

On a GCP `c3-standard-4` (`-C target-cpu=native`):

```text
Timer precision: 23.7 ns
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  129.8 µs      │ 958 µs        │ 160 µs        │ 161.7 µs      │ 6183    │ 6183
╰─ transfer   34.62 ms      │ 39.1 ms       │ 36.28 ms      │ 36.3 ms       │ 100     │ 100
              2.82 GiB/s    │ 2.497 GiB/s   │ 2.691 GiB/s   │ 2.689 GiB/s   │         │
```

`handshake` measures the time it takes to establish a Yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a Yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
