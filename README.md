# Yrgourd

Yrgourd uses [Lockstitch][] to establish mutually-authenticated, forward-secure, confidential,
high-performance connections secure against both classical and post-quantum adversaries. Like a toy
Wireguard.

[Lockstitch]: https://github.com/codahale/lockstitch

## ⚠️ WARNING: You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated. It uses
very recent cryptographic algorithms in slightly heterodox ways and may well be just an absolutely
terrible idea. The design is documented [below](#design); read it and see if the arguments therein
are convincing.

In addition, there is absolutely no guarantee of backwards compatibility.

## Things It Does

* Uses [X25519][] and [ML-KEM-768][] for asymmetric operations and [TurboSHAKE128][]/[AEGIS-128L][]
  for symmetric operations.
* Capable of >10 Gb/sec throughput.
* Everything in a connection is encrypted.
* Handshakes use Noise-IK-style ECDH/ML-KEM to authenticate both sender and receiver with forward
  security for both.
* Uses ephemeral keys and ML-KEM ciphertexts to ratchet the connection state every `N` seconds or
  `M` bytes.
* Responders can restrict handshakes to a set of valid initiator public keys.
* Core logic for handshakes and transport is <500 LoC.

[X25519]: https://www.rfc-editor.org/rfc/rfc7748.html
[ML-KEM-768]: https://csrc.nist.gov/pubs/fips/203/ipd
[TurboSHAKE128]: https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-13.html
[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-10.html

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

Both initiator and responder have [X25519][]/[ML-KEM-768] key pairs; the initiator knows the
responder's public key. The handshake is effectively the same as the `IK` handshake in the [Noise][]
protocol framework with an [ML-KEM-768][] prefix, providing full mutual authentication as well as
identity-hiding.

[Noise]: https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental

The initiator starts with a static private key `(is, IS)` and the responder's static public key
`RS`:

```text
function initiate((is, IS), RS):
  ie ← rand(32)                               // Generate the initiator's ephemeral X25519 private key.
  yg ← init("yrgourd.v1")                     // Initialize a protocol.
  yg ← mix(yg, "rs", RS)                      // Mix in the responder's static public key,
  (c0, ss) ← ml_kem_encap(RS)                 // Encapsulate a random key with ML-KEM-768.
  yg ← mix(yg, "rs-ml-kem-768-ct", c0)        // Mix in the ML-KEM ciphertext.
  yg ← mix(yg, "rs-ml-kem-768-ss", ss)        // Mix in the ML-KEM shared secret.
  (yg, c1) ← encrypt(yg, "ie", x25519(ie, G)) // Encrypt the initiator's ephemeral public key.
  yg ← mix(yg, "ie-rs", x25519(ie, RS))       // Mix in the ephemeral/static shared secret.
  (yg, c2) ← seal(yg, "is", IS)               // Seal the initiator's static public key.
  yg ← mix(yg, "is-rs", x25519(is, RS))       // Mix in the static/static shared secret.
  return (yg, ie, ct, c0, c2)
```

The initiator sends the ML-KEM-768 ciphertext `c0`, the encrypted ephemeral X25519 public key `c1`,
and the encrypted static X25519/ML-KEM-768 public key `c2` to the responder and keeps `yg` and `ie`
as private state.

The responder starts with a static private key `(rs, RS)`:

```text
function accept((rs, RS), c0, c1, c2):
  re ← rand(32)                            // Generate the responder's ephemeral X25519 private key.
  yg ← init("yrgourd.v1")                  // Initialize a protocol.
  yg ← mix(yg, "rs", RS)                   // Mix in the responder's static public key.
  ss ← ml_kem_decap(rs, c0)                // Decapsulate the ML-KEM_768 ciphertext.
  yg ← mix(yg, "rs-ml-kem-768-ct", c0)     // Mix in the ML-KEM ciphertext.
  yg ← mix(yg, "rs-ml-kem-768-ss", ss)     // Mix in the ML-KEM shared secret.
  (yg, IE) ← decrypt(yg, "ie", c1)         // Mix in the initiator's ephemeral public key.
  yg ← mix(yg, "ie-rs", [rs]IE))           // Mix in the ephemeral/static shared secret.
  (yg, IS) ← open(yg, "is", c0)            // Open the responder's static public key.
  yg ← mix(yg, "is-rs", [rs]IS))           // Mix in the static/static shared secret.

  (c3, ss) ← ml_kem_encap(IS)              // Encapsulate a random key with ML-KEM-768.
  yg ← mix(yg, "is-ml-kem-768-ct", c3)     // Mix in the ML-KEM ciphertext.
  yg ← mix(yg, "is-ml-kem-768-ss", ss)     // Mix in the ML-KEM shared secret.
  (yg, c4) ← seal(yg, "re", x25519(re, G)) // Seal the responder's ephemeral public key.
  yg ← mix(yg, "ie-re", x25519(re, IE))    // Mix in the ephemeral/ephemeral shared secret.
  yg ← mix(yg, "is-re", x25519(re, IS))    // Mix in the static/ephemeral shared secret.
  yg_recv ← mix(yg, "sender", "responder") // Fork the protocol into a (recv, send) pair.
  yg_send ← mix(yg, "sender", "initiator")
  return (yg_recv, yg_send, c3, c4)
```

The responder sends the encrypted ephemeral public key `c1` to the initiator.

The initiator performs the following:

```text
function finalize(yg, is, ie, c3, c4):
  ss ← ml_kem_decap(rs, c3)                // Decapsulate the ML-KEM_768 ciphertext.
  yg ← mix(yg, "is-ml-kem-768-ct", c3)     // Mix in the ML-KEM ciphertext.
  yg ← mix(yg, "is-ml-kem-768-ss", ss)     // Mix in the ML-KEM shared secret.
  (yg, RE) ← open(yg, "re", c4)            // Open the responder's ephemeral public key.
  yg ← mix(yg, "ie-re", x25519(ie, RE))    // Mix in the ephemeral/ephemeral shared secret.
  yg ← mix(yg, "is-re", x25519(ie, RE))    // Mix in the static/ephemeral shared secret.
  yg_recv ← mix(yg, "sender", "responder") // Fork the protocol into a (recv, send) pair.
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
with a `2` contains an ML-KEM-768 ciphertext and an X25519 public key prepended to the data for
ratcheting. To initiate a ratchet, the transport sends a `2` frame and then performs the following:

```text
yg_send ← mix(yg_send, "ratchet-x25519", x25519(rk, remote.pub, ratchet.priv))
let (ct, ss) ← ml_kem_encap(remote.pub)
yg_send ← mix(yg_send, "ratchet-ml-kem-768", ss)
```

The receiver, upon decrypting a `2` frame performs the following:

```text
yg_recv ← mix(yg_recv, "ratchet-x25519", x25519(rk.pub, local.priv))
ss ← ml_kem_decap(local.priv, ct)
yg_recv ← mix(yg_recv, "ratchet-ml-kem-768", ss)
```

Ratchets are performed every two minutes, or on every frame if fewer than one frame is sent every
two minutes.

## Performance

On my M3 MacBook Air:

```text
handshake               time:   [370.17 µs 371.07 µs 371.30 µs]

transfer/1MiB           time:   [653.47 µs 654.25 µs 657.37 µs]
                        thrpt:  [1.4856 GiB/s 1.4926 GiB/s 1.4944 GiB/s]
transfer/10MiB          time:   [2.2203 ms 2.2412 ms 2.3245 ms]
                        thrpt:  [4.2012 GiB/s 4.3574 GiB/s 4.3983 GiB/s]
transfer/100MiB         time:   [17.134 ms 17.213 ms 17.529 ms]
                        thrpt:  [5.5710 GiB/s 5.6734 GiB/s 5.6996 GiB/s]
transfer/1GiB           time:   [170.13 ms 170.77 ms 173.29 ms]
                        thrpt:  [5.7706 GiB/s 5.8560 GiB/s 5.8777 GiB/s]

```

`handshake` measures the time it takes to establish a Yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a Yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2024 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
