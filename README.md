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

* Uses [ML-KEM-768][] for asymmetric operations and [SHA-256][]/[AEGIS-128L][] for symmetric
  operations.
* Capable of >10 Gb/sec throughput.
* Everything in a connection is encrypted.
* Handshakes use a static/ephemeral ML-KEM handshake to authenticate both sender and receiver with
  forward security for both.
* Uses ML-KEM ciphertexts to ratchet the connection state every `N` seconds or `M` bytes.
* Responders can restrict handshakes to a set of valid initiator public keys.
* Core logic for handshakes and transport is <500 LoC.

[SHA-256]: https://doi.org/10.6028/NIST.FIPS.180-4
[ML-KEM-768]: https://csrc.nist.gov/pubs/fips/203/ipd
[AEGIS-128L]: https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-15.html

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

Both initiator and responder have [ML-KEM-768][] key pairs; the initiator knows the
responder's public key. The handshake is the `Kyber.AKE` construction from the original [Kyber][]
paper with the addition of encrypting the initiator's public keys and a confirmation tag in the
response.

[Kyber]: <https://eprint.iacr.org/2017/634>

The initiator starts with a static private key `(is, IS)` and the responder's static public key
`RS`:

```text
function initiate((is, IS), RS):
  (ie, IE) ← ml_kem::keygen()      // Generate a random ephemeral key.
  yg ← init("yrgourd.v1")          // Initialize a protocol.
  yg ← mix(yg, "rs", RS)           // Mix in the responder's static public key,
  (c0, ss) ← ml_kem::encap(RS)     // Encapsulate a random key with ML-KEM-768.
  yg ← mix(yg, "rs-ct", c0)        // Mix in the ML-KEM ciphertext.
  yg ← mix(yg, "rs-ss", ss)        // Mix in the ML-KEM shared secret.
  (yg, c1) ← encrypt(yg, "is", IS) // Encrypt the initiator's static public key.
  (yg, c2) ← seal(yg, "ie", IE)    // Seal the initiator's ephemeral public key.
  return ((yg, ie), c0, c1, c2)
```

The initiator sends the ML-KEM-768 ciphertext `c0`, the encrypted static public key `c1`, and the
sealed ephemeral public key `c2` to the responder and keeps `yg` and `ie` as private state.

The responder starts with a static private key `(rs, RS)`:

```text
function accept((rs, RS), c0, c1, c2):
  yg ← init("yrgourd.v1")                  // Initialize a protocol.
  yg ← mix(yg, "rs", RS)                   // Mix in the responder's static public key.

  rs_ss ← ml_kem::decap(rs, c0)            // Decapsulate the ML-KEM_768 ciphertext.
  yg ← mix(yg, "rs-ct", c0)                // Mix in the ML-KEM ciphertext.
  yg ← mix(yg, "rs-ss", rs_ss)             // Mix in the ML-KEM shared secret.
  (yg, IE) ← decrypt(yg, "ia", c1)         // Decrypt the initiator's static public key.
  (yg, IS) ← open(yg, "ie", c2)            // Open the initiator's ephemeral public key.

  (is_ct, is_ss) ← ml_kem::encap(IS)       // Encapsulate a random key with ML-KEM-768.
  (yg, c3) ← encrypt(yg, "is-ct", is_ct)   // Encrypt the ML-KEM ciphertext.
  yg ← mix(yg, "is-ss", is_ss)             // Mix in the ML-KEM shared secret.

  (ie_ct, ie_ss) ← ml_kem::encap(IE)       // Encapsulate a random key with ML-KEM-768.
  (yg, c4) ← seal(yg, "ie-ct", ie_ct)      // Seal the ML-KEM ciphertext.
  yg ← mix(yg, "ie-ss", ie_ss)             // Mix in the ML-KEM shared secret.

  yg_recv ← mix(yg, "sender", "responder") // Fork the protocol into a (recv, send) pair.
  yg_send ← mix(yg, "sender", "initiator")
  return ((yg_recv, yg_send), c3, c4)
```

The responder sends the ML-KEM-768 ciphertexts `c3` and `c4` to the initiator.

The initiator performs the following:

```text
function finalize(yg, is, ie, c3, c4):
  (ig, is_ct) ← decrypt(yg, "is-ct", c3)   // Decrypt the ciphertext.
  is_ss ← ml_kem::decap(is_ct)             // Decapsulate the shared secret.
  yg ← mix(yg, "is-ss", is_ss)             // Mix in the ML-KEM shared secret.

  (ig, ie_ct) ← open(yg, "ie-ct", c4)      // Open the ciphertext.
  ie_ss ← ml_kem::decap(ie_ct)             // Decapsulate the shared secret.
  yg ← mix(yg, "ie-ss", ie_ss)             // Mix in the ML-KEM shared secret.

  yg_recv ← mix(yg, "sender", "responder") // Fork the protocol into a (recv, send) pair.
  yg_send ← mix(yg, "sender", "initiator")
  return (yg_recv, yg_send)
```

Now the initiator and responder each have two protocols: `yg_recv` for decrypting received packets,
and `yg_send` for encrypting sent packets. The initiator discards their ephemeral keys and both
parties discard their shared secrets. An adversary who recovers the initiator's private key will be
unable to decapsulate the first shared secret (`rs_ss`) and thus unable to decrypt the rest of the
data. An adversary who recovers the responder's private key will be able to recover `rs_ss` but
unable to decapsulate the next two shared secrets (`is_ss` and `ie_ss`). An adversary who recovers
both will be able to decapsulate both `rs_ss` and `is_ss` but unable to decapsulate `ie_ss`.

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
with a `2` contains an ML-KEM-768 ciphertext prepended to the data for ratcheting. To initiate a
ratchet, the transport sends a `2` frame and then performs the following:

```text
let (ct, ss) ← ml_kem::encap(remote.pub)
yg_send ← mix(yg_send, "ratchet-ss", ss)
```

The receiver, upon decrypting a `2` frame performs the following:

```text
ss ← ml_kem::decap(local.priv, ct)
yg_recv ← mix(yg_recv, "ratchet-ss", ss)
```

Ratchets are performed every two minutes, or on every frame if fewer than one frame is sent every
two minutes.

## Performance

On my M3 MacBook Pro:

```text
handshake               time:   [261.38 µs 261.49 µs 261.62 µs]

transfer/1MiB           time:   [524.25 µs 525.74 µs 527.98 µs]
                        thrpt:  [1.8496 GiB/s 1.8575 GiB/s 1.8628 GiB/s]
transfer/10MiB          time:   [2.2045 ms 2.2097 ms 2.2147 ms]
                        thrpt:  [4.4094 GiB/s 4.4195 GiB/s 4.4298 GiB/s]
transfer/100MiB         time:   [17.670 ms 17.794 ms 17.975 ms]
                        thrpt:  [5.4329 GiB/s 5.4882 GiB/s 5.5267 GiB/s]
transfer/1GiB           time:   [177.49 ms 178.14 ms 178.84 ms]
                        thrpt:  [5.5917 GiB/s 5.6136 GiB/s 5.6343 GiB/s]
```

`handshake` measures the time it takes to establish a Yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a Yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2024-2025 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
