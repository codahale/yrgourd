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
* Handshakes use Noise-IK-style ECDH to authenticate both sender and receiver with forward security
  for both.
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
key. The handshake is effectively the same as the `IK` handshake in the [Noise][] protocol
framework, providing full mutual authentication as well as identity-hiding.

[Noise]: https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental

The initiator starts with a static private key `is` and the responder's static public key `RS`. They
initiate a handshake by generating an ephemeral private key `ie` and executing the following:

```text
function initiate(a, is, ie, RS):
  IE ← [ie]G                       // Calculate the initiator's ephemeral public key.
  yg ← init("yrgourd.v1")          // Initialize a protocol.
  yg ← mix(yg, "rs", RS)           // Mix in the responder's static public key,
  yg ← mix(yg, "ie", IE)           // Mix in the initiator's ephemeral public key.
  yg ← mix(yg, "ie-rs", [ie]RS))   // Mix in the ephemeral/static shared secret.
  (yg, c0) ← seal(yg, "is", [is]G) // Seal the initiator's static public key.
  yg ← mix(yg, "is-rs", [is]RS))   // Mix in the static/static shared secret.
  return (yg, IE, c0)
```

The initiator sends the plaintext ephemeral public key `IE` and the encrypted static public key `c0`
to the responder.

The responder starts with a static private key `rs`. They accept a handshake by generating an
ephemeral private key `re` and executing the following:

```text
function accept(rs, re, IE, c0):
  yg ← init("yrgourd.v1")                  // Initialize a protocol.
  yg ← mix(yg, "rs", [rs]G)                // Mix in the responder's static public key.
  yg ← mix(yg, "ie", IE)                   // Mix in the initiator's ephemeral public key.
  yg ← mix(yg, "ie-rs", [rs]IE))           // Mix in the ephemeral/static shared secret.
  (yg, IS) ← open(yg, "is", c0)            // Open the responder's static public key.
  yg ← mix(yg, "is-rs", [rs]IS))           // Mix in the static/static shared secret.
  (yg, c1) ← seal(yg, "re", [re]G)         // Seal the responder's ephemeral public key.
  yg ← mix(yg, "ie-re", [re]IE))           // Mix in the ephemeral/ephemeral shared secret.
  yg ← mix(yg, "is-re", [re]IS))           // Mix in the static/ephemeral shared secret.
  yg_recv ← mix(yg, "sender", "responder") // Fork the protocol into a (recv, send) pair.
  yg_send ← mix(yg, "sender", "initiator")
  return (yg_recv, yg_send, c1)
```

The responder sends the encrypted ephemeral public key `c1` to the initiator.

The initiator performs the following:

```text
function finalize(yg, is, ie, c1):
  (yg, RE) ← open(yg, "re", c1)            // Open the responder's ephemeral public key.
  yg ← mix(yg, "ie-re", [ie]RE))           // Mix in the ephemeral/ephemeral shared secret.
  yg ← mix(yg, "is-re", [ie]RE))           // Mix in the static/ephemeral shared secret.
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
handshake               time:   [80.943 µs 81.003 µs 81.066 µs]

transfer/1MiB           time:   [388.06 µs 388.62 µs 389.40 µs]
                        thrpt:  [2.5079 GiB/s 2.5129 GiB/s 2.5166 GiB/s]
transfer/10MiB          time:   [2.4058 ms 2.4116 ms 2.4175 ms]
                        thrpt:  [4.0395 GiB/s 4.0494 GiB/s 4.0592 GiB/s]
transfer/100MiB         time:   [21.316 ms 21.378 ms 21.443 ms]
                        thrpt:  [4.5542 GiB/s 4.5680 GiB/s 4.5815 GiB/s]
transfer/1GiB           time:   [215.44 ms 216.46 ms 217.44 ms]
                        thrpt:  [4.5991 GiB/s 4.6199 GiB/s 4.6416 GiB/s]

```

On a GCP `c3-standard-4` (`-C target-cpu=native`):

```text
handshake               time:   [118.06 µs 118.31 µs 118.56 µs]

transfer/1MiB           time:   [529.32 µs 530.28 µs 531.34 µs]
                        thrpt:  [1.8379 GiB/s 1.8416 GiB/s 1.8449 GiB/s]
transfer/10MiB          time:   [3.5231 ms 3.5342 ms 3.5454 ms]
                        thrpt:  [2.7545 GiB/s 2.7632 GiB/s 2.7718 GiB/s]
transfer/100MiB         time:   [33.904 ms 34.018 ms 34.130 ms]
                        thrpt:  [2.8613 GiB/s 2.8707 GiB/s 2.8804 GiB/s]
transfer/1GiB           time:   [342.90 ms 343.76 ms 344.61 ms]
                        thrpt:  [2.9018 GiB/s 2.9090 GiB/s 2.9163 GiB/s]
```

`handshake` measures the time it takes to establish a Yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a Yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
