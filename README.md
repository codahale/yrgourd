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

* Uses [Ristretto255][] for asymmetric operations and SHA-256/[AEGIS-128L][] for symmetric
  operations.
* Capable of >10 Gb/sec throughput.
* Everything but the first 32 bytes of a connection is encrypted.
* Handshakes use FHMQV-C to authenticate both sender and receiver with forward security for both.
* Uses ephemeral keys to ratchet the connection state every `N` seconds or `M` bytes.
* Responders can restrict handshakes to a set of valid initiator public keys.
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

Both initiator and responder have [Ristretto255][] key pairs; the initiator knows the responder's
public key.

The handshake is [FHMQV-C][] with a slight twist: the initiator's ephemeral key is broadcast in the
clear but the protocol is then keyed with the ECDH ephemeral shared secret and all other values are
encypted.

[FHMQV-C]: https://eprint.iacr.org/2009/408.pdf

The initiator initiates a handshake by generating an ephemeral key pair and executing the following:

```text
function initiator_init(initiator_static, initiator_ephemeral, responder_static.pub):
  yg ← init("yrgourd.v1")
  yg ← mix(yg, "responder-static-pub", responder_static.pub)
  yg ← mix(yg, "initiator-ephemeral-pub", initiator_ephemeral.pub)
  yg ← mix(yg, "ecdh-shared-secret", ecdh(responder_static.pub, initiator_ephemeral.priv))
  (yg, x) ← encrypt(yg, "initiator-static-pub", initiator_static.pub)
  return (yg, initiator_ephemeral.pub, x)
```

The initiator sends the plaintext ephemeral public key and the encrypted static public key to the
responder. The responder executes the following:

```text
function responder_accept(responder_static, responder_ephemeral, initiator_ephemeral.pub, x):
  yg ← init("yrgourd.v1")
  yg ← mix(yg, "responder-static-pub", responder_static.pub)
  yg ← mix(yg, "initiator-ephemeral-pub", initiator_ephemeral.pub)
  yg ← mix(yg, "ecdh-shared-secret", ecdh(initiator_ephemeral.pub, responder_static.pub))
  (yg, initiator_static.pub) ← decrypt(yg, "initiator-static-pub", x)
  (yg, y) ← encrypt(yg, "responder-ephemeral-pub", responder_ephemeral.pub)
  return (yg, y)
```

The responder sends the encrypted ephemeral public key to the initiator. The initiator performs the
following:

```text
function initiator_finalize(yg, initiator_static, initiator_ephemeral, responder_static.pub, y):
  (yg, responder_ephemeral.pub) ← decrypt(yg, "responder-ephemeral-pub", y)
  (yg, d) ← ristretto255::scalar(derive(yg, "scalar-d", 64))
  (yg, e) ← ristretto255::scalar(derive(yg, "scalar-e", 64))
  s_a ← initiator_ephemeral + d * initiator_static;
  k ← (responder_ephemeral.pub + (responder_static.pub * e)) * s_a;
  yg ← mix("shared-secret", k)
  yg_recv ← mix(yg, "sender", "responder")
  yg_send ← mix(yg, "sender", "initiator")
  return (yg_recv, yg_send)
```

The responder also performs the following:

```text
function responder_finalize(yg, responder_static, responder_ephemeral, initiator_static.pub, initiator_ephemeral.pub):
  (yg, d) ← ristretto255::scalar(derive(yg, "scalar-d", 64))
  (yg, e) ← ristretto255::scalar(derive(yg, "scalar-e", 64))
  s_b ← responder_ephemeral + e * responder_static;
  k ← (initiator_ephemeral.pub + (initiator_static.pub * d)) * s_b;
  yg ← mix("shared-secret", k)
  yg_recv ← mix(yg, "sender", "initiator")
  yg_send ← mix(yg, "sender", "responder")
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
├─ handshake  281.4 µs      │ 503.2 µs      │ 320.1 µs      │ 323.6 µs      │ 3090    │ 3090
╰─ transfer   21.9 ms       │ 29.04 ms      │ 22.59 ms      │ 23.14 ms      │ 100     │ 100
              4.458 GiB/s   │ 3.362 GiB/s   │ 4.321 GiB/s   │ 4.22 GiB/s    │         │
```

On a GCP `c3-standard-4`:

```text
Timer precision: 24.44 ns
benches       fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ handshake  374.5 µs      │ 638.3 µs      │ 415.6 µs      │ 420 µs        │ 2381    │ 2381
╰─ transfer   34.69 ms      │ 40.73 ms      │ 38.16 ms      │ 37.68 ms      │ 100     │ 100
              2.815 GiB/s   │ 2.397 GiB/s   │ 2.558 GiB/s   │ 2.591 GiB/s   │         │
```

`handshake` measures the time it takes to establish a Yrgourd connection over a Tokio duplex stream;
`transfer` measures the time it takes to transfer 100MiB via a Yrgourd connection over a Tokio
duplex stream.

See the [Lockstitch][] documentation for specifics on compiler options for performance.

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
