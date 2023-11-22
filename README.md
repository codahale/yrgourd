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

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
