# Reticulum QUIC Interface

A QUIC transport interface for the [Reticulum Network Stack](https://reticulum.network/).

Adds a `QUICInterface` type to Reticulum, enabling encrypted UDP-based transport with built-in multiplexing, congestion control, and 0-RTT reconnection. Works as both client and server.


## Install

```sh
pip install aioquic cryptography
```

Copy the interface into your Reticulum config directory:

```sh
cp src/Interfaces/QUICInterface.py ~/.reticulum/interfaces/
```

Reticulum automatically loads custom interfaces from `~/.reticulum/interfaces/` — no modifications to the RNS package needed.

If you use a non-default config directory, adjust the path accordingly:

```sh
cp src/Interfaces/QUICInterface.py /path/to/your/configdir/interfaces/
```

## Configuration

Add a section to your `~/.reticulum/config` file.

### Client (connect to a remote QUIC peer)

```ini
[[QUIC Transport]]
  type = QUICInterface
  enabled = yes
  target_host = 10.0.0.1
  target_port = 4244
```

### Server (accept incoming QUIC connections)

```ini
[[QUIC Server]]
  type = QUICInterface
  enabled = yes
  listen_ip = 0.0.0.0
  listen_port = 4244
```

### Options

| Key | Default | Description |
|-----|---------|-------------|
| `target_host` | — | Remote host (client mode) |
| `target_port` | — | Remote port (client mode) |
| `listen_ip` | `0.0.0.0` | Bind address (server mode) |
| `listen_port` | `4244` | Bind port (server mode) |
| `max_reconnect_tries` | unlimited | Max client reconnect attempts |

If `target_host` is present, the interface runs as a client. Otherwise it runs as a server.

## How it works

QUIC runs over UDP with TLS 1.3 encryption. Reticulum packets are sent as QUIC datagrams when they fit (no head-of-line blocking), with automatic fallback to unidirectional streams for oversized packets.

TLS uses ephemeral self-signed certificates with ALPN protocol `rns`. Certificate verification is disabled — Reticulum handles authentication at the protocol layer via IFAC and Identity.

The server spawns a per-client interface for each incoming connection, matching the pattern used by `TCPServerInterface` and `BackboneInterface`.

## Why QUIC over TCP?

- No head-of-line blocking (datagrams are independent)
- Built-in encryption (TLS 1.3, no extra handshake layer needed)
- Multiplexed streams without TCP's ordering constraints
- Better performance over lossy links (independent packet loss recovery)
- NAT traversal friendly (UDP-based)
- 0-RTT reconnection for returning clients

## License

MIT