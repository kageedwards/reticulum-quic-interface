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
| `session_ticket_file` | — | Path to persist session tickets for 0-RTT resumption (client only) |

If `target_host` is present, the interface runs as a client. Otherwise it runs as a server.

## How it works

QUIC runs over UDP with TLS 1.3 encryption. Reticulum packets are sent as QUIC datagrams when they fit within a single QUIC packet (no head-of-line blocking), with automatic fallback to unidirectional streams for oversized packets. Datagram support is negotiated during the handshake (RFC 9221), and the datagram-vs-stream decision is made per packet against the negotiated datagram size.

TLS uses ephemeral self-signed certificates with ALPN protocol `rns`. Certificate verification is disabled — Reticulum handles authentication at the protocol layer via IFAC and Identity.

The server spawns a per-client interface for each incoming connection, matching the pattern used by `TCPServerInterface` and `BackboneInterface`.

## Features

### Session Resumption (0-RTT)

The server enables TLS 1.3 early data and issues session tickets after each
successful handshake. The client caches these tickets and presents them on
reconnect, allowing a 0-RTT-capable resumption handshake that skips the
certificate exchange.

Set `session_ticket_file` in the client config to persist tickets across restarts:

```ini
[[QUIC Transport]]
  type = QUICInterface
  enabled = yes
  target_host = 10.0.0.1
  target_port = 4244
  session_ticket_file = /path/to/tickets.json
```

Tickets are stored as JSON (not pickle), so loading the file can never execute
arbitrary code even if it is tampered with. If a cached ticket is rejected or
expired, the client falls back to a full handshake automatically.

### Connection Migration

QUIC connections survive client IP address or port changes (NAT rebind, network switch, mobile roaming) without requiring a full reconnect. aioquic keeps routing on the existing connection ID; the server observes the changed UDP source address on incoming packets and logs the path change at debug level while continuing on the same connection.

### Persistent Event Loop

Each interface maintains a single asyncio event loop for its entire lifetime. Reconnection attempts are scheduled on the existing loop rather than creating a new one each time, avoiding resource leaks and improving lifecycle management.

### Instance-Safe Certificates

Each server instance generates a unique self-signed certificate using random temporary filenames. Multiple server instances on the same machine won't conflict. Certificate files are cleaned up on detach.

## Why QUIC over TCP?

- No head-of-line blocking (datagrams are independent)
- Built-in encryption (TLS 1.3, no extra handshake layer needed)
- Multiplexed streams without TCP's ordering constraints
- Better performance over lossy links (independent packet loss recovery)
- NAT traversal friendly (UDP-based)
- 0-RTT reconnection for returning clients
- Connection migration survives network changes

## License

MIT
