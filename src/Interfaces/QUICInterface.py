# QUICInterface — QUIC transport for Reticulum.
#
# Uses aioquic for the QUIC protocol with 
# self-signed TLS and ALPN "rns".
#
# Requires: pip install aioquic cryptography
#
# Config example (client):
#   [[QUIC Transport]]
#     type = QUICInterface
#     enabled = yes
#     target_host = 10.0.0.1
#     target_port = 4244
#
# Config example (server):
#   [[QUIC Server]]
#     type = QUICInterface
#     enabled = yes
#     listen_ip = 0.0.0.0
#     listen_port = 4244

import os
import ssl
import json
import time
import base64
import asyncio
import datetime
import threading
import tempfile

# Support both normal import (when placed in RNS/Interfaces/) and
# exec()-based loading (when placed in ~/.reticulum/interfaces/).
# The external loader injects `RNS` and `Interface` as globals.
try:
    import RNS
    from RNS.Interfaces.Interface import Interface as _Interface
except ImportError:
    # When loaded via exec(), RNS and Interface are already in globals
    _Interface = Interface  # noqa: F821 — injected by Reticulum loader

HW_MTU            = 1200
BITRATE_GUESS     = 10_000_000
DEFAULT_IFAC_SIZE = 16
RECONNECT_WAIT    = 5
ALPN_PROTOCOL     = "rns"

# QUIC DATAGRAM extension (RFC 9221). Both peers must advertise a non-None
# max_datagram_frame_size during the handshake, otherwise a received DATAGRAM
# frame is a PROTOCOL_VIOLATION and the connection is torn down.
MAX_DATAGRAM_FRAME_SIZE = 65536

# Conservative allowance for the QUIC short-header packet overhead plus the
# DATAGRAM frame header. A QUIC datagram must fit in a single packet (it cannot
# be fragmented), so we only send a packet as a datagram when it fits within
# the negotiated datagram size minus this overhead. Anything larger falls back
# to a unidirectional stream.
QUIC_DATAGRAM_OVERHEAD = 64

_aioquic_available = False
try:
    from aioquic.asyncio import connect as quic_connect, serve as quic_serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import (
        DatagramFrameReceived,
        StreamDataReceived,
        ConnectionTerminated,
    )
    from aioquic.tls import SessionTicket
    _aioquic_available = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Session ticket store for session resumption (TLS 1.3 / 0-RTT)
# ---------------------------------------------------------------------------

def _ticket_to_dict(t):
    """Serialize an aioquic SessionTicket to JSON-safe primitives."""
    return {
        "age_add": t.age_add,
        "cipher_suite": int(t.cipher_suite),
        "not_valid_after": t.not_valid_after.timestamp(),
        "not_valid_before": t.not_valid_before.timestamp(),
        "resumption_secret": base64.b64encode(t.resumption_secret).decode("ascii"),
        "server_name": t.server_name,
        "ticket": base64.b64encode(t.ticket).decode("ascii"),
        "max_early_data_size": t.max_early_data_size,
        "other_extensions": [
            [int(ext_type), base64.b64encode(ext_data).decode("ascii")]
            for ext_type, ext_data in t.other_extensions
        ],
    }


def _ticket_from_dict(d):
    """Reconstruct an aioquic SessionTicket from _ticket_to_dict() output."""
    return SessionTicket(
        age_add=d["age_add"],
        cipher_suite=d["cipher_suite"],
        not_valid_after=datetime.datetime.fromtimestamp(
            d["not_valid_after"], tz=datetime.timezone.utc
        ),
        not_valid_before=datetime.datetime.fromtimestamp(
            d["not_valid_before"], tz=datetime.timezone.utc
        ),
        resumption_secret=base64.b64decode(d["resumption_secret"]),
        server_name=d["server_name"],
        ticket=base64.b64decode(d["ticket"]),
        max_early_data_size=d.get("max_early_data_size"),
        other_extensions=[
            (ext_type, base64.b64decode(ext_data))
            for ext_type, ext_data in d.get("other_extensions", [])
        ],
    )


class TicketStore:
    """In-memory cache for TLS 1.3 session tickets, keyed by server address.

    Tickets are persisted as JSON rather than pickle so loading a store file
    can never execute arbitrary code, even if the file has been tampered with.
    """

    def __init__(self, persist_path=None):
        self._tickets = {}
        self._persist_path = persist_path
        if self._persist_path:
            self._load_from_disk()

    def store(self, address_key, ticket):
        """Store a ticket for the given address, replacing any existing one."""
        self._tickets[address_key] = ticket
        self._save_to_disk()

    def get(self, address_key):
        """Retrieve the stored ticket for the given address, or None."""
        return self._tickets.get(address_key, None)

    def remove(self, address_key):
        """Remove the ticket for the given address, if present."""
        self._tickets.pop(address_key, None)
        self._save_to_disk()

    def _save_to_disk(self):
        """Persist current tickets to disk as JSON. No-op if no persist_path."""
        if not self._persist_path:
            return
        try:
            serializable = {
                key: _ticket_to_dict(ticket)
                for key, ticket in self._tickets.items()
            }
            with open(self._persist_path, "w") as f:
                json.dump(serializable, f)
        except Exception as e:
            RNS.log(
                f"TicketStore: failed to write {self._persist_path}: {e}",
                RNS.LOG_WARNING,
            )

    def _load_from_disk(self):
        """Load tickets from disk. Logs warning and starts empty on failure."""
        try:
            with open(self._persist_path, "r") as f:
                raw = json.load(f)
            self._tickets = {
                key: _ticket_from_dict(value) for key, value in raw.items()
            }
        except FileNotFoundError:
            self._tickets = {}
        except Exception as e:
            RNS.log(
                f"TicketStore: failed to load {self._persist_path}: {e}",
                RNS.LOG_WARNING,
            )
            self._tickets = {}


# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------

def _make_self_signed_cert():
    """Generate an ephemeral self-signed cert+key pair for aioquic."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime

        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "rns"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )

        cert_fd, cert_path = tempfile.mkstemp(prefix="rns_quic_", suffix="_cert.pem")
        key_fd, key_path   = tempfile.mkstemp(prefix="rns_quic_", suffix="_key.pem")

        try:
            os.write(cert_fd, cert.public_bytes(serialization.Encoding.PEM))
        finally:
            os.close(cert_fd)

        try:
            os.write(key_fd, key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        finally:
            os.close(key_fd)

        return cert_path, key_path

    except Exception as e:
        RNS.log(f"QUICInterface: failed to generate self-signed cert: {e}", RNS.LOG_ERROR)
        return None, None


def _make_client_config():
    config = QuicConfiguration(is_client=True, alpn_protocols=[ALPN_PROTOCOL])
    config.verify_mode = ssl.CERT_NONE
    # Advertise DATAGRAM support so unreliable, head-of-line-blocking-free
    # datagrams can be negotiated for the common (small packet) path.
    config.max_datagram_frame_size = MAX_DATAGRAM_FRAME_SIZE
    return config


def _make_server_config(cert_path, key_path):
    config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN_PROTOCOL])
    config.load_cert_chain(cert_path, key_path)
    config.max_datagram_frame_size = MAX_DATAGRAM_FRAME_SIZE
    # Permit early data so resumed connections perform a genuine 0-RTT
    # handshake rather than a 1-RTT abbreviated one.
    config.max_early_data_size = 0xFFFFFFFF
    return config


# ---------------------------------------------------------------------------
# QUIC protocol handler (shared by client and server connections)
# ---------------------------------------------------------------------------

if _aioquic_available:
    class _RNSQuicProtocol(QuicConnectionProtocol):
        """Handles QUIC events for a single connection."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.interface = None
            self._stream_buffers = {}
            self._last_peer_addr = None

        def datagram_received(self, data, addr):
            # Observe the actual UDP source address on every received packet.
            # When it changes mid-connection (NAT rebind, network switch,
            # mobile roaming), QUIC connection migration has occurred. aioquic
            # keeps routing on the existing connection ID, so the interface
            # stays online — we just log the path change. This is the correct
            # place to detect it: the asyncio transport peername is unreliable
            # for a server's shared, unconnected UDP socket.
            if self._last_peer_addr is not None and addr != self._last_peer_addr:
                target = self.interface if self.interface is not None else self
                RNS.log(
                    f"QUIC path migration on {target}: "
                    f"{self._last_peer_addr} -> {addr}",
                    RNS.LOG_DEBUG,
                )
            self._last_peer_addr = addr
            super().datagram_received(data, addr)

        def _datagram_payload_limit(self):
            """Largest packet (in bytes) that fits in a single QUIC datagram.

            Returns 0 if the peer did not negotiate DATAGRAM support, forcing
            the stream path.
            """
            quic = self._quic
            remote_max = getattr(quic, "_remote_max_datagram_frame_size", None)
            if not remote_max:
                return 0
            max_dgram = getattr(quic, "_max_datagram_size", 1200)
            return max(0, min(remote_max, max_dgram) - QUIC_DATAGRAM_OVERHEAD)

        def send_packet(self, data):
            """Send one RNS packet over this connection.

            Chooses a QUIC DATAGRAM frame when the packet fits in a single
            datagram (no head-of-line blocking), otherwise falls back to a
            short-lived unidirectional stream. MUST be invoked on the event
            loop thread — aioquic connection state is not thread-safe.
            """
            try:
                if len(data) <= self._datagram_payload_limit():
                    self._quic.send_datagram_frame(data)
                else:
                    stream_id = self._quic.get_next_available_stream_id(
                        is_unidirectional=True
                    )
                    self._quic.send_stream_data(stream_id, data, end_stream=True)
                self.transmit()
                return True
            except Exception as e:
                target = self.interface if self.interface is not None else "QUIC"
                RNS.log(f"QUIC transmit error on {target}: {e}", RNS.LOG_ERROR)
                return False

        def quic_event_received(self, event):
            if isinstance(event, DatagramFrameReceived):
                if self.interface and len(event.data) > 0:
                    self.interface.process_incoming(event.data)

            elif isinstance(event, StreamDataReceived):
                # Buffer uni-stream data until the stream ends
                sid = event.stream_id
                if sid not in self._stream_buffers:
                    self._stream_buffers[sid] = bytearray()
                self._stream_buffers[sid] += event.data

                if event.end_stream:
                    data = bytes(self._stream_buffers.pop(sid, b""))
                    if self.interface and len(data) > 0:
                        self.interface.process_incoming(data)

            elif isinstance(event, ConnectionTerminated):
                if self.interface:
                    self.interface._handle_disconnect()


# ---------------------------------------------------------------------------
# QUICClientInterface
# ---------------------------------------------------------------------------

class QUICClientInterface(_Interface):
    BITRATE_GUESS      = BITRATE_GUESS
    DEFAULT_IFAC_SIZE  = DEFAULT_IFAC_SIZE
    AUTOCONFIGURE_MTU  = True
    RECONNECT_WAIT     = RECONNECT_WAIT
    RECONNECT_MAX_TRIES = None

    def __init__(self, owner, configuration):
        super().__init__()

        if not _aioquic_available:
            raise SystemError(
                "QUICInterface requires the aioquic package. "
                "Install it with: pip install aioquic"
            )

        c = _Interface.get_config_obj(configuration)
        name        = c["name"]
        target_host = c["target_host"]
        target_port = int(c["target_port"])

        self.HW_MTU           = HW_MTU
        self.IN               = True
        self.OUT              = True
        self.name             = name
        self.target_host      = target_host
        self.target_port      = target_port
        self.owner            = owner
        self.online           = False
        self.detached         = False
        self.initiator        = True
        self.reconnecting     = False
        self.never_connected  = True
        self.mode             = _Interface.MODE_FULL
        self.bitrate          = self.BITRATE_GUESS
        self.receives         = True

        self._protocol        = None

        self.supports_discovery = True

        max_reconnect_tries = c.as_int("max_reconnect_tries") if "max_reconnect_tries" in c else None
        if max_reconnect_tries is None:
            self.max_reconnect_tries = self.RECONNECT_MAX_TRIES
        else:
            self.max_reconnect_tries = max_reconnect_tries

        # Session resumption: ticket store and address key
        session_ticket_file = c["session_ticket_file"] if "session_ticket_file" in c else None
        self._ticket_store = TicketStore(persist_path=session_ticket_file)
        self._address_key = f"{target_host}:{target_port}"

        # Create a single persistent event loop for the lifetime of this interface
        self._loop = asyncio.new_event_loop()
        self._loop.set_exception_handler(self._loop_exception_handler)
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        # Schedule the initial connection on the persistent loop
        asyncio.run_coroutine_threadsafe(self._connect(), self._loop)

    def _loop_exception_handler(self, loop, context):
        """Handle uncaught exceptions in the event loop without crashing."""
        msg = context.get("message", "Unhandled exception in event loop")
        exc = context.get("exception", None)
        if exc:
            RNS.log(f"QUICInterface {self.name} loop error: {msg}: {exc}", RNS.LOG_ERROR)
        else:
            RNS.log(f"QUICInterface {self.name} loop error: {msg}", RNS.LOG_ERROR)

    def _run_loop(self):
        """Run the persistent event loop forever in a daemon thread."""
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        except Exception as e:
            RNS.log(f"QUICInterface {self.name} event loop error: {e}", RNS.LOG_ERROR)
        finally:
            self.online = False

    def _session_ticket_received(self, ticket):
        """Callback invoked by aioquic when the server issues a session ticket."""
        self._ticket_store.store(self._address_key, ticket)

    async def _connect(self):
        ticket = self._ticket_store.get(self._address_key)
        try:
            RNS.log(f"Establishing QUIC connection for {self}...", RNS.LOG_DEBUG)
            config = _make_client_config()
            if ticket is not None:
                config.session_ticket = ticket
            config.session_ticket_handler = self._session_ticket_received
            async with quic_connect(
                self.target_host,
                self.target_port,
                configuration=config,
                create_protocol=_RNSQuicProtocol,
            ) as protocol:
                protocol.interface = self
                self._protocol = protocol
                self.online = True
                self.never_connected = False
                RNS.log(f"QUIC connection for {self} established", RNS.LOG_DEBUG)

                # Keep the connection alive until it closes
                await protocol.wait_closed()

        except Exception as e:
            RNS.log(f"QUIC connection for {self} failed: {e}", RNS.LOG_ERROR)
            self.online = False

            # Resumption fallback: if a ticket was used and the connection
            # failed, drop the stale ticket and retry with a full handshake
            if ticket is not None:
                RNS.log(
                    f"Session ticket rejected or expired for {self}, "
                    f"falling back to full handshake",
                    RNS.LOG_DEBUG,
                )
                self._ticket_store.remove(self._address_key)
                try:
                    config = _make_client_config()
                    config.session_ticket_handler = self._session_ticket_received
                    async with quic_connect(
                        self.target_host,
                        self.target_port,
                        configuration=config,
                        create_protocol=_RNSQuicProtocol,
                    ) as protocol:
                        protocol.interface = self
                        self._protocol = protocol
                        self.online = True
                        self.never_connected = False
                        RNS.log(
                            f"QUIC connection for {self} established (full handshake)",
                            RNS.LOG_DEBUG,
                        )
                        await protocol.wait_closed()
                except Exception as e2:
                    RNS.log(
                        f"QUIC full-handshake fallback for {self} failed: {e2}",
                        RNS.LOG_ERROR,
                    )
                    self.online = False

        self._handle_disconnect()

    def _handle_disconnect(self):
        self.online = False
        if self.initiator and not self.detached:
            if not self.reconnecting:
                self.reconnecting = True
                thread = threading.Thread(target=self._reconnect, daemon=True)
                thread.start()

    def _reconnect(self):
        attempts = 0
        while not self.online and not self.detached:
            time.sleep(self.RECONNECT_WAIT)
            attempts += 1

            if self.max_reconnect_tries is not None and attempts > self.max_reconnect_tries:
                RNS.log(f"Max reconnection attempts reached for {self}", RNS.LOG_ERROR)
                self.detach()
                break

            try:
                # Schedule _connect() on the existing persistent event loop
                future = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
                future.result()  # Block until _connect() completes
            except Exception as e:
                RNS.log(f"QUIC reconnect for {self} failed: {e}", RNS.LOG_DEBUG)

        self.reconnecting = False

    def process_incoming(self, data):
        if self.online and not self.detached:
            self.rxb += len(data)
            self.owner.inbound(data, self)

    def process_outgoing(self, data):
        # Marshal the actual send onto the event loop thread. aioquic's
        # connection objects are not thread-safe, so we must never touch
        # self._protocol._quic or call transmit() from Reticulum's outbound
        # thread directly.
        if self.online and not self.detached and self._protocol:
            loop = self._loop
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(self._dispatch_send, data)

    def _dispatch_send(self, data):
        """Run on the event loop thread: hand the packet to the protocol."""
        protocol = self._protocol
        if protocol is not None and protocol.send_packet(data):
            self.txb += len(data)

    def detach(self):
        self.online  = False
        self.detached = True
        self.OUT = False
        self.IN  = False
        loop = self._loop
        if loop and loop.is_running():
            # Close the connection and stop the loop on the loop thread, in
            # that order (call_soon_threadsafe preserves FIFO ordering).
            loop.call_soon_threadsafe(self._close_protocol)
            loop.call_soon_threadsafe(loop.stop)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._loop and not self._loop.is_closed():
            self._loop.close()

    def _close_protocol(self):
        """Close the QUIC connection. MUST run on the event loop thread."""
        if self._protocol:
            try:
                self._protocol._quic.close()
                self._protocol.transmit()
            except Exception:
                pass

    def __str__(self):
        return f"QUICInterface[{self.name}/{self.target_host}:{self.target_port}]"


# ---------------------------------------------------------------------------
# QUICServerInterface
# ---------------------------------------------------------------------------

class QUICServerInterface(_Interface):
    BITRATE_GUESS     = BITRATE_GUESS
    DEFAULT_IFAC_SIZE = DEFAULT_IFAC_SIZE

    def __init__(self, owner, configuration):
        super().__init__()

        if not _aioquic_available:
            raise SystemError(
                "QUICInterface requires the aioquic package. "
                "Install it with: pip install aioquic"
            )

        c = _Interface.get_config_obj(configuration)
        name      = c["name"]
        listen_ip = c["listen_ip"] if "listen_ip" in c else "0.0.0.0"
        listen_port = int(c["listen_port"]) if "listen_port" in c else 4244

        self.HW_MTU           = HW_MTU
        self.IN               = True
        self.OUT              = False
        self.name             = name
        self.listen_ip        = listen_ip
        self.listen_port      = listen_port
        self.owner            = owner
        self.online           = False
        self.detached         = False
        self.mode             = _Interface.MODE_FULL
        self.bitrate          = self.BITRATE_GUESS
        self.receives         = True

        self.spawned_interfaces = []
        self._loop             = None

        self.supports_discovery = True

        cert_path, key_path = _make_self_signed_cert()
        if cert_path is None:
            raise SystemError("QUICServerInterface: could not generate TLS certificate")

        self._cert_path = cert_path
        self._key_path  = key_path

        thread = threading.Thread(target=self._serve_loop, daemon=True)
        thread.start()

    def _serve_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.set_exception_handler(self._loop_exception_handler)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as e:
            RNS.log(f"QUICServerInterface {self.name} error: {e}", RNS.LOG_ERROR)
        finally:
            self.online = False

    def _loop_exception_handler(self, loop, context):
        """Handle uncaught exceptions in the server event loop without crashing."""
        msg = context.get("message", "Unhandled exception in event loop")
        exc = context.get("exception", None)
        if exc:
            RNS.log(f"QUICServerInterface {self.name} loop error: {msg}: {exc}", RNS.LOG_ERROR)
        else:
            RNS.log(f"QUICServerInterface {self.name} loop error: {msg}", RNS.LOG_ERROR)

    async def _serve(self):
        config = _make_server_config(self._cert_path, self._key_path)
        server_interface = self

        # Server-side session ticket store for 0-RTT resumption
        session_ticket_store = {}

        def _server_session_ticket_handler(ticket):
            """Store a session ticket issued to a client."""
            try:
                session_ticket_store[ticket.ticket] = ticket
            except Exception as e:
                RNS.log(
                    f"QUICServerInterface {server_interface.name}: "
                    f"session_ticket_handler error: {e}",
                    RNS.LOG_ERROR,
                )

        def _server_session_ticket_fetcher(ticket_bytes):
            """Retrieve a previously issued session ticket."""
            return session_ticket_store.get(ticket_bytes, None)

        config.session_ticket_handler = _server_session_ticket_handler
        config.session_ticket_fetcher = _server_session_ticket_fetcher

        class _ServerProtocol(_RNSQuicProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._spawned = None

            def quic_event_received(self, event):
                if isinstance(event, DatagramFrameReceived) or isinstance(event, StreamDataReceived):
                    if self._spawned is None:
                        self._spawned = _QUICSpawnedInterface(
                            server_interface, self, self._quic.host_cid
                        )
                        self.interface = self._spawned
                        server_interface.spawned_interfaces.append(self._spawned)
                        RNS.log(f"QUIC client connected to {server_interface}", RNS.LOG_VERBOSE)

                super().quic_event_received(event)

                if isinstance(event, ConnectionTerminated):
                    if self._spawned:
                        try:
                            server_interface.spawned_interfaces.remove(self._spawned)
                        except ValueError:
                            pass
                        self._spawned.online = False

        RNS.log(f"QUIC server listening on {self.listen_ip}:{self.listen_port}", RNS.LOG_VERBOSE)
        self.online = True

        await quic_serve(
            self.listen_ip,
            self.listen_port,
            configuration=config,
            create_protocol=_ServerProtocol,
        )

    @property
    def clients(self):
        return len(self.spawned_interfaces)

    def process_outgoing(self, data):
        for spawned in self.spawned_interfaces:
            spawned.process_outgoing(data)

    def detach(self):
        self.online  = False
        self.detached = True
        for spawned in list(self.spawned_interfaces):
            spawned.detach()
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

        # Clean up temporary cert/key files created for this instance
        for path in (self._cert_path, self._key_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except PermissionError as e:
                RNS.log(f"QUICServerInterface: could not delete {path}: {e}", RNS.LOG_WARNING)

    def __str__(self):
        return f"QUICInterface[{self.name}/{self.listen_ip}:{self.listen_port}]"


class _QUICSpawnedInterface(_Interface):
    """A per-client interface spawned by QUICServerInterface."""

    def __init__(self, parent, protocol, connection_id):
        super().__init__()
        self.HW_MTU           = HW_MTU
        self.IN               = True
        self.OUT              = True
        self.online           = True
        self.detached         = False
        self.name             = f"Client on {parent.name}"
        self.parent_interface = parent
        self.owner            = parent.owner
        self.mode             = _Interface.MODE_FULL
        self.bitrate          = BITRATE_GUESS
        self.receives         = True
        self._protocol        = protocol
        self._connection_id   = connection_id

    def process_incoming(self, data):
        if self.online and not self.detached:
            self.rxb += len(data)
            if self.parent_interface:
                self.parent_interface.rxb += len(data)
            self.owner.inbound(data, self)

    def process_outgoing(self, data):
        # Marshal onto the server's event loop thread (aioquic is not
        # thread-safe); the actual send happens in _dispatch_send.
        if self.online and not self.detached and self._protocol:
            parent = self.parent_interface
            loop = parent._loop if parent is not None else None
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(self._dispatch_send, data)

    def _dispatch_send(self, data):
        """Run on the event loop thread: hand the packet to the protocol."""
        protocol = self._protocol
        if protocol is not None and protocol.send_packet(data):
            n = len(data)
            self.txb += n
            if self.parent_interface:
                self.parent_interface.txb += n

    def _handle_disconnect(self):
        # Invoked by the protocol on ConnectionTerminated. The server protocol
        # also removes this interface from the parent's spawned list.
        self.online = False

    def detach(self):
        self.online  = False
        self.detached = True
        parent = self.parent_interface
        loop = parent._loop if parent is not None else None
        if self._protocol and loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._close_protocol)

    def _close_protocol(self):
        """Close the QUIC connection. MUST run on the event loop thread."""
        if self._protocol:
            try:
                self._protocol._quic.close()
                self._protocol.transmit()
            except Exception:
                pass

    def __str__(self):
        return f"QUICInterface[{self.name}]"


# ---------------------------------------------------------------------------
# Config entry point — auto-detected by Reticulum's external interface loader
# ---------------------------------------------------------------------------

class QUICInterface:
    """
    Factory dispatched by Reticulum config parser.

    If ``target_host`` is present, creates a QUICClientInterface.
    Otherwise creates a QUICServerInterface.
    """

    @staticmethod
    def __init_subclass__(**kwargs):
        pass

    def __new__(cls, owner, configuration):
        c = _Interface.get_config_obj(configuration)
        if "target_host" in c and c["target_host"] is not None:
            return QUICClientInterface(owner, configuration)
        else:
            return QUICServerInterface(owner, configuration)

# Required by Reticulum's external interface loader (exec-based).
# When placed in ~/.reticulum/interfaces/, the loader looks for this global.
interface_class = QUICInterface
