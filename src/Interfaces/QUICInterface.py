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
import time
import pickle
import asyncio
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
# Session ticket store for 0-RTT resumption
# ---------------------------------------------------------------------------

class TicketStore:
    """In-memory cache for TLS 1.3 session tickets, keyed by server address."""

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
        """Persist current tickets to disk via pickle. No-op if no persist_path."""
        if not self._persist_path:
            return
        try:
            with open(self._persist_path, "wb") as f:
                pickle.dump(self._tickets, f)
        except Exception as e:
            RNS.log(
                f"TicketStore: failed to write {self._persist_path}: {e}",
                RNS.LOG_WARNING,
            )

    def _load_from_disk(self):
        """Load tickets from disk. Logs warning and starts empty on failure."""
        try:
            with open(self._persist_path, "rb") as f:
                self._tickets = pickle.load(f)
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
    return config


def _make_server_config(cert_path, key_path):
    config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN_PROTOCOL])
    config.load_cert_chain(cert_path, key_path)
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
        self._loop            = None
        self._thread          = None

        self.supports_discovery = True

        max_reconnect_tries = c.as_int("max_reconnect_tries") if "max_reconnect_tries" in c else None
        if max_reconnect_tries is None:
            self.max_reconnect_tries = self.RECONNECT_MAX_TRIES
        else:
            self.max_reconnect_tries = max_reconnect_tries

        thread = threading.Thread(target=self._connect_loop, daemon=True)
        thread.start()

    def _connect_loop(self):
        """Run the asyncio event loop for this connection in a background thread."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect())
            if self.online:
                self._loop.run_forever()
        except Exception as e:
            RNS.log(f"QUICInterface {self.name} event loop error: {e}", RNS.LOG_ERROR)
        finally:
            self.online = False

    async def _connect(self):
        try:
            RNS.log(f"Establishing QUIC connection for {self}...", RNS.LOG_DEBUG)
            config = _make_client_config()
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
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
                self._loop.run_until_complete(self._connect())
                if self.online:
                    self._loop.run_forever()
            except Exception as e:
                RNS.log(f"QUIC reconnect for {self} failed: {e}", RNS.LOG_DEBUG)

        self.reconnecting = False

    def process_incoming(self, data):
        if self.online and not self.detached:
            self.rxb += len(data)
            self.owner.inbound(data, self)

    def process_outgoing(self, data):
        if self.online and not self.detached and self._protocol:
            try:
                # Try datagram first (fast, no head-of-line blocking)
                self._protocol._quic.send_datagram_frame(data)
                self._protocol.transmit()
                self.txb += len(data)
            except Exception:
                # Datagram too large or not supported — fall back to uni stream
                try:
                    if self._loop and self._loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self._send_stream(data), self._loop
                        )
                        self.txb += len(data)
                except Exception as e:
                    RNS.log(f"QUIC transmit error on {self}: {e}", RNS.LOG_ERROR)

    async def _send_stream(self, data):
        """Send data over a unidirectional QUIC stream."""
        if self._protocol:
            stream_id = self._protocol._quic.get_next_available_stream_id(is_unidirectional=True)
            self._protocol._quic.send_stream_data(stream_id, data, end_stream=True)
            self._protocol.transmit()

    def detach(self):
        self.online  = False
        self.detached = True
        self.OUT = False
        self.IN  = False
        if self._protocol:
            try:
                self._protocol._quic.close()
                self._protocol.transmit()
            except: pass
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

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
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as e:
            RNS.log(f"QUICServerInterface {self.name} error: {e}", RNS.LOG_ERROR)
        finally:
            self.online = False

    async def _serve(self):
        config = _make_server_config(self._cert_path, self._key_path)
        server_interface = self

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
        if self.online and not self.detached and self._protocol:
            try:
                self._protocol._quic.send_datagram_frame(data)
                self._protocol.transmit()
                self.txb += len(data)
                if self.parent_interface:
                    self.parent_interface.txb += len(data)
            except Exception:
                try:
                    stream_id = self._protocol._quic.get_next_available_stream_id(
                        is_unidirectional=True
                    )
                    self._protocol._quic.send_stream_data(stream_id, data, end_stream=True)
                    self._protocol.transmit()
                    self.txb += len(data)
                    if self.parent_interface:
                        self.parent_interface.txb += len(data)
                except Exception as e:
                    RNS.log(f"QUIC transmit error on {self}: {e}", RNS.LOG_ERROR)

    def detach(self):
        self.online  = False
        self.detached = True
        if self._protocol:
            try:
                self._protocol._quic.close()
                self._protocol.transmit()
            except: pass

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
