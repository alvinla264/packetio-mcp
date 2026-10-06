"""Generic raw-socket send and capture on a local network interface.

Everything here talks directly to AF_PACKET on an interface of the host (or of
whatever network namespace the process already sits in). There is no Docker,
container or topology awareness: the caller names an interface such as ``eth1``.

Sending a frame and reading the reply requires raw-socket privileges, so the
server uses a dedicated, access-restricted interpreter granted ``CAP_NET_RAW``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import errno
from pathlib import Path
import socket
import struct
import time

from .decode import decode_link_frame, summarize_frame
from .packets import (
    ETH_P_ALL,
    PACKET_OUTGOING,
    PACKET_TYPE_NAMES,
    format_mac,
    hex_bytes,
)


# Python does not expose these AF_PACKET constants on every build.
SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
PACKET_ADD_MEMBERSHIP = getattr(socket, "PACKET_ADD_MEMBERSHIP", 1)
PACKET_MR_PROMISC = 1


class CaptureError(RuntimeError):
    """Raised when an interface cannot be opened, bound or used."""


def _require_privileges(error: OSError) -> CaptureError:
    if error.errno in (errno.EPERM, errno.EACCES):
        return CaptureError(f"{_PRIVILEGE_HELP} Grant it with: {privilege_fix_command()}")
    return CaptureError(str(error))


_PRIVILEGE_HELP = (
    "opening a raw packet socket requires CAP_NET_RAW, which this interpreter "
    "does not have. Use an access-restricted dedicated interpreter; do not "
    "grant capabilities to shared Python or run this server as root. "
    "Everything except sending and capturing works without it: "
    "building, decoding, filtering and capture file handling need no "
    "privileges."
)


def _locate_setup_script() -> Path | None:
    """Find setup-capabilities.sh relative to this checkout, if present.

    Walks up from this file because the package may be imported from ``src`` or
    from an installed copy inside a virtual environment. Returns ``None`` when
    the script is not part of the layout in use, so callers can fall back to a
    manual command.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "setup-capabilities.sh"
        if candidate.is_file():
            return candidate
    return None


def privilege_fix_command() -> str:
    """Suggest unprivileged setup, never root execution or shared setcap."""
    import shlex
    script = _locate_setup_script()
    if script is not None:
        return shlex.quote(str(script))
    return 'configure an access-restricted dedicated interpreter with CAP_NET_RAW; never setcap shared Python'


def check_raw_socket_permission() -> tuple[bool, str]:
    """Report whether this process may open a raw packet socket.

    The check opens and closes a real socket rather than inspecting capability
    sets, because a file may carry CAP_NET_RAW and still be unable to use it on
    a filesystem mounted ``nosuid`` or one that ignores extended attributes.

    Returns ``(permitted, reason)``. ``reason`` is empty when permitted.
    """
    import socket

    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        return False, "CAP_NET_RAW is not available to this interpreter"
    except OSError as error:
        return False, f"raw socket probe failed: {error}"
    else:
        probe.close()
    return True, ""


def require_raw_socket_permission() -> None:
    """Raise :class:`CaptureError` when raw sockets are unavailable.

    Intended for a fail-fast check at startup so a missing capability is
    reported once, clearly, instead of surfacing as a confusing error the first
    time a frame is sent.
    """
    permitted, reason = check_raw_socket_permission()
    if not permitted:
        raise CaptureError(
            f"{reason}. {_PRIVILEGE_HELP} Grant it with: {privilege_fix_command()}"
        )


def list_interfaces() -> list[dict]:
    """List local interfaces using only the standard library."""
    names = sorted(socket.if_nameindex(), key=lambda item: item[0])
    interfaces = []
    for _, name in names:
        entry: dict = {"name": name}
        try:
            entry["index"] = socket.if_nametoindex(name)
        except OSError:
            continue
        entry["up"] = _is_up(name)
        entry["mac"] = _interface_mac(name)
        interfaces.append(entry)
    return interfaces


def _read_sysfs(name: str, attribute: str) -> str | None:
    try:
        with open(f"/sys/class/net/{name}/{attribute}", encoding="ascii") as handle:
            return handle.read().strip()
    except OSError:
        return None


def _is_up(name: str) -> bool:
    flags = _read_sysfs(name, "flags")
    if flags is None:
        return False
    try:
        return bool(int(flags, 16) & 0x1)  # IFF_UP
    except ValueError:
        return False


def _interface_mac(name: str) -> str | None:
    address = _read_sysfs(name, "address")
    if address is None or address == "00:00:00:00:00:00":
        return address
    return address


def resolve_interface(interface: str) -> str:
    """Validate that an interface exists before opening a socket."""
    if not interface or not isinstance(interface, str):
        raise CaptureError("an interface name is required")
    try:
        socket.if_nametoindex(interface)
    except OSError as error:
        raise CaptureError(f"unknown interface {interface!r}: {error}") from error
    return interface


@dataclass
class CapturedFrame:
    """One frame read from an AF_PACKET socket."""

    data: bytes
    interface: str
    packet_type: int
    protocol: int
    timestamp: float
    timestamp_source: str = "userspace"
    capture_truncated: bool = False
    vlan_reconstructed: bool = False

    def to_dict(
        self,
        *,
        decode: str = "full",
        payload_limit: int = 256,
    ) -> dict:
        """Describe the frame at the requested decode verbosity.

        ``decode`` is one of:

        ``none``
            Only transport metadata and raw hex.
        ``summary``
            A compact identification line, for triaging large captures.
        ``full``
            The complete decoded tree.
        """
        entry: dict = {
            "interface": self.interface,
            "direction": "outgoing" if self.is_outgoing else "incoming",
            "packet_type": PACKET_TYPE_NAMES.get(self.packet_type, str(self.packet_type)),
            "protocol": f"0x{self.protocol:04x}",
            "captured_at": round(self.timestamp, 6),
            "length": len(self.data),
            "timestamp_source": self.timestamp_source,
            "capture_truncated": self.capture_truncated,
            "vlan_reconstructed": self.vlan_reconstructed,
        }

        if decode == "none":
            entry["hex"] = hex_bytes(self.data)
            return entry

        if decode == "summary":
            entry.update(summarize_frame(self.data))
            return entry

        entry["hex"] = hex_bytes(self.data)
        decoded = decode_link_frame(self.data, payload_limit=payload_limit)
        decoded.pop("hex", None)  # the transport field above already carries it
        entry.update(decoded)
        return entry

    @property
    def is_outgoing(self) -> bool:
        """Whether this frame was transmitted by this host."""
        return self.packet_type == PACKET_OUTGOING


class RawInterface:
    """An AF_PACKET socket bound to one interface.

    The socket receives everything the interface sees, including frames this
    process transmits (reported as ``PACKET_OUTGOING``), which lets a caller
    distinguish its own request from the peer's reply.
    """

    def __init__(self, interface: str):
        self.interface = resolve_interface(interface)
        try:
            self._socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
            )
        except OSError as error:
            raise _require_privileges(error) from error
        self.promiscuous_enabled = False
        self.kernel_timestamps = False
        try:
            # Linux packet sockets deliver stripped VLAN tags as ancillary data.
            self._socket.setsockopt(SOL_PACKET, 8, 1)  # PACKET_AUXDATA
        except OSError as error:
            self.close()
            raise CaptureError(f"cannot enable VLAN capture metadata: {error}") from error
        try:
            self._socket.setsockopt(socket.SOL_SOCKET, 35, 1)  # Linux SO_TIMESTAMPNS
            self.kernel_timestamps = True
        except OSError:
            pass

    def __enter__(self) -> "RawInterface":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def bind(self) -> None:
        try:
            self._socket.bind((self.interface, 0))
            # The socket can queue traffic from any interface before binding.
            self.drain()
        except OSError as error:
            raise CaptureError(
                f"cannot bind to interface {self.interface!r}: {error}"
            ) from error

    def set_promiscuous(self, enabled: bool = True) -> None:
        """Enable promiscuous mode so frames not addressed to us are visible.

        Best-effort: ``lo`` and some tunnel interfaces reject the membership,
        which is not fatal for send/receive on an ordinary Ethernet port.
        """
        if not enabled:
            return
        try:
            self._socket.setsockopt(
                SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                _mreq(self.interface, PACKET_MR_PROMISC),
            )
            self.promiscuous_enabled = True
        except OSError:
            pass

    def send(self, frame: bytes) -> int:
        try:
            sent = self._socket.send(frame)
        except OSError as error:
            raise CaptureError(f"send failed on {self.interface!r}: {error}") from error
        if sent != len(frame):
            raise CaptureError(
                f"short packet send: wrote {sent} of {len(frame)} bytes"
            )
        return sent

    def recv(self, timeout: float) -> CapturedFrame | None:
        """Read one frame, or return None if the timeout expires."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._socket.settimeout(remaining)
            try:
                if hasattr(self._socket, "recvmsg"):
                    data, ancillary, flags, address = self._socket.recvmsg(262144, 128)
                else:
                    data, address = self._socket.recvfrom(65535)
                    ancillary, flags = [], 0
            except socket.timeout:
                return None
            except OSError as error:
                raise CaptureError(f"receive failed on {self.interface!r}: {error}") from error
            if address and address[0] == self.interface:
                data, reconstructed = _restore_vlan(data, ancillary)
                captured = _captured_from_sockaddr(data, address)
                captured.vlan_reconstructed = reconstructed
                captured.capture_truncated = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                for level, kind, value in ancillary:
                    if level == socket.SOL_SOCKET and kind == 35 and len(value) >= struct.calcsize("@ll"):
                        seconds, nanoseconds = struct.unpack("@ll", value[:struct.calcsize("@ll")])
                        captured.timestamp = seconds + nanoseconds / 1_000_000_000
                        captured.timestamp_source = "kernel_software"
                return captured

    def drain(self) -> list[CapturedFrame]:
        """Read every frame already queued, without blocking."""
        frames = []
        self._socket.setblocking(False)
        try:
            # Do not spin forever on a busy link during setup.
            for _ in range(4096):
                try:
                    data, address = self._socket.recvfrom(65535)
                except (BlockingIOError, socket.timeout):
                    break
                except OSError as error:
                    raise CaptureError(f"receive failed on {self.interface!r}: {error}") from error
                frames.append(_captured_from_sockaddr(data, address))
        finally:
            self._socket.setblocking(True)
        return frames

    def statistics(self) -> dict:
        """PACKET_STATISTICS counters reset on read; call once per capture."""
        try:
            packets, drops = struct.unpack("=II", self._socket.getsockopt(SOL_PACKET, 6, 8))
            return {"socket_packets": packets, "socket_drops": drops,
                    "drop_counters_available": True,
                    "promiscuous_enabled": self.promiscuous_enabled,
                    "timestamp_mode": "kernel_software" if self.kernel_timestamps else "userspace"}
        except (OSError, AttributeError, struct.error):
            return {"drop_counters_available": False}

    def close(self) -> None:
        sock = getattr(self, "_socket", None)
        if sock is not None:
            try:
                sock.close()
            finally:
                self._socket = None


def _restore_vlan(data: bytes, ancillary: list) -> tuple[bytes, bool]:
    """Restore the outer VLAN header reported by Linux tpacket_auxdata.

    VALID status bits, not nonzero TCI, distinguish VLAN 0 from an untagged
    frame. A remaining VLAN header may be the inner QinQ tag: never suppress
    insertion merely because the delivered bytes are already VLAN-tagged.
    """
    for level, kind, value in ancillary:
        if level != SOL_PACKET or kind != 8 or len(value) < 20:
            continue
        status, length, snaplen, mac, net, tci, tpid = struct.unpack("=IIIHHHH", value[:20])
        if not status & (1 << 4):  # TP_STATUS_VLAN_VALID
            continue
        if len(data) < 14:
            raise CaptureError("VLAN metadata accompanies an incomplete Ethernet header")
        if not status & (1 << 6):  # TP_STATUS_VLAN_TPID_VALID
            tpid = 0x8100
        return data[:12] + struct.pack("!HH", tpid, tci) + data[12:], True
    return data, False


def _mreq(interface: str, membership_type: int) -> bytes:
    index = socket.if_nametoindex(interface)
    # struct packet_mreq { int mr_ifindex; unsigned short mr_type; unsigned short mr_alen; unsigned char mr_address[8]; }
    return struct.pack("=ihh8s", index, membership_type, 0, b"\x00" * 8)


def _captured_from_sockaddr(data: bytes, address: tuple) -> CapturedFrame:
    """Build a CapturedFrame from the AF_PACKET sockaddr tuple.

    The tuple is ``(ifname, protocol, pkttype, hatype, hwaddr)``. Index 1 is the
    link-layer protocol the frame arrived on, not the EtherType, so the EtherType
    is read from the frame itself by the decoder. Index 2 is the packet type
    (PACKET_HOST / PACKET_OUTGOING / ...).
    """
    interface = address[0] if len(address) > 0 else ""
    protocol = address[1] if len(address) > 1 else 0
    packet_type = address[2] if len(address) > 2 else 0
    return CapturedFrame(
        data=data,
        interface=interface,
        protocol=protocol,
        packet_type=packet_type,
        timestamp=time.time(),
    )


@dataclass
class ExchangeResult:
    """The outcome of a send-and-capture exchange."""

    interface: str
    frames: list[CapturedFrame] = field(default_factory=list)
    response_timeout: float = 1.0
    send_errors: list[str] = field(default_factory=list)
    quality: dict = field(default_factory=dict)
    transmissions: list[dict] = field(default_factory=list)

    def replies(self, *, exclude_outgoing: bool = True) -> list[CapturedFrame]:
        if not exclude_outgoing:
            return list(self.frames)
        return [frame for frame in self.frames if not frame.is_outgoing]

    def own_frames(self) -> list[CapturedFrame]:
        return [frame for frame in self.frames if frame.is_outgoing]


def exchange(
    interface: str,
    frames: list[bytes],
    *,
    timeout: float = 1.0,
    count: int = 1,
    interval: float = 0.0,
    capture_own: bool = True,
    promiscuous: bool = True,
    source_mac_filter: str | None = None,
    ether_type_filter: int | None = None,
    frame_filter=None,
    max_capture_frames: int = 5000,
    frame_delays: list[float] | None = None,
) -> ExchangeResult:
    """Send frames on an interface and capture what comes back.

    ``timeout`` is the reply window after the final transmission. Replies that
    arrive during sending are collected by the receive/send event loop.
    ``interval`` spaces every frame.
    ``count`` and ``interval`` repeat the send. Setting ``capture_own`` to False
    discards frames this process transmitted, leaving only peer replies.

    On a busy link a promiscuous socket sees unrelated traffic, so
    ``source_mac_filter`` and ``ether_type_filter`` narrow the capture to the
    frames that plausibly answer the request.
    """
    if not frames:
        raise CaptureError("at least one frame is required")
    if timeout < 0:
        raise CaptureError("timeout cannot be negative")
    if count < 1:
        raise CaptureError("count must be at least 1")
    if interval < 0:
        raise CaptureError("interval cannot be negative")

    wanted_mac = None
    if source_mac_filter:
        from .packets import parse_mac

        wanted_mac = parse_mac(source_mac_filter)

    import math
    if not math.isfinite(timeout) or not math.isfinite(interval):
        raise CaptureError("timeout and interval must be finite")
    total = len(frames) * count
    if total > 10_000 or (total - 1) * interval + timeout > 120:
        raise CaptureError("exchange is limited to 10,000 sends and 120 seconds")
    if frame_delays is not None and (len(frame_delays) != total or any(
            not math.isfinite(d) or d < 0 for d in frame_delays) or sum(frame_delays) + timeout > 120):
        raise CaptureError("frame_delays must match sends and fit the 120-second limit")
    if not 1 <= max_capture_frames <= 5000:
        raise CaptureError("max_capture_frames must be between 1 and 5000")

    result = ExchangeResult(interface=interface, response_timeout=timeout)
    started = time.time()
    observed = 0
    retained_bytes = 0
    reason = "timeout"
    with RawInterface(interface) as raw:
        raw.bind()
        if promiscuous:
            raw.set_promiscuous(True)
        raw.drain()
        next_send = time.monotonic() + (frame_delays[0] if frame_delays else 0)
        sent = 0
        deadline = None
        while True:
            now = time.monotonic()
            if sent < total and now >= next_send:
                sent_at = time.time()
                raw.send(frames[sent % len(frames)])
                result.transmissions.append({"send_index": sent, "sent_at": sent_at})
                sent += 1
                if sent == total:
                    deadline = time.monotonic() + timeout
                else:
                    next_send = time.monotonic() + (frame_delays[sent] if frame_delays else interval)
                # Poll receive even during back-to-back sending to avoid starving it.
                wait_until = min(next_send, now + 0.001) if sent < total else deadline
            else:
                wait_until = next_send if sent < total else deadline
            if timeout == 0:
                if sent == total:
                    break
                time.sleep(max(0, next_send - time.monotonic()))
                continue
            if sent == total and time.monotonic() >= deadline:
                break
            remaining = max(0.000001, wait_until - time.monotonic())
            captured = raw.recv(remaining)
            if captured is None:
                continue
            observed += 1
            if not capture_own and captured.is_outgoing:
                continue
            if wanted_mac is not None and captured.data[6:12] != wanted_mac:
                continue
            if ether_type_filter is not None or frame_filter is not None:
                decoded = decode_link_frame(captured.data, payload_limit=0)
                if ether_type_filter is not None and decoded.get("ether_type") != f"0x{ether_type_filter:04x}":
                    continue
                if frame_filter is not None and not frame_filter(decoded):
                    continue
            retained_bytes += len(captured.data)
            if retained_bytes > 32 * 1024 * 1024:
                reason = "byte_limit"
                break
            result.frames.append(captured)
            if len(result.frames) >= max_capture_frames:
                reason = "frame_limit"
                break
        statistics = raw.statistics() if hasattr(raw, "statistics") else {"drop_counters_available": False}
        result.quality = {**statistics, "capture_started_at": started,
                          "capture_ended_at": time.time(), "stop_reason": reason,
                          "frames_observed": observed, "frames_retained": len(result.frames),
                          "frames_sent": sent, "requested_sends": total,
                          "capture_enabled": timeout > 0,
                          "capture_complete": timeout > 0 and reason == "timeout" and not statistics.get("socket_drops", 0)
                              and not any(f.capture_truncated for f in result.frames),
                          "note": "socket counters include setup; kernel timestamps are software receive times, not wire/hardware timestamps"}
    return result
