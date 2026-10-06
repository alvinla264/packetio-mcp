"""Dependency-free Ethernet frame construction and decoding.

Builders are deliberately generic: the caller supplies the header fields and
payload bytes, and this module handles framing, validation, VLAN tags and the
Ethernet minimum-length pad. Higher-level protocols (ARP, ICMP, DHCP, ...) are
left to the caller, which can express them with ``raw`` or ``ethernet`` and an
explicit ``payload_hex``.
"""

from __future__ import annotations

import re
import struct

ETHERNET_HEADER_LEN = 14
ETHERNET_MIN_FRAME_LEN = 60  # Excludes the four-byte FCS added by hardware.
IEEE_8023_MIN_PAYLOAD_LEN = ETHERNET_MIN_FRAME_LEN - ETHERNET_HEADER_LEN
VLAN_MODES = ("untagged", "802.1q", "qinq")
ETH_P_ALL = 0x0003
MAX_PACKET_BYTES = 9216
MAX_HEX_CHARACTERS = MAX_PACKET_BYTES * 6
DEFAULT_SOURCE_MAC = "02:00:00:00:00:01"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# pkttype values reported by AF_PACKET in the recvfrom() address tuple.
PACKET_HOST = 0
PACKET_BROADCAST = 1
PACKET_MULTICAST = 2
PACKET_OTHERHOST = 3
PACKET_OUTGOING = 4

PACKET_TYPE_NAMES = {
    PACKET_HOST: "host",
    PACKET_BROADCAST: "broadcast",
    PACKET_MULTICAST: "multicast",
    PACKET_OTHERHOST: "otherhost",
    PACKET_OUTGOING: "outgoing",
}

_MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class PacketError(ValueError):
    """Raised when a packet description is invalid."""


def parse_mac(value: str) -> bytes:
    """Convert a colon-delimited MAC address into its six wire bytes."""
    if not isinstance(value, str) or not _MAC_PATTERN.fullmatch(value):
        raise PacketError(f"invalid MAC address: {value!r}")
    return bytes.fromhex(value.replace(":", ""))


def format_mac(raw: bytes) -> str:
    """Render wire bytes as a colon-delimited MAC address."""
    return ":".join(f"{byte:02x}" for byte in raw[:6])


def compact_hex(value: str) -> str:
    """Strip separators commonly used when writing hexadecimal by hand."""
    if not isinstance(value, str):
        raise PacketError(f"expected a hexadecimal string, got {type(value).__name__}")
    if len(value) > MAX_HEX_CHARACTERS:
        raise PacketError(f'hex input exceeds {MAX_HEX_CHARACTERS} characters')
    return re.sub(r"[\s:_-]", "", value)


def parse_hex_bytes(value: str, *, what: str = "hex") -> bytes:
    """Parse separated or compact hexadecimal into bytes."""
    compact = compact_hex(value)
    if not compact:
        return b""
    if len(compact) > MAX_PACKET_BYTES * 2:
        raise PacketError(f'{what} exceeds {MAX_PACKET_BYTES} bytes')
    if len(compact) % 2 != 0:
        raise PacketError(f"{what} must contain a whole number of bytes")
    if not re.fullmatch(r"[0-9a-fA-F]+", compact):
        raise PacketError(f"{what} contains a non-hexadecimal character")
    return bytes.fromhex(compact)


def parse_ethernet_frame(value: str) -> bytes:
    """Parse a raw Ethernet frame written as compact or separated hex."""
    frame = parse_hex_bytes(value, what="raw frame")
    if len(frame) < ETHERNET_HEADER_LEN:
        raise PacketError("raw Ethernet frame must include a 14-byte header")
    return frame


def parse_ether_type(value: str | int) -> int:
    """Parse an EtherType written as an integer or hexadecimal string."""
    if isinstance(value, bool):
        raise PacketError(f"invalid EtherType: {value!r}")
    if isinstance(value, int):
        ether_type = value
    elif isinstance(value, str):
        text = value.lower()
        base = 16 if text.startswith("0x") else 16
        compact = text.removeprefix("0x")
        if not compact or not re.fullmatch(r"[0-9a-f]+", compact):
            raise PacketError(f"invalid EtherType: {value!r}")
        ether_type = int(compact, base)
    else:
        raise PacketError(f"invalid EtherType: {value!r}")
    if not 0 <= ether_type <= 0xFFFF:
        raise PacketError("EtherType must be between 0x0000 and 0xffff")
    return ether_type


def _vlan_tci(vlan_id: int, pcp: int, dei: int = 0) -> int:
    if not 0 <= vlan_id <= 4094:
        raise PacketError("VLAN ID must be in the range 0 through 4094")
    if not 0 <= pcp <= 7:
        raise PacketError("VLAN PCP must be in the range 0 through 7")
    if not 0 <= dei <= 1:
        raise PacketError("VLAN DEI must be 0 or 1")
    return (pcp << 13) | (dei << 12) | vlan_id


def build_ethernet_frame(
    *,
    destination_mac: str = BROADCAST_MAC,
    source_mac: str = DEFAULT_SOURCE_MAC,
    ether_type: str | int = "88b5",
    vlan_mode: str = "untagged",
    vlan_id: int = 100,
    pcp: int = 0,
    dei: int = 0,
    outer_vlan_id: int = 200,
    outer_pcp: int = 0,
    outer_dei: int = 0,
    payload_hex: str = "",
    pad: bool = True,
) -> bytes:
    """Build an Ethernet II frame with optional 802.1Q or QinQ tags."""
    if vlan_mode not in VLAN_MODES:
        raise PacketError(f"VLAN mode must be one of: {', '.join(VLAN_MODES)}")

    frame = parse_mac(destination_mac) + parse_mac(source_mac)
    if vlan_mode == "802.1q":
        frame += struct.pack("!HH", 0x8100, _vlan_tci(vlan_id, pcp, dei))
    elif vlan_mode == "qinq":
        frame += struct.pack("!HH", 0x88A8, _vlan_tci(outer_vlan_id, outer_pcp, outer_dei))
        frame += struct.pack("!HH", 0x8100, _vlan_tci(vlan_id, pcp, dei))

    frame += struct.pack("!H", parse_ether_type(ether_type)) + parse_hex_bytes(
        payload_hex, what="payload"
    )
    if len(frame) > MAX_PACKET_BYTES:
        raise PacketError(f'frame exceeds {MAX_PACKET_BYTES} bytes')
    if pad and len(frame) < ETHERNET_MIN_FRAME_LEN:
        frame = frame.ljust(ETHERNET_MIN_FRAME_LEN, b"\x00")
    return frame


def hex_bytes(frame: bytes) -> str:
    """Return bytes as copy/paste-friendly, space-delimited hex."""
    return " ".join(f"{byte:02x}" for byte in frame)


def hex_dump(frame: bytes, width: int = 16) -> str:
    """Return a conventional offset, hex and ASCII frame dump."""
    lines = []
    for offset in range(0, len(frame), width):
        chunk = frame[offset : offset + width]
        hexadecimal = " ".join(f"{byte:02x}" for byte in chunk)
        text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hexadecimal:<{width * 3 - 1}}  |{text}|")
    return "\n".join(lines)


def parse_vlan_stack(frame: bytes) -> tuple[list[dict], int, int]:
    """Walk the VLAN tag stack.

    Returns (tags, offset_after_tags, ether_type). ``tags`` is ordered
    outermost-first, each entry carrying ``tpid``, ``vlan_id``, ``pcp`` and
    ``dei``.
    """
    offset = 12
    tags: list[dict] = []
    while offset + 4 <= len(frame):
        tpid = struct.unpack("!H", frame[offset : offset + 2])[0]
        if tpid not in (0x8100, 0x88A8, 0x9100, 0x9200):
            break
        tci = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        tags.append(
            {
                "tpid": f"0x{tpid:04x}",
                "vlan_id": tci & 0x0FFF,
                "pcp": (tci >> 13) & 0x7,
                "dei": (tci >> 12) & 0x1,
            }
        )
        offset += 4

    if offset + 2 <= len(frame):
        ether_type = struct.unpack("!H", frame[offset : offset + 2])[0]
        offset += 2
    else:
        ether_type = 0
    return tags, offset, ether_type


def decode_frame(frame: bytes, *, payload_limit: int = 256) -> dict:
    """Decode an Ethernet frame into a JSON-friendly summary.

    The decoder is intentionally shallow: it reports addressing, VLAN tags,
    EtherType and the payload bytes as hex. Protocol-specific interpretation
    stays with the caller.
    """
    summary: dict = {"length": len(frame), "hex": hex_bytes(frame)}
    if len(frame) < ETHERNET_HEADER_LEN:
        summary["error"] = "frame shorter than the 14-byte Ethernet header"
        return summary

    summary["destination_mac"] = format_mac(frame[0:6])
    summary["source_mac"] = format_mac(frame[6:12])

    tags, payload_offset, ether_type = parse_vlan_stack(frame)
    summary["vlan_tags"] = tags
    summary["ether_type"] = f"0x{ether_type:04x}"

    payload = frame[payload_offset:]
    if ether_type <= 1500 and ether_type != 0:
        summary["frame_kind"] = "ieee-802.3-length"
        summary["llc_length"] = ether_type
    else:
        summary["frame_kind"] = "ethernet-ii"
    if payload:
        summary["payload_hex"] = hex_bytes(payload[:payload_limit])
        summary["payload_length"] = len(payload)
        if len(payload) > payload_limit:
            summary["payload_truncated"] = True
    else:
        summary["payload_length"] = 0

    # A convenience peek for the two protocols most often used to elicit a reply.
    if ether_type == 0x0806 and len(payload) >= 8:
        summary["arp"] = {
            "operation": struct.unpack("!H", payload[6:8])[0],
            "sender_mac": format_mac(payload[8:14]) if len(payload) >= 14 else None,
            "sender_ip": ".".join(str(b) for b in payload[14:18]) if len(payload) >= 18 else None,
            "target_mac": format_mac(payload[18:24]) if len(payload) >= 24 else None,
            "target_ip": ".".join(str(b) for b in payload[24:28]) if len(payload) >= 28 else None,
        }
    elif ether_type == 0x0800 and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
        summary["ipv4"] = {
            "version": payload[0] >> 4,
            "header_length": ihl,
            "protocol": payload[9],
            "source_ip": ".".join(str(b) for b in payload[12:16]),
            "destination_ip": ".".join(str(b) for b in payload[16:20]),
        }
        if payload[9] == 1 and len(payload) >= ihl + 8:
            icmp = payload[ihl:]
            summary["icmp"] = {
                "type": icmp[0],
                "code": icmp[1],
                "id": struct.unpack("!H", icmp[4:6])[0],
                "sequence": struct.unpack("!H", icmp[6:8])[0],
            }
    return summary
