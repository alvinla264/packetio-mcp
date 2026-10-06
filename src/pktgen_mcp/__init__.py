"""Generic packet generation and send/receive tools exposed over MCP."""

from .packets import (
    BROADCAST_MAC,
    DEFAULT_SOURCE_MAC,
    VLAN_MODES,
    PacketError,
    build_ethernet_frame,
    decode_frame,
    parse_ethernet_frame,
    parse_ether_type,
)

__all__ = [
    "BROADCAST_MAC",
    "DEFAULT_SOURCE_MAC",
    "VLAN_MODES",
    "PacketError",
    "build_ethernet_frame",
    "decode_frame",
    "parse_ethernet_frame",
    "parse_ether_type",
]
