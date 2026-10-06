"""Shared helpers for the packet generator MCP tools."""

from __future__ import annotations

from typing import Any

from .packets import PacketError


class ToolError(ValueError):
    """An error that should be reported to the caller as a validation failure."""


def build_frame(
    *,
    builder: str = "ethernet",
    frame_hex: str | None = None,
    destination_mac: str | None = None,
    source_mac: str | None = None,
    ether_type: str | int | None = None,
    vlan_mode: str = "untagged",
    vlan_id: int | None = None,
    pcp: int = 0,
    dei: int = 0,
    outer_vlan_id: int | None = None,
    outer_pcp: int = 0,
    outer_dei: int = 0,
    payload_hex: str = "",
    pad: bool = True,
) -> bytes:
    """Build one frame from either raw hex or structured header fields."""
    from .packets import build_ethernet_frame, parse_ethernet_frame

    if builder == "raw":
        if not frame_hex:
            raise ToolError("builder 'raw' requires frame_hex")
        return parse_ethernet_frame(frame_hex)
    if builder != "ethernet":
        raise ToolError(f"unknown builder {builder!r}; use 'ethernet' or 'raw'")

    try:
        return build_ethernet_frame(
            destination_mac=destination_mac or "ff:ff:ff:ff:ff:ff",
            source_mac=source_mac or "02:00:00:00:00:01",
            ether_type=ether_type if ether_type is not None else "88b5",
            vlan_mode=vlan_mode,
            vlan_id=vlan_id if vlan_id is not None else 100,
            pcp=pcp,
            dei=dei,
            outer_vlan_id=outer_vlan_id if outer_vlan_id is not None else 200,
            outer_pcp=outer_pcp,
            outer_dei=outer_dei,
            payload_hex=payload_hex,
            pad=pad,
        )
    except PacketError as error:
        raise ToolError(str(error)) from error


def response_payload(frame: bytes) -> dict[str, Any]:
    """Summarise one captured frame for the model."""
    from .packets import hex_bytes

    out: dict[str, Any] = {
        "length": len(frame),
        "hex": hex_bytes(frame),
    }
    from .packets import decode_frame

    decoded = decode_frame(frame)
    decoded.pop("hex", None)
    out.update(decoded)
    return out
