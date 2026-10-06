"""MCP server: generic packet generation and send/receive on a local interface.

The tools here are deliberately low-level. They build Ethernet frames from
explicit fields or raw hex, transmit them on a named interface, and return
whatever comes back decoded into JSON. Protocol construction (ARP, ICMP, DHCP,
LLDP, ...) is left to the caller, which is what lets a model express any frame
without the server needing to know that protocol.

Raw AF_PACKET sockets require root or CAP_NET_RAW.
"""

from __future__ import annotations

import sys
from typing import Any

from fastmcp import FastMCP

from .analysis import frame_summaries, summarise_frames
from .capture import (
    CaptureError,
    check_raw_socket_permission,
    exchange,
    list_interfaces,
    privilege_fix_command,
    resolve_interface,
)
from .common import ToolError, build_frame
from .decode import decode_link_frame, summarize_frame
from .filters import FilterError, compile_filter
from .packets import (
    BROADCAST_MAC,
    DEFAULT_SOURCE_MAC,
    VLAN_MODES,
    PacketError,
    decode_frame,
    hex_bytes,
    hex_dump,
)
from .pcap import (
    PcapError,
    capture_dir,
    list_captures,
    read_pcap,
    resolve_capture_path,
    write_pcap,
)

mcp = FastMCP("PacketIO")

DECODE_MODES = ("none", "summary", "full")
MAX_CAPTURE_FRAMES = 50_000
MAX_REPLAY_FRAMES = 10_000


def _error(message: str) -> dict[str, Any]:
    return {"ok": False, "error": message}


def _validate_decode_mode(decode: str) -> str | None:
    """Return an error message when a decode mode is not recognised."""
    if decode not in DECODE_MODES:
        return f"decode must be one of: {', '.join(DECODE_MODES)}"
    return None


def _summarise(result, *, decode: str = "full", payload_limit: int = 256) -> dict[str, Any]:
    return {
        "interface": result.interface,
        "total_frames": len(result.frames),
        "reply_count": len(result.replies()),
        "own_frame_count": len(result.own_frames()),
        "response_timeout_seconds": result.response_timeout,
        "capture_quality": result.quality,
        "replies": [
            frame.to_dict(decode=decode, payload_limit=payload_limit)
            for frame in result.replies()
        ],
        "own_frames": [
            frame.to_dict(decode=decode, payload_limit=payload_limit)
            for frame in result.own_frames()
        ],
    }


def _prepare_expectations(expect: dict | None) -> dict | None:
    """Reject malformed expectations before any network side effect."""
    if expect is None:
        return None
    if not isinstance(expect, dict) or not expect or set(expect) - {
            'reply_count_at_least', 'reply_contains', 'filter'}:
        raise ToolError('expect must contain only recognized, nonempty checks')
    if 'reply_count_at_least' in expect:
        value = expect['reply_count_at_least']
        if type(value) is not int or not 0 <= value <= 5000:
            raise ToolError('reply_count_at_least must be an integer from 0 to 5000')
    if 'reply_contains' in expect:
        from .packets import parse_hex_bytes
        value = expect['reply_contains']
        if not isinstance(value, str) or not parse_hex_bytes(value):
            raise ToolError('reply_contains must be nonempty bounded hexadecimal')
    if 'filter' in expect:
        try:
            if not isinstance(expect['filter'], str) or compile_filter(expect['filter']) is None:
                raise ToolError('expect filter must be a nonempty string')
        except FilterError as error:
            raise ToolError(f'invalid expect filter: {error}') from error
    return expect


def _evaluate_expectations(
    expect: dict | None, reply_frames: list[bytes]
) -> dict[str, Any] | None:
    """Check simple expectations against the captured reply frames.

    Expectations are evaluated against the raw reply bytes rather than the
    presented dictionaries, so the decode verbosity a caller chose cannot change
    whether an assertion passes.

    Supported keys:

    ``reply_count_at_least``
        Require at least this many replies.
    ``reply_contains``
        Require a reply whose raw bytes contain this hex fragment.
    ``filter``
        Require a reply matching this filter expression.
    """
    if expect is None:
        return None
    if not isinstance(expect, dict):
        return {"matched": False, "reason": "expect must be an object"}

    checks: list[dict[str, Any]] = []
    matched = True
    decoded_replies = [decode_link_frame(frame, payload_limit=0) for frame in reply_frames]

    if "reply_count_at_least" in expect:
        try:
            wanted = int(expect["reply_count_at_least"])
        except (TypeError, ValueError):
            checks.append(
                {"check": "reply_count_at_least", "passed": False, "reason": "not an integer"}
            )
            matched = False
        else:
            passed = len(reply_frames) >= wanted
            checks.append(
                {
                    "check": "reply_count_at_least",
                    "passed": passed,
                    "expected": wanted,
                    "actual": len(reply_frames),
                }
            )
            matched = matched and passed

    if "reply_contains" in expect:
        try:
            from .packets import parse_hex_bytes
            fragment = parse_hex_bytes(expect['reply_contains'])
        except ValueError:
            checks.append(
                {
                    "check": "reply_contains",
                    "passed": False,
                    "reason": "not valid hexadecimal",
                }
            )
            matched = False
        else:
            passed = any(fragment in frame for frame in reply_frames)
            checks.append(
                {
                    "check": "reply_contains",
                    "passed": passed,
                    "fragment": fragment.hex(" "),
                }
            )
            matched = matched and passed

    if "filter" in expect:
        try:
            predicate = compile_filter(str(expect["filter"]))
        except FilterError as error:
            checks.append({"check": "filter", "passed": False, "reason": str(error)})
            matched = False
        else:
            if predicate is None:
                checks.append({"check": "filter", "passed": False, "reason": "empty filter"})
                matched = False
            else:
                passed = any(predicate(decoded) for decoded in decoded_replies)
                checks.append(
                    {"check": "filter", "passed": passed, "expression": expect["filter"]}
                )
                matched = matched and passed

    if not checks:
        return {"matched": False, "reason": "expect contained no recognised checks"}
    return {"matched": matched, "checks": checks}


@mcp.tool()
def list_available_interfaces(include_down: bool = True) -> dict[str, Any]:
    """List local network interfaces that packets can be sent on.

    Call this first to discover valid interface names. Prefer an interface whose
    ``up`` flag is true; sending on a down interface usually fails.

    Args:
        include_down: Include interfaces that are administratively down.

    Returns:
        An object with an ``interfaces`` list of ``{name, index, up, mac}``.
    """
    interfaces = list_interfaces()
    if not include_down:
        interfaces = [entry for entry in interfaces if entry.get("up")]
    return {"ok": True, "count": len(interfaces), "interfaces": interfaces}


@mcp.tool()
def describe_builders() -> dict[str, Any]:
    """Describe how to construct frames with the 'ethernet' and 'raw' builders.

    Returns the accepted arguments, the VLAN modes, and the default
    source/destination MAC addresses so a caller can format a frame correctly.
    """
    return {
        "ok": True,
        "builders": {
            "ethernet": {
                "description": (
                    "Structured Ethernet II frame. Header fields are named; the "
                    "payload is arbitrary hex so any protocol can be encoded."
                ),
                "arguments": {
                    "destination_mac": "MAC, default broadcast " + BROADCAST_MAC,
                    "source_mac": "MAC, default " + DEFAULT_SOURCE_MAC,
                    "ether_type": "'0800', '0806', '86dd', '88b5', ...",
                    "vlan_mode": "one of " + ", ".join(VLAN_MODES),
                    "vlan_id": "0-4094 (inner tag when vlan_mode is qinq)",
                    "pcp": "0-7 priority on the inner tag",
                    "dei": "0 or 1 drop-eligible indicator on the inner tag",
                    "outer_vlan_id": "0-4094, QinQ outer tag only",
                    "outer_pcp": "0-7, QinQ outer tag only",
                    "outer_dei": "0 or 1, QinQ outer tag only",
                    "payload_hex": "payload bytes as hex, e.g. 'de ad be ef'",
                    "pad": "pad to the 60-byte Ethernet minimum (default true)",
                },
            },
            "raw": {
                "description": (
                    "An exact Ethernet frame supplied as hex. It must include the "
                    "14-byte header. Nothing is added or padded."
                ),
                "arguments": {"frame_hex": "complete frame as hex bytes"},
            },
        },
        "packet_types_reported": [
            "incoming frames appear as host/broadcast/multicast/otherhost",
            "frames this host transmitted appear as outgoing",
        ],
    }


@mcp.tool()
def build_packet(
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
) -> dict[str, Any]:
    """Build a frame and return its bytes without sending anything.

    Use this to verify a frame is well formed and to read back the exact wire
    bytes before transmitting. It never touches the network.

    Args:
        builder: 'ethernet' for structured fields, 'raw' for an exact frame.
        frame_hex: complete frame hex; required when builder is 'raw'.
        destination_mac: destination MAC address.
        source_mac: source MAC address.
        ether_type: EtherType such as '0800', '0806', or '88b5'.
        vlan_mode: 'untagged', '802.1q', or 'qinq'.
        vlan_id: VLAN ID for the inner (or only) tag.
        pcp: 802.1p priority for the inner (or only) tag.
        dei: drop-eligible indicator for the inner (or only) tag.
        outer_vlan_id: QinQ outer VLAN ID.
        outer_pcp: QinQ outer priority.
        outer_dei: QinQ outer drop-eligible indicator.
        payload_hex: payload bytes as hex.
        pad: pad short frames to the 60-byte Ethernet minimum.

    Returns:
        The frame length, space-delimited hex, an ASCII dump, and decoded fields.
    """
    try:
        frame = build_frame(
            builder=builder,
            frame_hex=frame_hex,
            destination_mac=destination_mac,
            source_mac=source_mac,
            ether_type=ether_type,
            vlan_mode=vlan_mode,
            vlan_id=vlan_id,
            pcp=pcp,
            dei=dei,
            outer_vlan_id=outer_vlan_id,
            outer_pcp=outer_pcp,
            outer_dei=outer_dei,
            payload_hex=payload_hex,
            pad=pad,
        )
    except (ToolError, PacketError) as error:
        return _error(str(error))

    return {
        "ok": True,
        "length": len(frame),
        "hex": hex_bytes(frame),
        "dump": hex_dump(frame),
        "decoded": decode_frame(frame),
    }


@mcp.tool()
def send_packet(
    interface: str,
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
    count: int = 1,
    interval: float = 0.0,
) -> dict[str, Any]:
    """Transmit a frame on an interface without waiting for a reply.

    Use this for fire-and-forget traffic. When a reply is expected, use
    send_and_receive instead, which listens on the interface while sending.

    Args:
        interface: interface to transmit on, such as 'eth1'.
        builder: 'ethernet' or 'raw'.
        frame_hex: complete frame hex when builder is 'raw'.
        destination_mac: destination MAC address.
        source_mac: source MAC address.
        ether_type: EtherType such as '0800', '0806', or '88b5'.
        vlan_mode: 'untagged', '802.1q', or 'qinq'.
        vlan_id: VLAN ID for the inner (or only) tag.
        pcp: 802.1p priority for the inner (or only) tag.
        dei: drop-eligible indicator for the inner (or only) tag.
        outer_vlan_id: QinQ outer VLAN ID.
        outer_pcp: QinQ outer priority.
        outer_dei: QinQ outer drop-eligible indicator.
        payload_hex: payload bytes as hex.
        pad: pad short frames to the 60-byte Ethernet minimum.
        count: number of times to transmit the frame.
        interval: seconds between repeated transmissions.

    Returns:
        The interface, frame size, and how many frames were sent.
    """
    try:
        frame = build_frame(
            builder=builder,
            frame_hex=frame_hex,
            destination_mac=destination_mac,
            source_mac=source_mac,
            ether_type=ether_type,
            vlan_mode=vlan_mode,
            vlan_id=vlan_id,
            pcp=pcp,
            dei=dei,
            outer_vlan_id=outer_vlan_id,
            outer_pcp=outer_pcp,
            outer_dei=outer_dei,
            payload_hex=payload_hex,
            pad=pad,
        )
        resolve_interface(interface)
        if count < 1:
            return _error("count must be at least 1")
        if interval < 0:
            return _error("interval cannot be negative")
        # timeout=0 opens, binds, sends and closes without capturing.
        result = exchange(
            interface,
            [frame],
            timeout=0.0,
            count=count,
            interval=interval,
            capture_own=False,
            promiscuous=False,
        )
    except (ToolError, PacketError, CaptureError) as error:
        return _error(str(error))

    return {
        "ok": True,
        "interface": interface,
        "frame_length": len(frame),
        "frames_sent": len(result.transmissions),
        "hex": hex_bytes(frame),
    }


@mcp.tool()
def send_and_receive(
    interface: str,
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
    count: int = 1,
    interval: float = 0.0,
    timeout: float = 1.0,
    capture_own: bool = True,
    max_replies: int = 16,
    reply_source_mac: str | None = None,
    reply_ether_type: str | None = None,
    reply_filter: str | None = None,
    decode: str = "full",
    expect: dict | None = None,
) -> dict[str, Any]:
    """Send a frame and capture what comes back on the same interface.

    This is the request/response tool. It binds a raw socket to the interface,
    drains stale frames, transmits the request, then collects frames for
    ``timeout`` seconds. Replies are reported separately from frames this host
    transmitted, so a peer's answer can be told apart from the request.

    A promiscuous socket on a busy link also sees unrelated traffic. When the
    expected responder is known, pass ``reply_source_mac``, ``reply_ether_type``
    or ``reply_filter`` so only the plausible answer is returned.

    Args:
        interface: interface to transmit and listen on, such as 'eth1'.
        builder: 'ethernet' or 'raw'.
        frame_hex: complete frame hex when builder is 'raw'.
        destination_mac: destination MAC address; use the peer's MAC for unicast.
        source_mac: source MAC address.
        ether_type: EtherType such as '0800', '0806', or '88b5'.
        vlan_mode: 'untagged', '802.1q', or 'qinq'.
        vlan_id: VLAN ID for the inner (or only) tag.
        pcp: 802.1p priority for the inner (or only) tag.
        dei: drop-eligible indicator for the inner (or only) tag.
        outer_vlan_id: QinQ outer VLAN ID.
        outer_pcp: QinQ outer priority.
        outer_dei: QinQ outer drop-eligible indicator.
        payload_hex: payload bytes as hex; this carries the request protocol.
        pad: pad short frames to the 60-byte Ethernet minimum.
        count: number of times to transmit the request.
        interval: seconds between repeated transmissions.
        timeout: seconds to wait for frames after sending.
        capture_own: include frames this host transmitted in the result.
        max_replies: cap the number of replies reported.
        reply_source_mac: only keep captured frames from this source MAC.
        reply_ether_type: only keep captured frames with this EtherType.
        reply_filter: keep only captured frames matching this filter expression.
            See describe_filters for the language.
        decode: decode verbosity, one of 'none', 'summary' or 'full'.
        expect: optional checks applied to the captured replies. Recognised keys
            are ``reply_count_at_least`` (integer), ``reply_contains`` (hex
            fragment present in a reply) and ``filter`` (a reply matches this
            filter expression). The result reports ``matched`` and the detail of
            each check, so a caller can assert on the outcome instead of reading
            the frames itself.

    Returns:
        ``replies`` (frames from the peer) and ``own_frames`` (transmissions),
        the request that was sent, and an ``expectation`` block when ``expect``
        was supplied.
    """
    from .packets import parse_ether_type

    invalid = _validate_decode_mode(decode)
    if invalid:
        return _error(invalid)

    try:
        frame = build_frame(
            builder=builder,
            frame_hex=frame_hex,
            destination_mac=destination_mac,
            source_mac=source_mac,
            ether_type=ether_type,
            vlan_mode=vlan_mode,
            vlan_id=vlan_id,
            pcp=pcp,
            dei=dei,
            outer_vlan_id=outer_vlan_id,
            outer_pcp=outer_pcp,
            outer_dei=outer_dei,
            payload_hex=payload_hex,
            pad=pad,
        )
        resolve_interface(interface)
        if count < 1:
            return _error("count must be at least 1")
        if interval < 0:
            return _error("interval cannot be negative")
        if timeout < 0:
            return _error("timeout cannot be negative")
        wanted_ether_type = (
            parse_ether_type(reply_ether_type) if reply_ether_type else None
        )
        try:
            frame_predicate = compile_filter(reply_filter)
        except FilterError as error:
            return _error(f"invalid reply_filter: {error}")
        expect = _prepare_expectations(expect)

        result = exchange(
            interface,
            [frame],
            timeout=timeout,
            count=count,
            interval=interval,
            capture_own=capture_own,
            promiscuous=True,
            source_mac_filter=reply_source_mac,
            ether_type_filter=wanted_ether_type,
            frame_filter=frame_predicate,
        )
    except (ToolError, PacketError, CaptureError) as error:
        return _error(str(error))

    summary = _summarise(result, decode=decode)
    summary["ok"] = True
    summary["request"] = {
        "length": len(frame),
        "hex": hex_bytes(frame),
        "decoded": decode_link_frame(frame, payload_limit=64),
    }
    summary["frames_sent"] = len(result.transmissions)
    if len(summary["replies"]) > max_replies:
        summary["replies"] = summary["replies"][:max_replies]
        summary["replies_truncated"] = True
    if expect is not None:
        summary["expectation"] = _evaluate_expectations(
            expect, [frame.data for frame in result.replies()]
        )
    return summary


@mcp.tool()
def capture_packets(
    interface: str,
    timeout: float = 2.0,
    max_frames: int = 32,
    ether_type_filter: str | None = None,
    source_mac_filter: str | None = None,
    filter_expression: str | None = None,
    decode: str = "full",
    promiscuous: bool = True,
    include_own: bool = False,
    save_as: str | None = None,
    summarise: bool = True,
) -> dict[str, Any]:
    """Passively listen on an interface and return frames without sending.

    Useful to confirm the link is live, to discover a peer's MAC, or to observe
    a response to traffic sent separately with send_packet. The capture can be
    written to a file so it can be examined later.

    Args:
        interface: interface to listen on, such as 'eth1'.
        timeout: seconds to listen before returning.
        max_frames: stop early once this many frames have been collected.
        ether_type_filter: only keep frames matching this EtherType, e.g. '0806'.
        source_mac_filter: only keep frames from this source MAC.
        filter_expression: keep only frames matching this filter expression, for
            example "protocol == dhcp and ipv4.dhcp.message_type_name == offer".
            See describe_filters for the language.
        decode: decode verbosity, one of 'none', 'summary' or 'full'.
        promiscuous: request promiscuous mode so frames not addressed to this
            host are still visible.
        include_own: keep frames transmitted by this host.
        save_as: optional filename to write the capture to, inside the capture
            directory. A '.pcap' suffix is added when missing.
        summarise: include a protocol/host overview of the captured frames.

    Returns:
        The frames seen at the requested decode verbosity, an optional overview,
        and the capture file path when ``save_as`` was given.
    """
    from .packets import parse_ether_type, parse_mac

    invalid = _validate_decode_mode(decode)
    if invalid:
        return _error(invalid)

    try:
        resolve_interface(interface)
        import math
        if timeout < 0:
            return _error("timeout cannot be negative")
        if not math.isfinite(timeout) or timeout > 120:
            return _error("timeout must be finite and at most 120 seconds")
        if max_frames < 1:
            return _error("max_frames must be at least 1")
        if max_frames > MAX_CAPTURE_FRAMES:
            return _error(f"max_frames may not exceed {MAX_CAPTURE_FRAMES}")
        wanted = None
        if ether_type_filter:
            wanted = parse_ether_type(ether_type_filter)
        wanted_mac = parse_mac(source_mac_filter) if source_mac_filter else None
        try:
            predicate = compile_filter(filter_expression)
        except FilterError as error:
            return _error(f"invalid filter_expression: {error}")
        target_path = resolve_capture_path(save_as, for_write=True) if save_as else None
    except (CaptureError, PacketError, PcapError) as error:
        return _error(str(error))

    import time

    from .capture import RawInterface
    from .packets import PACKET_OUTGOING

    collected: list[tuple[bytes, float]] = []
    captured_objects = []
    frames: list[dict[str, Any]] = []
    capture_started = time.time()
    retained_bytes = 0
    stop_reason = "timeout"
    try:
        with RawInterface(interface) as raw:
            raw.bind()
            if promiscuous:
                raw.set_promiscuous(True)
            deadline = time.monotonic() + timeout
            while len(collected) < max_frames:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                captured = raw.recv(remaining)
                if captured is None:
                    break
                if not include_own and captured.packet_type == PACKET_OUTGOING:
                    continue
                if wanted_mac is not None and captured.data[6:12] != wanted_mac:
                    continue
                if wanted is not None or predicate is not None:
                    decoded_for_filter = decode_link_frame(captured.data, payload_limit=0)
                    if wanted is not None and decoded_for_filter.get("ether_type") != f"0x{wanted:04x}":
                        continue
                    if predicate is not None and not predicate(decoded_for_filter):
                        continue
                retained_bytes += len(captured.data)
                if retained_bytes > 32 * 1024 * 1024:
                    stop_reason = "byte_limit"
                    break
                collected.append((captured.data, captured.timestamp))
                captured_objects.append(captured)
                frames.append(
                    captured.to_dict(decode=decode, payload_limit=256)
                )
            if len(collected) >= max_frames:
                stop_reason = "frame_limit"
            statistics = raw.statistics() if hasattr(raw, "statistics") else {"drop_counters_available": False}
    except CaptureError as error:
        return _error(str(error))

    result: dict[str, Any] = {
        "ok": True,
        "interface": interface,
        "frame_count": len(frames),
        "frames": frames,
        "capture_quality": {**statistics, "capture_started_at": capture_started,
                            "capture_ended_at": time.time(), "stop_reason": stop_reason,
                            "capture_complete": stop_reason == "timeout" and not statistics.get("socket_drops", 0)
                                and not any(f.capture_truncated for f in captured_objects)},
    }
    if summarise:
        result["overview"] = summarise_frames(collected)
    if target_path is not None:
        try:
            if target_path.suffix.lower() == ".pcapng":
                from .pcap import write_pcapng, PcapRecord
                written = write_pcapng(target_path, [PcapRecord(f.data, f.timestamp, len(f.data),
                    interface_name=f.interface, direction=2 if f.is_outgoing else 1,
                    comment=f"timestamp_source={f.timestamp_source};vlan_reconstructed={f.vlan_reconstructed}")
                    for f in captured_objects])
            else:
                written = write_pcap(target_path, collected)
        except PcapError as error:
            return _error(str(error))
        result["capture_file"] = str(written)
        result["capture_frames_written"] = len(collected)
    return result


@mcp.tool()
def decode_packet(
    frame_hex: str,
    decode: str = "full",
) -> dict[str, Any]:
    """Decode an Ethernet frame supplied as hex into its fields.

    Use this to interpret a frame captured elsewhere, or to double-check what a
    builder produced. Nothing is transmitted.

    Args:
        frame_hex: complete Ethernet frame, compact or space separated.
        decode: 'summary' for a compact identification line, 'full' for the
            complete decoded tree.

    Returns:
        Length, addressing, VLAN tag stack, EtherType and, for recognised
        protocols, the decoded fields such as ARP, IPv4/IPv6, TCP, UDP, ICMP,
        DHCP, DNS and LLDP.
    """
    from .packets import parse_ethernet_frame

    invalid = _validate_decode_mode(decode)
    if invalid:
        return _error(invalid)

    try:
        frame = parse_ethernet_frame(frame_hex)
    except PacketError as error:
        return _error(str(error))

    if decode == "summary":
        return {"ok": True, "summary": summarize_frame(frame)}
    return {
        "ok": True,
        "dump": hex_dump(frame),
        "decoded": decode_link_frame(frame),
    }


@mcp.tool()
def describe_decode_support() -> dict[str, Any]:
    """Describe which protocols the decoder recognises and at what depth.

    The decoder is deliberately shallow: it extracts the fields needed to
    identify a frame, not every field on the wire. Any frame can still be read
    from its raw hex, so an unrecognised protocol is never a dead end.
    """
    return {
        "ok": True,
        "decode_modes": list(DECODE_MODES),
        "capture_file_analysis": {
            "selection": "prefer tshark on PATH; fall back to Scapy with an explicit reason",
            "scope": "offline read_capture_file and summarise_capture_file only",
            "limits": {"packets": 200, "input_bytes": 4194304,
                       "output_bytes": 8388608, "timeout_seconds": 10},
            "filters": "existing MCP filters retain their Scapy/normalized semantics",
        },
        "scapy_dissection": {
            "backend": "scapy",
            "full_output": "scapy.layers contains parsed layer names and JSON-safe fields",
            "summary_output": "layer_names lists detected Scapy layers",
            "limits": {"layers": 16, "fields_per_object": 64, "items_per_list": 16,
                       "value_depth": 4, "text_characters": 256, "byte_preview_max": 256},
            "link_types": "capture files use Scapy link-type bindings; unknown types are not guessed",
        },
        "decoded_protocols": {
            "ethernet": ["source_mac", "destination_mac", "vlan_tags", "ether_type"],
            "arp": ["operation", "sender/target mac and ip"],
            "ipv4": ["addresses", "ttl", "protocol", "fragmentation"],
            "ipv6": ["addresses", "hop limit", "next header (incl. extensions)"],
            "tcp": ["ports", "flags", "sequence", "acknowledgement", "window"],
            "udp": ["ports", "length"],
            "icmp": ["type", "code", "id", "sequence"],
            "icmpv6": ["type", "code", "id", "sequence", "nd target"],
            "dhcp": ["message type", "transaction id", "client mac", "your ip", "server id", "lease", "subnet", "routers", "hostname", "requested ip"],
            "dns": ["transaction id", "flags", "question name/type", "first answer"],
            "lldp": ["chassis id", "port id", "ttl", "system name", "system description", "capabilities"],
        },
        "notes": [
            "Fields are omitted rather than guessed when a frame is malformed or truncated.",
            "Raw hex is available in none/full modes; summary mode omits it.",
            "Existing normalized Ethernet fields remain for filter compatibility; Scapy dissection is additional.",
            "Scapy dissection does not certify checksum validity or protocol conformance, and does not perform stream reassembly here.",
        ],
    }


@mcp.tool()
def describe_filters() -> dict[str, Any]:
    """Describe the filter expression language used by the capture tools.

    Filters match on decoded frame fields and are combined with 'and', 'or' and
    'not'. A missing field never matches, so a filter cannot be satisfied by a
    frame that merely lacks the field it mentions.
    """
    return {
        "ok": True,
        "syntax": "field operator value, combined with 'and', 'or', 'not', and parentheses",
        "operators": {
            "==": "equal (numeric when both sides are numbers)",
            "!=": "not equal",
            ">": "greater than (numeric or lexicographic)",
            "<": "less than (numeric or lexicographic)",
            ">=": "greater than or equal",
            "<=": "less than or equal",
            "~": "case-insensitive substring",
            "in": "membership in a list, e.g. protocol in (dhcp, dns)",
        },
        "example_fields": [
            "protocol",
            "ether_type",
            "vlan_ids",
            "scapy.protocol",
            "scapy.layer_names",
            "source_mac",
            "destination_mac",
            "ipv4.source_ip",
            "ipv4.destination_ip",
            "ipv4.ttl",
            "ipv4.tcp.destination_port",
            "ipv4.tcp.flags.flag_string",
            "ipv4.udp.source_port",
            "ipv4.icmp.type_name",
            "ipv6.destination_ip",
            "ipv6.icmpv6.type_name",
            "ipv4.dhcp.message_type_name",
            "ipv4.dhcp.server_identifier",
            "ipv4.dns.question.name",
            "arp.operation_name",
            "arp.sender_ip",
            "lldp.system_name",
        ],
        "examples": [
            "protocol == dhcp",
            "protocol == arp and arp.operation_name == reply",
            "ipv4.tcp.destination_port == 443",
            "ipv4.source_ip ~ '192.168.'",
            "protocol in (dhcp, dns) and vlan_ids == 300",
            "not protocol == arp",
        ],
        "notes": [
            "List-valued fields match when any member satisfies the comparison.",
            "Values may be quoted or bare; numbers compare numerically.",
        ],
    }


@mcp.tool()
def list_capture_files() -> dict[str, Any]:
    """List capture files already written to the capture directory.

    Returns:
        The capture directory and its files, newest first.
    """
    try:
        return {'ok': True, 'capture_dir': str(capture_dir()),
                'files': list_captures()}
    except PcapError as error:
        return _error(str(error))


@mcp.tool()
def read_capture_file(
    filename: str,
    max_records: int = 200,
    filter_expression: str | None = None,
    decode: str = "summary",
    summarise: bool = True,
    start_index: int = 0,
) -> dict[str, Any]:
    """Read a capture file and return its frames, optionally filtered.

    Use this to inspect a capture recorded earlier, in the same way a live
    capture is inspected.

    Args:
        filename: capture filename inside the capture directory, e.g. 'run1.pcap'.
        max_records: read at most this many frames from the file.
        filter_expression: keep only frames matching this filter expression.
            See describe_filters for the language.
        decode: decode verbosity, one of 'none', 'summary' or 'full'.
        summarise: include a protocol/host overview of the captured frames.

    Returns:
        File metadata, the matching frames, and an optional overview.
    """
    invalid = _validate_decode_mode(decode)
    if invalid:
        return _error(invalid)

    try:
        if max_records < 1:
            return _error("max_records must be at least 1")
        path = resolve_capture_path(filename)
        try:
            predicate = compile_filter(filter_expression)
        except FilterError as error:
            return _error(f"invalid filter_expression: {error}")
        if max_records > 200:
            return _error("max_records may not exceed 200; use start_index for pagination")
        parsed = read_pcap(path, max_records=max_records, start_index=start_index)
    except (PcapError, FilterError) as error:
        return _error(str(error))

    from .pcap_analysis import analyze_records

    analysis = (analyze_records(parsed.records, link_type=parsed.link_type)
                if decode != "none" else {"backend": "none", "packets": []})
    tshark_packets = {id(record): packet for record, packet in
                     zip(parsed.records, analysis["packets"])}
    records = parsed.records
    if predicate is not None:
        records = [
            record
            for record in records
            if predicate(decode_link_frame(record.data, payload_limit=0, link_type=record.link_type))
        ]

    frames = []
    for record in records:
        entry = record.to_dict(include_hex=(decode != "summary"))
        if decode == "summary":
            entry.update(summarize_frame(record.data, link_type=record.link_type))
        elif decode == "full":
            entry.update(decode_link_frame(record.data, payload_limit=256, link_type=record.link_type))
        packet_analysis = tshark_packets.get(id(record))
        if packet_analysis is not None:
            entry["tshark"] = (packet_analysis if decode == "full" else
                               {"protocols": packet_analysis["protocols"]})
        frames.append(entry)

    result = parsed.to_dict(include_records=False)
    result["analysis_backend"] = analysis["backend"]
    if analysis.get("reason"):
        result["analysis_fallback_reason"] = analysis["reason"]
    result["ok"] = True
    result["returned_records"] = len(frames)
    result["frames"] = frames
    if summarise:
        result["overview"] = summarise_frames(
            [(record.data, record.timestamp if record.timestamp_available else None, record.link_type)
             for record in records]
        )
    return result


@mcp.tool()
def replay_capture_file(
    filename: str,
    interface: str,
    max_frames: int = 100,
    rate_pps: float = 10.0,
    start_index: int = 0,
    filter_expression: str | None = None,
    capture_replies: bool = False,
    timeout: float = 1.0,
) -> dict[str, Any]:
    """Transmit the frames from a capture file on an interface.

    This re-sends recorded traffic, which is useful for reproducing a known
    sequence. It is rate limited and capped on purpose: replaying a capture is
    never allowed to flood a link.

    Args:
        filename: capture filename inside the capture directory.
        interface: interface to transmit on, such as 'eth1'.
        max_frames: hard cap on how many frames may be transmitted.
        rate_pps: frames per second, must be greater than zero.
        start_index: skip this many matching frames before transmitting.
        filter_expression: replay only frames matching this filter expression.
        capture_replies: listen for replies after the last frame is sent.
        timeout: seconds to listen when ``capture_replies`` is true.

    Returns:
        How many frames were transmitted and, optionally, what came back.
    """
    try:
        resolve_interface(interface)
        if max_frames < 1:
            return _error("max_frames must be at least 1")
        if max_frames > MAX_REPLAY_FRAMES:
            return _error(f"max_frames may not exceed {MAX_REPLAY_FRAMES}")
        if rate_pps <= 0:
            return _error("rate_pps must be greater than zero")
        if start_index < 0:
            return _error("start_index cannot be negative")
        if timeout < 0:
            return _error("timeout cannot be negative")
        path = resolve_capture_path(filename)
        try:
            predicate = compile_filter(filter_expression)
        except FilterError as error:
            return _error(f"invalid filter_expression: {error}")
        parsed = read_pcap(path, max_records=None)
        if parsed.link_type != 1:
            return _error("raw Ethernet replay requires an Ethernet capture (link type 1)")
    except (CaptureError, PcapError) as error:
        return _error(str(error))

    selected = [
        record
        for record in parsed.records
        if predicate is None or predicate(decode_link_frame(record.data, payload_limit=0, link_type=record.link_type))
    ]
    selected = selected[start_index : start_index + max_frames]
    if not selected:
        return {
            "ok": True,
            "interface": interface,
            "frames_sent": 0,
            "note": "no frames matched the selection",
        }

    interval = 1.0 / rate_pps
    try:
        result = exchange(
            interface,
            [record.data for record in selected],
            timeout=timeout if capture_replies else 0.0,
            count=1,
            interval=interval,
            capture_own=False,
            promiscuous=capture_replies,
        )
    except CaptureError as error:
        return _error(str(error))

    out: dict[str, Any] = {
        "ok": True,
        "interface": interface,
        "capture_file": str(path),
        "frames_sent": len(result.transmissions),
        "capture_quality": result.quality,
        "rate_pps": rate_pps,
        "start_index": start_index,
    }
    if capture_replies:
        out["reply_count"] = len(result.replies())
        out["replies"] = [frame.to_dict(decode="summary") for frame in result.replies()]
    return out


@mcp.tool()
def summarise_capture_file(
    filename: str,
    filter_expression: str | None = None,
    top_n: int = 10,
) -> dict[str, Any]:
    """Summarise a capture file without returning the individual frames.

    This is the cheapest way to understand a capture: it reports which
    protocols, hosts, conversations and VLANs are present, so a caller can then
    ask for the few frames that matter.

    Args:
        filename: capture filename inside the capture directory.
        filter_expression: summarise only frames matching this filter expression.
        top_n: how many entries to keep in each ranked list.

    Returns:
        Protocol, host, conversation, VLAN and address observations.
    """
    try:
        if top_n < 1:
            return _error("top_n must be at least 1")
        path = resolve_capture_path(filename)
        predicate = compile_filter(filter_expression)
        parsed = read_pcap(path, max_records=None)
    except (PcapError, FilterError) as error:
        return _error(str(error))

    records = [
        record
        for record in parsed.records
        if predicate is None or predicate(decode_link_frame(record.data, payload_limit=0, link_type=record.link_type))
    ]
    overview = summarise_frames(
        [(record.data, record.timestamp if record.timestamp_available else None, record.link_type)
         for record in records], top_n=top_n
    )
    from collections import Counter
    from .pcap_analysis import analyze_records

    analysis = analyze_records(parsed.records, link_type=parsed.link_type)
    overview["scan_truncated"] = parsed.scan_truncated
    overview["next_index"] = parsed.next_index
    overview["analysis_backend"] = analysis["backend"]
    if analysis.get("reason"):
        overview["analysis_fallback_reason"] = analysis["reason"]
    if analysis["backend"] == "tshark":
        packet_map = {id(record): packet for record, packet in
                      zip(parsed.records, analysis["packets"])}
        overview["tshark_protocol_stacks"] = dict(Counter(
            packet_map[id(record)]["protocols"] for record in records
        ).most_common(top_n))
    overview["ok"] = True
    overview["capture_file"] = str(path)
    return overview


def _report_startup_privileges() -> None:
    """Warn on stderr when raw sockets are unavailable.

    A stdio MCP server must not write to stdout, which is the protocol channel,
    so the notice goes to stderr. The server deliberately keeps running without
    the capability: building frames, decoding, filtering and capture file
    handling all work unprivileged, and only sending or capturing fails. Failing
    loudly here means the cause is obvious instead of surfacing later as a
    confusing error on the first send.

    The remedy is printed as a complete, absolute command so it can be pasted
    into a shell from any working directory.
    """
    permitted, reason = check_raw_socket_permission()
    if permitted:
        return
    print(
        "pktgen-mcp: raw packet sockets are unavailable "
        f"({reason}).\n"
        "pktgen-mcp: sending and live capture will fail. Available without "
        "privileges: build_packet, decode_packet, read_capture_file, "
        "summarise_capture_file, list_capture_files, describe_*.\n"
        "pktgen-mcp: grant CAP_NET_RAW with:\n"
        f"pktgen-mcp:     {privilege_fix_command()}\n"
        "pktgen-mcp: then restart this MCP server. This is a one-time step per "
        "machine, and is needed again only if the virtual environment is "
        "rebuilt or the system Python is upgraded.",
        file=sys.stderr,
    )


@mcp.tool()
def describe_capabilities() -> dict[str, Any]:
    """Discover backends, formats, limits and analysis semantics before testing."""
    import shutil
    from .pcap import MAX_READ_RECORDS, MAX_READ_BYTES, MAX_FILE_BYTES, MAX_SCAN_PACKETS
    return {
        "ok": True, "live_backend": "Linux AF_PACKET", "offline_backend": "Scapy",
        "tshark_available": shutil.which("tshark") is not None,
        "read_formats": ["pcap", "pcapng"], "write_format": "pcap or pcapng",
        "structured_layers": {
            "ethernet": ["src", "dst", "type"],
            "vlan": ["vlan", "prio", "id", "type"],
            "qinq": ["vlan", "prio", "id", "type"],
            "arp": ["op", "hwsrc", "hwdst", "psrc", "pdst"],
            "ipv4": ["src", "dst", "ttl", "id", "flags", "frag", "tos", "chksum", "len"],
            "ipv6": ["src", "dst", "hlim", "tc", "fl"],
            "udp": ["sport", "dport", "chksum", "len"],
            "tcp": ["sport", "dport", "seq", "ack", "flags", "window", "options", "chksum"],
            "icmp": ["type", "code", "id", "seq", "chksum"],
            "dns": ["id", "qr", "rd", "rcode", "qname", "qtype"],
            "bootp": ["op", "xid", "flags", "ciaddr", "yiaddr", "siaddr", "giaddr", "chaddr"],
            "dhcp": ["message_type", "requested_addr", "server_id", "lease_time", "hostname"],
            "icmpv6_echo": ["id", "seq", "cksum"],
            "icmpv6_echo_reply": ["id", "seq", "cksum"],
            "nd_solicitation": ["tgt", "cksum"],
            "nd_advertisement": ["tgt", "R", "S", "O", "cksum"],
            "nd_source_lladdr": ["lladdr"],
            "nd_destination_lladdr": ["lladdr"],
        },
        "structured_requirements": "Ethernet src/dst and IP src/dst must be explicit; numeric IP addresses only",
        "vlan_fields": "prio is PCP, id is DEI, vlan is VID",
        "timestamp_semantics": "pcapng records carry ticks-per-second resolution and nullable captured_at",
        "capture_input_limit_bytes": MAX_FILE_BYTES,
        "capture_quality": "kernel software timestamps where available, socket packet/drop counters, stop reason",
        "test_limits": "100 steps, 32 assertions, 90 seconds, 5000 captured frames/32 MiB",
        "tcp_options": "list of {name,value}: MSS, WScale, Timestamp (two uint32), SAckOK, NOP, EOL",
        "negative_tests": "explicit chksum/cksum and IP/UDP len overrides are allowed",
        "stream_semantics": "bounded sequence ranges, gaps and conflicting overlaps; not full TCP reassembly/decryption",
        "limits": {"page_packets": 200, "scan_packets": MAX_SCAN_PACKETS,
                   "scan_bytes": MAX_READ_BYTES, "tshark_prefix_packets": 200,
                   "tshark_input_bytes": 4 * 1024 * 1024, "tshark_seconds": 10},
        "filter_semantics": {"filter_expression": "normalized/Scapy expression language",
                             "display_filter": "Wireshark; requires tshark"},
        "limitations": ["kernel timestamps are software receive times, not wire/hardware timestamps; userspace fallback",
                        "spoofed-MAC reply reception depends on NIC/driver and is not verified",
                        "queries and summaries report bounded-prefix scope, not full-capture conclusions",
                        "mixed-link pcapng decoded per packet; replay rejects mixed links",
                        "pcapng output regenerates interface IDs and uses microsecond timestamps; unknown timestamps are not invented",
                        "no follow-stream or full-capture reassembly API"],
    }


@mcp.tool()
def inspect_capture_page(filename: str, start_index: int = 0, page_size: int = 50,
                         fields: list[str] | None = None,
                         filter_expression: str | None = None) -> dict[str, Any]:
    """Inspect a bounded page with zero-based physical indexes and selected dotted fields.

    Pagination precedes filtering: an empty page can still have next_index.
    Example fields: source_mac, ipv4.source_ip, arp.operation, scapy.layer_names, hex.
    Missing fields are null. Raw bytes remain available via hex or read_capture_file.
    """
    if fields is not None and (not fields or len(fields) > 16 or
                               any(len(f) > 128 for f in fields)):
        return _error("fields must contain 1 to 16 paths, each at most 128 characters")
    result = read_capture_file(filename, max_records=page_size, start_index=start_index,
                               filter_expression=filter_expression, decode="full", summarise=False)
    if result.get("ok") and fields is not None:
        selected = []
        for frame in result["frames"]:
            row = {"packet_index": frame["packet_index"]}
            for field in fields:
                value = frame
                for part in field.split("."):
                    value = value.get(part) if isinstance(value, dict) else None
                row[field] = value
            selected.append(row)
        result["frames"] = selected
    result["scope"] = "page indexes are physical packet positions before filtering"
    return result


@mcp.tool()
def build_protocol_packet(layers: list[dict[str, Any]], payload_hex: str = "",
                          pad: bool = True) -> dict[str, Any]:
    """Construct Ethernet plus allowlisted protocol layers; compute lengths/checksums.

    Example layers: [{"protocol":"ethernet","fields":{"src":"02:00:00:00:00:01",
    "dst":"02:00:00:00:00:02"}}, {"protocol":"ipv4","fields":{"src":"192.0.2.1",
    "dst":"192.0.2.2"}}, {"protocol":"udp","fields":{"sport":1234,"dport":53}}].
    Nothing is sent. Use returned hex with the raw sending builder.
    """
    from .workflows import protocol_frame
    return protocol_frame(layers, payload_hex, pad)


@mcp.tool()
def query_capture(filename: str, fields: list[str], display_filter: str | None = None,
                  max_packets: int = 200, start_index: int = 0) -> dict[str, Any]:
    """Query a bounded capture range using Wireshark display filters/selected fields.

    tshark required. Example fields: frame.number, ip.src, tcp.analysis.retransmission.
    Unlike filter_expression, this uses Wireshark syntax. No shell commands allowed.
    """
    from .workflows import tshark_query
    return tshark_query(filename, display_filter, fields, max_packets, start_index)


@mcp.tool()
def diagnose_capture(filename: str, diagnostic: str, max_packets: int = 200,
                     start_index: int = 0) -> dict[str, Any]:
    """Retrieve indexed evidence for tcp_retransmissions, dns_failures,
    arp_requests, unanswered_arp or dhcp_exchanges. ARP requests are not proof of unanswered ARP;
    absence/retransmission findings are bounded observations, not DUT verdicts.
    """
    from .workflows import DIAGNOSTICS, tshark_query, unanswered_arp
    if diagnostic == "unanswered_arp":
        return unanswered_arp(filename, max_packets, start_index)
    if diagnostic not in DIAGNOSTICS:
        return _error("diagnostic must be one of: unanswered_arp, " + ", ".join(DIAGNOSTICS))
    result = tshark_query(filename, DIAGNOSTICS[diagnostic],
                          ["frame.number", "frame.time_epoch", "_ws.col.Protocol", "_ws.col.Info"],
                          max_packets, start_index)
    result["diagnostic"] = diagnostic
    result["interpretation"] = "matching evidence in scanned prefix; not a conformance verdict"
    return result


@mcp.tool()
def analyse_capture(filename: str, max_packets: int = 100000,
                    top_n: int = 20) -> dict[str, Any]:
    """Stream a capture for protocol counts and conversation evidence without retaining frames.

    Limits: 1 GiB file, 15 seconds, up to 1,000,000 packets and 2048 tracked flows.
    Results explicitly report scope/truncation. Use conversation_id with inspect_stream.
    """
    from .investigation import scan_capture
    return scan_capture(filename, max_packets, top_n)


@mcp.tool()
def inspect_stream(filename: str, conversation_id: str, max_packets: int = 200,
                   max_payload_bytes: int = 16384) -> dict[str, Any]:
    """Inspect a TCP/UDP conversation timeline and bounded payload evidence.

    TCP sequence ranges preserve gaps and flag conflicting overlaps; first-seen
    bytes win. This is not full TCP reassembly/decryption. UDP returns datagrams.
    Obtain conversation_id from analyse_capture. IDs group endpoint pairs/VLAN/interface.
    """
    from .investigation import inspect_stream as inspect
    return inspect(filename, conversation_id, max_packets, max_payload_bytes)


@mcp.tool()
def run_packet_test(interface: str, steps: list[dict[str, Any]],
                    assertions: list[dict[str, Any]], timeout: float = 2.0,
                    save_as: str | None = None, max_frames: int = 500) -> dict[str, Any]:
    """Run a bounded declarative send/capture/assert sequence and optionally save evidence.

    Steps: frame_hex OR layers, optional payload_hex and delay_before (0..5s).
    Assertions: filter, count_at_least/count_at_most, optional after_send_index and
    within_seconds. Indexes are zero-based. Only incoming frames satisfy assertions.
    Limits: 100 steps, 32 assertions, 90 seconds, 5000 captured frames/32 MiB.
    Report verdict is passed/failed/inconclusive, distinct from tool execution ok.
    Saves .pcap/.pcapng and a .report.json sidecar. No code expressions accepted.
    """
    from .testing import run_test
    return run_test(interface, steps, assertions, timeout, save_as, max_frames)


def main() -> None:
    _report_startup_privileges()
    mcp.run()


if __name__ == "__main__":
    main()
