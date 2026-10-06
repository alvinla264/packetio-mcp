"""Tests for the packet generator MCP server.

These cover frame construction, decoding and the tool layer. Anything that
touches a live interface is marked ``live`` and skipped unless the process is
running as root with an interface available, so the suite passes unprivileged.

Run everything:

    sudo .venv/bin/python -m pytest tests -v

Run only the offline tests:

    .venv/bin/python -m pytest tests -v -m "not live"
"""

from __future__ import annotations

import os
import struct

import pytest

from packetio_mcp import server
from packetio_mcp.capture import (
    CaptureError,
    RawInterface,
    check_raw_socket_permission,
    exchange,
    list_interfaces,
    require_raw_socket_permission,
)
from packetio_mcp.packets import (
    ETHERNET_MIN_FRAME_LEN,
    PacketError,
    build_ethernet_frame,
    decode_frame,
    hex_bytes,
    parse_ethernet_frame,
    parse_ether_type,
    parse_hex_bytes,
)

ARP_REQUEST = (
    "00 01 08 00 06 04 00 01 02 11 22 33 44 55 "
    "c0 a8 01 0a 00 00 00 00 00 00 c0 a8 01 01"
)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def can_open_raw_socket() -> bool:
    """Whether this process may open a raw packet socket.

    True when running as root, or when the interpreter carries CAP_NET_RAW, as
    installed by setup-capabilities.sh. Live tests are gated on this rather than
    on the user id, so a capability-equipped interpreter runs them too.
    """
    import socket

    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except OSError:
        return False
    probe.close()
    return True


live = pytest.mark.skipif(
    not can_open_raw_socket(),
    reason="needs root or CAP_NET_RAW for a raw packet socket",
)


# --------------------------------------------------------------------------- #
# Frame construction
# --------------------------------------------------------------------------- #


def test_untagged_frame_layout_and_padding():
    frame = build_ethernet_frame(
        destination_mac="ff:ff:ff:ff:ff:ff",
        source_mac="02:00:00:00:00:01",
        ether_type="88b5",
        payload_hex="de ad be ef",
    )
    assert len(frame) == ETHERNET_MIN_FRAME_LEN
    assert frame[0:6] == bytes.fromhex("ffffffffffff")
    assert frame[6:12] == bytes.fromhex("020000000001")
    assert frame[12:14] == bytes.fromhex("88b5")
    assert frame[14:18] == bytes.fromhex("deadbeef")
    assert frame[18:] == bytes(42)


def test_single_tag_encodes_pcp_and_vlan_id():
    frame = build_ethernet_frame(vlan_mode="802.1q", vlan_id=200, pcp=5)
    tpid, tci = struct.unpack("!HH", frame[12:16])
    assert tpid == 0x8100
    assert tci >> 13 == 5
    assert tci & 0x0FFF == 200


def test_qinq_outer_and_inner_tags():
    frame = build_ethernet_frame(
        vlan_mode="qinq", outer_vlan_id=230, outer_pcp=1, vlan_id=200, pcp=5
    )
    outer_tpid, outer_tci, inner_tpid, inner_tci = struct.unpack("!HHHH", frame[12:20])
    assert outer_tpid == 0x88A8
    assert outer_tci & 0x0FFF == 230
    assert inner_tpid == 0x8100
    assert inner_tci & 0x0FFF == 200
    assert inner_tci >> 13 == 5


def test_padding_can_be_disabled():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="de ad", pad=False)
    assert len(frame) == 16


@pytest.mark.parametrize("vlan_id", [-1, 4095])
def test_rejects_out_of_range_vlan(vlan_id):
    with pytest.raises(PacketError):
        build_ethernet_frame(vlan_mode="802.1q", vlan_id=vlan_id)


@pytest.mark.parametrize("pcp", [-1, 8])
def test_rejects_out_of_range_pcp(pcp):
    with pytest.raises(PacketError):
        build_ethernet_frame(vlan_mode="802.1q", pcp=pcp)


def test_rejects_unknown_vlan_mode():
    with pytest.raises(PacketError):
        build_ethernet_frame(vlan_mode="double-tag")


@pytest.mark.parametrize("mac", ["", "nope", "02:00:00:00:00", "gg:00:00:00:00:01"])
def test_rejects_invalid_mac(mac):
    with pytest.raises(PacketError):
        build_ethernet_frame(source_mac=mac)


def test_ether_type_parsing_accepts_hex_forms():
    assert parse_ether_type("0800") == 0x0800
    assert parse_ether_type("0x86dd") == 0x86DD
    assert parse_ether_type(0x0806) == 0x0806
    with pytest.raises(PacketError):
        parse_ether_type("10000")


def test_hex_parsing_accepts_separators():
    assert parse_hex_bytes("de:ad be-ef_01") == bytes.fromhex("deadbeef01")
    with pytest.raises(PacketError):
        parse_hex_bytes("abc")  # odd length
    with pytest.raises(PacketError):
        parse_hex_bytes("zz")


def test_raw_frame_requires_full_header():
    with pytest.raises(PacketError):
        parse_ethernet_frame("ff ff ff")
    assert parse_ethernet_frame("ff" * 14) == b"\xff" * 14


# --------------------------------------------------------------------------- #
# Decoding
# --------------------------------------------------------------------------- #


def test_decode_reports_addressing_and_arp():
    frame = build_ethernet_frame(
        destination_mac="ff:ff:ff:ff:ff:ff",
        source_mac="02:11:22:33:44:55",
        ether_type="0806",
        payload_hex=ARP_REQUEST,
    )
    decoded = decode_frame(frame)
    assert decoded["destination_mac"] == "ff:ff:ff:ff:ff:ff"
    assert decoded["source_mac"] == "02:11:22:33:44:55"
    assert decoded["ether_type"] == "0x0806"
    assert decoded["arp"]["operation"] == 1
    assert decoded["arp"]["sender_ip"] == "192.168.1.10"
    assert decoded["arp"]["target_ip"] == "192.168.1.1"


def test_decode_reports_vlan_stack_outer_first():
    frame = build_ethernet_frame(vlan_mode="qinq", outer_vlan_id=230, vlan_id=200)
    decoded = decode_frame(frame)
    assert [tag["vlan_id"] for tag in decoded["vlan_tags"]] == [230, 200]


def test_decode_reports_icmp_inside_ipv4():
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 1, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 7)
    frame = build_ethernet_frame(ether_type="0800", payload_hex=hex_bytes(ip + icmp))
    decoded = decode_frame(frame)
    assert decoded["ipv4"]["protocol"] == 1
    assert decoded["ipv4"]["source_ip"] == "10.0.0.1"
    assert decoded["icmp"]["type"] == 8
    assert decoded["icmp"]["id"] == 0x1234
    assert decoded["icmp"]["sequence"] == 7


def test_decode_flags_truncated_payload():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="aa" * 300)
    decoded = decode_frame(frame, payload_limit=32)
    assert decoded["payload_truncated"] is True
    assert decoded["payload_length"] == 300


def test_decode_short_frame_is_an_error_not_a_crash():
    assert "error" in decode_frame(b"\x01\x02")


def test_ieee_8023_length_field_is_distinguished_from_ethertype():
    header = bytes.fromhex("0180c2000021") + bytes.fromhex("020000000001") + b"\x00\x2e"
    decoded = decode_frame(header + bytes(46))
    assert decoded["frame_kind"] == "ieee-802.3-length"
    assert decoded["llc_length"] == 46


# --------------------------------------------------------------------------- #
# Tool layer (no network access)
# --------------------------------------------------------------------------- #


def test_list_available_interfaces_returns_local_interfaces():
    result = server.list_available_interfaces()
    assert result["ok"] is True
    assert result["count"] == len(result["interfaces"])
    assert all({"name", "index", "up", "mac"} <= set(entry) for entry in result["interfaces"])


def test_list_available_interfaces_can_hide_down_ones():
    all_ifaces = server.list_available_interfaces(include_down=True)["interfaces"]
    up_ifaces = server.list_available_interfaces(include_down=False)["interfaces"]
    assert len(up_ifaces) <= len(all_ifaces)
    assert all(entry["up"] for entry in up_ifaces)


def test_describe_builders_documents_both_builders():
    builders = server.describe_builders()["builders"]
    assert set(builders) == {"ethernet", "raw"}
    assert "payload_hex" in builders["ethernet"]["arguments"]


def test_build_packet_returns_hex_dump_and_decoded_fields():
    result = server.build_packet(ether_type="88b5", payload_hex="de ad be ef")
    assert result["ok"] is True
    assert result["length"] == ETHERNET_MIN_FRAME_LEN
    assert "de ad be ef" in result["hex"]
    assert result["decoded"]["ether_type"] == "0x88b5"


def test_build_packet_reports_validation_errors_without_raising():
    assert server.build_packet(source_mac="nope")["ok"] is False
    assert server.build_packet(builder="weird")["ok"] is False
    assert server.build_packet(builder="raw", frame_hex="ff")["ok"] is False


def test_send_packet_rejects_unknown_interface():
    result = server.send_packet("definitely-not-real0", ether_type="88b5")
    assert result["ok"] is False
    assert "unknown interface" in result["error"]


def test_send_and_receive_rejects_unknown_interface():
    result = server.send_and_receive("definitely-not-real0", ether_type="88b5")
    assert result["ok"] is False
    assert "unknown interface" in result["error"]


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"count": 0}, "count must be at least 1"),
        ({"interval": -1}, "interval cannot be negative"),
        ({"timeout": -1}, "timeout cannot be negative"),
    ],
)
def test_send_and_receive_validates_numeric_arguments(kwargs, message):
    result = server.send_and_receive("lo", ether_type="88b5", **kwargs)
    assert result["ok"] is False
    assert message in result["error"]


def test_capture_packets_rejects_bad_arguments():
    assert server.capture_packets("definitely-not-real0")["ok"] is False
    assert server.capture_packets("lo", timeout=-1)["ok"] is False
    assert server.capture_packets("lo", max_frames=0)["ok"] is False
    assert server.capture_packets("lo", ether_type_filter="zz")["ok"] is False


def test_capture_packets_rejects_bad_source_mac_filter():
    result = server.capture_packets("lo", source_mac_filter="nope")
    assert result["ok"] is False
    assert "invalid MAC" in result["error"]


def test_send_and_receive_rejects_bad_reply_filters():
    bad_mac = server.send_and_receive("lo", ether_type="88b5", reply_source_mac="nope")
    assert bad_mac["ok"] is False
    assert "invalid MAC" in bad_mac["error"]

    bad_type = server.send_and_receive("lo", ether_type="88b5", reply_ether_type="zz")
    assert bad_type["ok"] is False
    assert "EtherType" in bad_type["error"]


def test_describe_builders_documents_reply_filtering():
    described = server.describe_builders()
    assert "packet_types_reported" in described


def test_decode_packet_tool_round_trips_hex():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="de ad be ef")
    result = server.decode_packet(hex_bytes(frame))
    assert result["ok"] is True
    assert result["decoded"]["payload_hex"].startswith("de ad be ef")
    assert server.decode_packet("ff ff")["ok"] is False


# --------------------------------------------------------------------------- #
# Live interface behaviour (root only)
# --------------------------------------------------------------------------- #


@live
def test_exchange_captures_the_frame_it_sends_on_loopback():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="de ad be ef")
    result = exchange("lo", [frame], timeout=0.5)
    assert len(result.frames) >= 1
    assert any(captured.data[14:18] == bytes.fromhex("deadbeef") for captured in result.frames)


@live
def test_exchange_separates_own_frames_from_replies():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="ca fe")
    result = exchange("lo", [frame], timeout=0.5)
    assert len(result.own_frames()) + len(result.replies()) == len(result.frames)


@live
def test_exchange_can_suppress_own_frames():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="ca fe")
    result = exchange("lo", [frame], timeout=0.5, capture_own=False)
    assert all(not captured.is_outgoing for captured in result.frames)


@live
def test_exchange_repeats_the_send():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="01")
    result = exchange("lo", [frame], timeout=0.5, count=3, interval=0.01)
    assert len(result.frames) >= 3


@live
def test_send_and_receive_tool_round_trips_on_loopback():
    result = server.send_and_receive(
        "lo", ether_type="88b5", payload_hex="de ad be ef", timeout=0.5
    )
    assert result["ok"] is True
    assert result["reply_count"] >= 1
    assert result["request"]["decoded"]["ether_type"] == "0x88b5"


@live
def test_capture_packets_filters_by_ethertype():
    result = server.capture_packets("lo", timeout=0.3, ether_type_filter="88b5")
    assert result["ok"] is True
    assert all(frame["ether_type"] == "0x88b5" for frame in result["frames"])


@live
def test_capture_packets_filters_by_source_mac():
    # Send a frame from a distinctive MAC, then capture only that source.
    server.send_packet(
        "lo", source_mac="02:aa:bb:cc:dd:ee", ether_type="88b5", payload_hex="01"
    )
    result = server.capture_packets(
        "lo", timeout=0.4, source_mac_filter="02:aa:bb:cc:dd:ee", include_own=True
    )
    assert result["ok"] is True
    assert all(frame["source_mac"] == "02:aa:bb:cc:dd:ee" for frame in result["frames"])


@live
def test_exchange_source_mac_filter_excludes_other_senders():
    frame = build_ethernet_frame(
        source_mac="02:aa:bb:cc:dd:ee", ether_type="88b5", payload_hex="01"
    )
    result = exchange(
        "lo", [frame], timeout=0.5, source_mac_filter="02:aa:bb:cc:dd:ee"
    )
    assert all(captured.data[6:12] == bytes.fromhex("02aabbccddee") for captured in result.frames)


@live
def test_send_and_receive_reply_ether_type_filter():
    result = server.send_and_receive(
        "lo", ether_type="88b5", payload_hex="de ad", timeout=0.5, reply_ether_type="88b5"
    )
    assert result["ok"] is True
    assert all(reply["ether_type"] == "0x88b5" for reply in result["replies"])


@live
def test_raw_interface_reports_privileged_errors_clearly():
    with RawInterface("lo") as raw:
        raw.bind()
        raw.send(build_ethernet_frame(ether_type="88b5"))
    # Binding and sending on a real interface must not raise.
    assert True


@live
def test_list_interfaces_includes_loopback():
    names = [entry["name"] for entry in list_interfaces()]
    assert "lo" in names


def _can_open_raw_socket() -> bool:
    """Whether this process may open a raw packet socket.

    True when running as root, or when the interpreter carries CAP_NET_RAW,
    which is the case for the interpreter installed by setup-capabilities.sh.
    """
    import socket

    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except OSError:
        return False
    probe.close()
    return True


def test_unprivileged_raw_socket_error_mentions_privileges():
    """The privilege hint must be actionable when the socket cannot be opened."""
    if _can_open_raw_socket():
        pytest.skip("raw sockets are permitted here; the socket will open")
    with pytest.raises(CaptureError, match="root|CAP_NET_RAW"):
        RawInterface("lo").bind()


def test_permission_check_reports_a_reason_when_denied():
    permitted, reason = check_raw_socket_permission()
    if permitted:
        assert reason == ""
    else:
        assert "CAP_NET_RAW" in reason


def test_permission_check_matches_an_actual_socket_attempt():
    """The check must agree with really trying to open a socket."""
    permitted, _ = check_raw_socket_permission()
    actually_worked = True
    try:
        RawInterface("lo").bind()
    except CaptureError:
        actually_worked = False
    assert permitted is actually_worked


def test_require_permission_raises_only_when_unavailable():
    permitted, _ = check_raw_socket_permission()
    if permitted:
        require_raw_socket_permission()  # must not raise
    else:
        with pytest.raises(CaptureError, match="CAP_NET_RAW"):
            require_raw_socket_permission()


def test_privilege_message_lists_what_still_works_without_privileges():
    """The error must not imply the whole server is unusable."""
    from packetio_mcp.capture import _PRIVILEGE_HELP

    assert "CAP_NET_RAW" in _PRIVILEGE_HELP
    assert "no privileges" in _PRIVILEGE_HELP
    # The remediation command is appended separately, so it must be reachable
    # via the helper rather than hard-coded in the explanation text.
    from packetio_mcp.capture import privilege_fix_command

    assert not privilege_fix_command().startswith('sudo ')


def test_privilege_fix_command_is_absolute_and_copy_pasteable():
    """The remediation must work from any working directory."""
    from packetio_mcp.capture import privilege_fix_command

    command = privilege_fix_command()
    import shlex
    assert shlex.split(command)[0].startswith('/')
    assert not command.startswith('sudo ')
    assert "\n" not in command


def test_privilege_fix_command_prefers_the_setup_script():
    from packetio_mcp.capture import _locate_setup_script, privilege_fix_command

    script = _locate_setup_script()
    if script is None:
        pytest.skip("setup-capabilities.sh is not present in this layout")
    command = privilege_fix_command()
    assert str(script) in command
    assert script.is_file()


def test_privilege_fix_command_never_caps_shared_python(monkeypatch):
    import packetio_mcp.capture as capture

    monkeypatch.setattr(capture, "_locate_setup_script", lambda: None)
    command = capture.privilege_fix_command()
    assert 'dedicated interpreter' in command
    assert 'never setcap shared Python' in command
    assert not command.startswith('sudo ')


def test_privilege_help_mentions_what_still_works():
    from packetio_mcp.capture import _PRIVILEGE_HELP

    assert "CAP_NET_RAW" in _PRIVILEGE_HELP
    assert "no privileges" in _PRIVILEGE_HELP
