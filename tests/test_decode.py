"""Tests for the protocol decoder.

The decoder must never raise on hostile input: a frame that cannot be
interpreted is returned with its raw hex so analysis can continue.
"""

from __future__ import annotations

import os
import struct

import pytest

from pktgen_mcp.decode import (
    decode_arp,
    decode_dhcp,
    decode_dns,
    decode_icmp,
    decode_ipv4,
    decode_ipv6,
    decode_link_frame,
    decode_lldp,
    decode_tcp,
    decode_udp,
    summarize_frame,
)
from pktgen_mcp.packets import build_ethernet_frame, hex_bytes

ARP_REQUEST = (
    "00 01 08 00 06 04 00 01 02 11 22 33 44 55 "
    "c0 a8 01 0a 00 00 00 00 00 00 c0 a8 01 01"
)


def _eth(payload_hex: str, ether_type: str, **kwargs) -> bytes:
    return build_ethernet_frame(ether_type=ether_type, payload_hex=payload_hex, **kwargs)


def _ipv4(protocol: int, source: str, destination: str, body: bytes, **fields) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(body),
        fields.get("identification", 0),
        fields.get("flags_fragment", 0),
        fields.get("ttl", 64),
        protocol,
        0,
        bytes(int(part) for part in source.split(".")),
        bytes(int(part) for part in destination.split(".")),
    )
    return header + body


def _udp(source_port: int, destination_port: int, body: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(body), 0) + body


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #


def test_tcp_flags_and_ports():
    segment = struct.pack("!HHIIBBHHH", 12345, 443, 1000, 0, 0x50, 0x02, 8192, 0, 0)
    decoded = decode_tcp(segment)
    assert decoded["source_port"] == 12345
    assert decoded["destination_port"] == 443
    assert decoded["flags"]["flag_string"] == "syn"
    assert decoded["sequence"] == 1000


def test_tcp_multiple_flags_are_all_reported():
    segment = struct.pack("!HHIIBBHHH", 1, 2, 0, 0, 0x50, 0x12, 0, 0, 0)  # SYN+ACK
    decoded = decode_tcp(segment)
    assert set(decoded["flags"]["names"]) == {"syn", "ack"}


def test_tcp_payload_is_reported_separately():
    segment = struct.pack("!HHIIBBHHH", 1, 2, 0, 0, 0x50, 0x10, 0, 0, 0) + b"hello"
    decoded = decode_tcp(segment)
    assert decoded["payload_length"] == 5
    assert decoded["payload_hex"].startswith("68 65 6c 6c 6f")


def test_udp_header():
    decoded = decode_udp(struct.pack("!HHHH", 5353, 53, 12, 0) + b"abcd")
    assert decoded["source_port"] == 5353
    assert decoded["destination_port"] == 53
    assert decoded["payload_length"] == 4


def test_udp_and_tcp_reject_short_input():
    assert decode_udp(b"\x00" * 4) is None
    assert decode_tcp(b"\x00" * 10) is None


def test_icmp_echo_request():
    decoded = decode_icmp(struct.pack("!BBHHH", 8, 0, 0, 0xABCD, 7))
    assert decoded["type_name"] == "echo-request"
    assert decoded["id"] == 0xABCD
    assert decoded["sequence"] == 7


def test_icmpv6_neighbor_solicitation_includes_target():
    payload = struct.pack("!BBH", 135, 0, 0) + b"\x00" * 4 + bytes.fromhex(
        "20010db8000000000000000000000001"
    )
    decoded = decode_icmp(payload, version=6)
    assert decoded["type_name"] == "neighbor-solicitation"
    assert decoded["target_address"] == "2001:db8::1"


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #


def test_ipv4_and_icmp_together():
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 3)
    decoded = decode_ipv4(_ipv4(1, "10.0.0.1", "10.0.0.2", body))
    assert decoded["source_ip"] == "10.0.0.1"
    assert decoded["destination_ip"] == "10.0.0.2"
    assert decoded["protocol_name"] == "icmp"
    assert decoded["icmp"]["id"] == 0x1234


def test_ipv4_fragmentation_is_reported():
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    decoded = decode_ipv4(
        _ipv4(1, "10.0.0.1", "10.0.0.2", body, flags_fragment=0x2000)
    )
    assert decoded["fragmented"] is True
    assert decoded["more_fragments"] is True


def test_ipv4_rejects_a_non_ipv4_version():
    assert decode_ipv4(struct.pack("!BBHHHBBH4s4s", 0x65, 0, 20, 0, 0, 64, 6, 0, b"\x00" * 4, b"\x00" * 4)) is None


def test_ipv6_compresses_adjacent_zero_groups():
    header = struct.pack("!IHBB", 0x60000000, 8, 58, 64) + bytes.fromhex(
        "20010db8000000000000000000000001"
    ) + bytes.fromhex("20010db8000000000000000000000002")
    decoded = decode_ipv6(header + struct.pack("!BBHHH", 128, 0, 0, 1, 1))
    assert decoded["source_ip"] == "2001:db8::1"
    assert decoded["destination_ip"] == "2001:db8::2"
    assert decoded["icmpv6"]["type_name"] == "echo-request"


def test_ipv6_walks_extension_headers_to_find_udp():
    udp = _udp(1, 2, b"x")
    # A hop-by-hop header (next=17) precedes the UDP datagram.
    extension = bytes([17, 0]) + b"\x00" * 6
    header = struct.pack("!IHBB", 0x60000000, len(extension) + len(udp), 0, 64) + (
        bytes.fromhex("20010db8000000000000000000000001")
        + bytes.fromhex("20010db8000000000000000000000002")
    )
    decoded = decode_ipv6(header + extension + udp)
    assert decoded["effective_next_header"] == 17
    assert decoded["udp"]["destination_port"] == 2


def test_arp_reply_decoded_from_an_ethernet_frame():
    decoded = decode_link_frame(_eth(ARP_REQUEST, "0806"))
    assert decoded["protocol"] == "arp"
    assert decoded["arp"]["operation_name"] == "request"
    assert decoded["arp"]["sender_ip"] == "192.168.1.10"
    assert decoded["arp"]["target_ip"] == "192.168.1.1"


def test_arp_with_an_unusual_hardware_length_is_not_decoded():
    # A non-Ethernet/IPv4 ARP is not interpreted rather than being guessed at.
    payload = struct.pack("!HHBBH", 1, 0x0800, 3, 3, 1) + b"\x00" * 12
    assert decode_arp(payload) is None


def test_arp_short_frame_is_not_decoded():
    assert decode_arp(b"\x00" * 4) is None


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #


def _dhcp_message(message_type: int, options: bytes = b"", operation: int = 1) -> bytes:
    bootp = bytearray(240)
    bootp[0], bootp[1], bootp[2] = operation, 2, 6
    bootp[4:8] = b"\xde\xad\xbe\xef"
    bootp[16:20] = bytes([192, 168, 1, 50])
    bootp[20:24] = bytes([192, 168, 1, 1])
    bootp[28:34] = bytes.fromhex("020000000001")
    bootp[236:240] = b"\x63\x82\x53\x63"
    return bytes(bootp) + bytes([53, 1, message_type]) + options + bytes([255])


def test_dhcp_offer_options():
    options = bytes([54, 4, 192, 168, 1, 1]) + bytes([51, 4, 0, 0, 0x0E, 0x10])
    decoded = decode_dhcp(_dhcp_message(2, options, operation=2))
    assert decoded["operation_name"] == "reply"
    assert decoded["message_type_name"] == "offer"
    assert decoded["your_ip"] == "192.168.1.50"
    assert decoded["server_identifier"] == "192.168.1.1"
    assert decoded["lease_time"] == 3600


def test_dhcp_discover_requested_ip_and_parameter_list():
    options = bytes([50, 4, 192, 168, 1, 77]) + bytes([55, 3, 1, 3, 6])
    decoded = decode_dhcp(_dhcp_message(1, options))
    assert decoded["message_type_name"] == "discover"
    assert decoded["requested_ip"] == "192.168.1.77"
    assert decoded["parameter_request_list"] == [1, 3, 6]


def test_dhcp_rejects_a_bad_magic_cookie():
    payload = bytearray(_dhcp_message(1))
    payload[236:240] = b"\x00\x00\x00\x00"
    assert decode_dhcp(bytes(payload)) is None


def test_dns_query_name_and_type():
    body = (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + b"\x03www\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )
    decoded = decode_dns(body)
    assert decoded["is_response"] is False
    assert decoded["question"]["name"] == "www.example.com"
    assert decoded["question"]["type_name"] == "A"


def test_dns_answer_follows_a_compression_pointer():
    body = (
        struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
        # answer name is a pointer back to offset 12
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + bytes([93, 184, 216, 34])
    )
    decoded = decode_dns(body)
    assert decoded["first_answer"]["name"] == "example.com"
    assert decoded["first_answer"]["address"] == "93.184.216.34"
    assert decoded["first_answer"]["ttl"] == 300


def test_dns_pointer_loop_terminates():
    body = (
        struct.pack("!HHHHHH", 1, 0x8180, 0, 1, 0, 0)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 0, 4)
        + b"\x00\x00\x00\x00"
    )
    decoded = decode_dns(body)
    assert decoded is not None


def test_dhcp_and_dns_are_attached_from_their_transport_ports():
    dhcp = _dhcp_message(1)
    frame = _eth(
        hex_bytes(_ipv4(17, "0.0.0.0", "255.255.255.255", _udp(68, 67, dhcp))), "0800"
    )
    assert "dhcp" in decode_link_frame(frame)["ipv4"]

    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x01a\x00" + struct.pack("!HH", 1, 1)
    frame = _eth(hex_bytes(_ipv4(17, "10.0.0.1", "10.0.0.2", _udp(40000, 53, dns))), "0800")
    assert "dns" in decode_link_frame(frame)["ipv4"]


def test_lldp_tlvs():
    def tlv(kind: int, value: bytes) -> bytes:
        return struct.pack("!H", (kind << 9) | len(value)) + value

    payload = (
        tlv(1, b"\x04" + bytes.fromhex("001122334455"))
        + tlv(2, b"\x05eth0")
        + tlv(3, struct.pack("!H", 120))
        + tlv(5, b"switch-1")
        + tlv(0, b"")
    )
    decoded = decode_lldp(payload)
    assert decoded["chassis_id"] == "00:11:22:33:44:55"
    assert decoded["port_id"] == "eth0"
    assert decoded["system_name"] == "switch-1"
    assert decoded["ttl"] == 120


def test_lldp_truncated_tlv_stops_cleanly():
    decoded = decode_lldp(b"\x0a\x05ab")  # claims 5 bytes, only 2 present
    assert isinstance(decoded, dict)


# --------------------------------------------------------------------------- #
# Frame-level behaviour
# --------------------------------------------------------------------------- #


def test_summary_is_compact_and_identifies_the_protocol():
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    summary = summarize_frame(_eth(hex_bytes(_ipv4(1, "10.0.0.1", "10.0.0.2", body)), "0800"))
    assert summary["protocol"] == "icmp"
    assert summary["source_ip"] == "10.0.0.1"
    assert summary["icmp_type"] == "echo-request"
    assert "hex" not in summary


def test_summary_reports_tcp_ports_and_flags():
    tcp = struct.pack("!HHIIBBHHH", 5000, 8080, 1, 0, 0x50, 0x02, 0, 0, 0)
    summary = summarize_frame(_eth(hex_bytes(_ipv4(6, "1.1.1.1", "2.2.2.2", tcp)), "0800"))
    assert summary["protocol"] == "tcp"
    assert summary["destination_port"] == 8080
    assert summary["tcp_flags"] == "syn"


def test_vlan_tags_are_reported():
    decoded = decode_link_frame(_eth(ARP_REQUEST, "0806", vlan_mode="802.1q", vlan_id=300))
    assert decoded["vlan_ids"] == [300]
    assert decoded["protocol"] == "arp"


def test_raw_hex_is_always_present():
    for frame in (b"\x00" * 8, b"\xff" * 64, _eth(ARP_REQUEST, "0806")):
        assert "hex" in decode_link_frame(frame)


def test_ieee_8023_length_field_is_not_treated_as_an_ethertype():
    frame = bytes.fromhex("0180c2000021") + bytes.fromhex("020000000001") + b"\x00\x2e" + bytes(46)
    decoded = decode_link_frame(frame)
    assert decoded["frame_kind"] == "ieee-802.3-length"


def test_decoder_fuzz_never_raises():
    for size in range(0, 160):
        for seed in range(8):
            blob = os.urandom(size)
            decode_link_frame(blob)
            summarize_frame(blob)


def test_decoder_never_raises_on_any_truncation_of_a_valid_frame():
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 3)
    full = _eth(hex_bytes(_ipv4(1, "10.0.0.1", "10.0.0.2", body)), "0800", vlan_mode="802.1q")
    for cut in range(len(full) + 1):
        decode_link_frame(full[:cut])
        summarize_frame(full[:cut])


def test_decoder_never_raises_on_random_lldp_and_dhcp():
    for size in range(0, 300, 7):
        blob = os.urandom(size)
        decode_lldp(blob)
        decode_dhcp(blob)
        decode_dns(blob)
