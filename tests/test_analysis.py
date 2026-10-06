"""Tests for the capture analysis layer."""

from __future__ import annotations

import struct

import pytest

from packetio_mcp.analysis import (
    count_protocols,
    frame_summaries,
    summarise_frames,
)
from packetio_mcp.packets import build_ethernet_frame, hex_bytes


def _ipv4(protocol: int, source: str, destination: str, body: bytes) -> bytes:
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(body),
            0,
            0,
            64,
            protocol,
            0,
            bytes(int(part) for part in source.split(".")),
            bytes(int(part) for part in destination.split(".")),
        )
        + body
    )


def _udp(source_port: int, destination_port: int, body: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(body), 0) + body


def _dns_query(name: str = "example.com") -> bytes:
    labels = b"".join(
        bytes([len(part)]) + part.encode() for part in name.split(".")
    ) + b"\x00"
    return (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + labels
        + struct.pack("!HH", 1, 1)
    )


def _dhcp(message_type: int, server: str | None = None, offered: str | None = None) -> bytes:
    bootp = bytearray(240)
    bootp[0], bootp[1], bootp[2] = 1, 1, 6
    bootp[28:34] = bytes.fromhex("020000000001")
    if offered:
        bootp[16:20] = bytes(int(part) for part in offered.split("."))
    bootp[236:240] = b"\x63\x82\x53\x63"
    options = bytes([53, 1, message_type])
    if server:
        options += bytes([54, 4]) + bytes(int(part) for part in server.split("."))
    return bytes(bootp) + options + bytes([255])


def _arp(operation: int, sender_ip: str, target_ip: str) -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        operation,
        bytes.fromhex("020000000001"),
        bytes(int(part) for part in sender_ip.split(".")),
        b"\x00" * 6,
        bytes(int(part) for part in target_ip.split(".")),
    )


def _sample_frames() -> list[bytes]:
    return [
        build_ethernet_frame(
            ether_type="0800",
            payload_hex=hex_bytes(_ipv4(17, "10.0.0.5", "8.8.8.8", _udp(5000, 53, _dns_query()))),
        ),
        build_ethernet_frame(
            ether_type="0800",
            payload_hex=hex_bytes(_ipv4(17, "10.0.0.5", "8.8.8.8", _udp(5001, 53, _dns_query("other.test")))),
        ),
        build_ethernet_frame(
            ether_type="0800",
            payload_hex=hex_bytes(
                _ipv4(17, "192.168.1.1", "255.255.255.255", _udp(67, 68, _dhcp(1, server="192.168.1.1")))
            ),
        ),
        build_ethernet_frame(ether_type="0806", payload_hex=hex_bytes(_arp(1, "10.0.0.10", "10.0.0.1"))),
        build_ethernet_frame(ether_type="0806", payload_hex=hex_bytes(_arp(2, "10.0.0.1", "10.0.0.10"))),
        build_ethernet_frame(
            ether_type="0800",
            vlan_mode="802.1q",
            vlan_id=300,
            payload_hex=hex_bytes(
                _ipv4(6, "10.0.0.5", "1.2.3.4", struct.pack("!HHIIBBHHH", 12345, 443, 1, 0, 0x50, 0x02, 8192, 0, 0))
            ),
        ),
    ]


def test_protocol_histogram_counts_each_frame():
    summary = summarise_frames(_sample_frames())
    assert summary["frame_count"] == 6
    assert summary["protocols"] == {"dns": 2, "arp": 2, "dhcp": 1, "tcp": 1}


def test_total_bytes_and_parse_errors():
    frames = _sample_frames() + [b"\x00\x01"]
    summary = summarise_frames(frames)
    assert summary["frame_count"] == 7
    assert summary["unparsed_frames"] == 1
    assert summary["total_bytes"] == sum(len(frame) for frame in frames)


def test_vlans_are_reported_as_strings():
    summary = summarise_frames(_sample_frames())
    assert summary["vlans"] == {"300": 1}


def test_dhcp_servers_and_offers_are_collected():
    frames = [
        build_ethernet_frame(
            ether_type="0800",
            payload_hex=hex_bytes(
                _ipv4(
                    17,
                    "192.168.1.1",
                    "255.255.255.255",
                    _udp(67, 68, _dhcp(2, server="192.168.1.1", offered="192.168.1.50")),
                )
            ),
        )
    ]
    summary = summarise_frames(frames)
    assert summary["dhcp_servers"] == ["192.168.1.1"]
    assert summary["dhcp_offered_addresses"] == ["192.168.1.50"]


def test_dns_questions_are_collected():
    summary = summarise_frames(_sample_frames())
    assert summary["dns_questions"] == {"example.com": 1, "other.test": 1}


def test_arp_requesters_and_responders_are_separated():
    summary = summarise_frames(_sample_frames())
    assert summary["arp_requesters"] == {"10.0.0.10": 1}
    assert summary["arp_responders"] == {"10.0.0.1": 1}


def test_conversations_are_direction_independent():
    frames = [
        build_ethernet_frame(
            ether_type="0800", payload_hex=hex_bytes(_ipv4(6, "1.1.1.1", "2.2.2.2", b"\x00" * 20))
        ),
        build_ethernet_frame(
            ether_type="0800", payload_hex=hex_bytes(_ipv4(6, "2.2.2.2", "1.1.1.1", b"\x00" * 20))
        ),
    ]
    summary = summarise_frames(frames)
    assert len(summary["top_conversations"]) == 1
    assert summary["top_conversations"][0]["frames"] == 2


def test_services_use_the_lower_port_for_both_directions():
    frames = [
        build_ethernet_frame(
            ether_type="0800", payload_hex=hex_bytes(_ipv4(6, "1.1.1.1", "2.2.2.2", struct.pack("!HHIIBBHHH", 50000, 443, 1, 0, 0x50, 0x02, 0, 0, 0)))
        ),
        build_ethernet_frame(
            ether_type="0800", payload_hex=hex_bytes(_ipv4(6, "2.2.2.2", "1.1.1.1", struct.pack("!HHIIBBHHH", 443, 50000, 1, 0, 0x50, 0x12, 0, 0, 0)))
        ),
    ]
    summary = summarise_frames(frames)
    assert summary["top_services"] == [{"service": "tcp/443", "frames": 2}]


def test_l2_only_traffic_still_reports_talkers():
    frames = [build_ethernet_frame(ether_type="88b5", source_mac="02:aa:bb:cc:dd:ee")]
    summary = summarise_frames(frames)
    assert summary["top_talkers"][0]["host"] == "mac:02:aa:bb:cc:dd:ee"


def test_timestamps_produce_a_duration():
    frames = [(frame, 1000.0 + index) for index, frame in enumerate(_sample_frames())]
    summary = summarise_frames(frames)
    assert summary["first_timestamp"] == pytest.approx(1000.0)
    assert summary["last_timestamp"] == pytest.approx(1005.0)
    assert summary["duration_seconds"] == pytest.approx(5.0)


def test_summary_omits_timestamps_when_none_are_supplied():
    summary = summarise_frames(_sample_frames())
    assert "duration_seconds" not in summary


def test_top_n_limits_ranked_lists():
    frames = [
        build_ethernet_frame(
            ether_type="0800",
            payload_hex=hex_bytes(_ipv4(6, f"10.0.0.{index}", "1.1.1.1", b"\x00" * 20)),
        )
        for index in range(1, 8)
    ]
    summary = summarise_frames(frames, top_n=3)
    assert len(summary["top_talkers"]) == 3
    assert len(summary["top_conversations"]) == 3


def test_empty_input_is_handled():
    summary = summarise_frames([])
    assert summary["frame_count"] == 0
    assert summary["protocols"] == {}
    assert summary["top_conversations"] == []


def test_frame_summaries_respects_a_limit_and_adds_timestamps():
    frames = [(frame, 1234.5) for frame in _sample_frames()]
    summaries = frame_summaries(frames, limit=2)
    assert len(summaries) == 2
    assert summaries[0]["captured_at"] == pytest.approx(1234.5)


def test_count_protocols_matches_the_histogram():
    frames = _sample_frames()
    assert count_protocols(frames) == summarise_frames(frames)["protocols"]
