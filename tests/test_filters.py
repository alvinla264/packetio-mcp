"""Tests for the filter expression language."""

from __future__ import annotations

import pytest

from packetio_mcp.filters import FilterError, compile_filter, frame_matches

TCP_FRAME = {
    "protocol": "tcp",
    "ether_type": "0x0800",
    "ipv4": {
        "source_ip": "192.168.1.10",
        "destination_ip": "93.184.216.34",
        "ttl": 64,
        "tcp": {
            "source_port": 12345,
            "destination_port": 443,
            "flags": {"flag_string": "syn", "names": ["syn"]},
        },
    },
}

DHCP_FRAME = {
    "protocol": "dhcp",
    "ipv4": {
        "source_ip": "0.0.0.0",
        "dhcp": {"message_type_name": "discover", "server_identifier": None},
    },
}

VLAN_FRAME = {
    "protocol": "icmp",
    "vlan_ids": [300, 400],
    "ipv4": {"icmp": {"type_name": "echo-request"}},
}

ARP_FRAME = {
    "protocol": "arp",
    "arp": {"operation_name": "reply", "sender_ip": "10.0.0.1"},
}


@pytest.mark.parametrize(
    "expression, frame, expected",
    [
        ("protocol == tcp", TCP_FRAME, True),
        ("protocol == 'tcp'", TCP_FRAME, True),
        ("protocol == udp", TCP_FRAME, False),
        ("protocol != udp", TCP_FRAME, True),
        ("ipv4.ttl == 64", TCP_FRAME, True),
        ("ipv4.ttl > 63", TCP_FRAME, True),
        ("ipv4.ttl < 63", TCP_FRAME, False),
        ("ipv4.ttl >= 64", TCP_FRAME, True),
        ("ipv4.ttl <= 64", TCP_FRAME, True),
        ("ipv4.tcp.destination_port == 443", TCP_FRAME, True),
        ("ipv4.tcp.destination_port > 1024", TCP_FRAME, False),
        ("ipv4.source_ip ~ '192.168'", TCP_FRAME, True),
        ("ipv4.source_ip ~ '10.'", TCP_FRAME, False),
        ("protocol == tcp and ipv4.tcp.destination_port == 443", TCP_FRAME, True),
        ("protocol == udp and ipv4.tcp.destination_port == 443", TCP_FRAME, False),
        ("protocol == udp or ipv4.tcp.destination_port == 443", TCP_FRAME, True),
        ("not protocol == udp", TCP_FRAME, True),
        ("not (protocol == udp)", TCP_FRAME, True),
        ("not protocol == tcp", TCP_FRAME, False),
        (
            "(protocol == tcp or protocol == udp) and ipv4.tcp.destination_port == 443",
            TCP_FRAME,
            True,
        ),
        ("protocol in (tcp, udp, dns)", TCP_FRAME, True),
        ("protocol in (udp, dns)", TCP_FRAME, False),
        # list-valued fields match when any member matches
        ("vlan_ids == 300", VLAN_FRAME, True),
        ("vlan_ids == 400", VLAN_FRAME, True),
        ("vlan_ids == 500", VLAN_FRAME, False),
        ("vlan_ids in (400, 500)", VLAN_FRAME, True),
        ("ipv4.icmp.type_name == echo-request", VLAN_FRAME, True),
        # nested application fields
        ("ipv4.dhcp.message_type_name == discover", DHCP_FRAME, True),
        ("ipv4.dhcp.message_type_name == offer", DHCP_FRAME, False),
        ("arp.operation_name == reply", ARP_FRAME, True),
        ("arp.sender_ip ~ '10.0.0.'", ARP_FRAME, True),
        # a missing field never matches, even when negated
        ("nonexistent == 1", TCP_FRAME, False),
        ("nonexistent != 1", TCP_FRAME, False),
        ("ipv4.tcp.not_a_field == 1", TCP_FRAME, False),
        ("arp.sender_ip == 10.0.0.1", ARP_FRAME, True),
    ],
)
def test_filter_matches(expression, frame, expected):
    assert frame_matches(expression, frame) is expected


def test_empty_filter_matches_everything():
    assert compile_filter("") is None
    assert compile_filter(None) is None
    assert compile_filter("   ") is None
    assert frame_matches("", TCP_FRAME) is True


@pytest.mark.parametrize(
    "expression",
    [
        "and",
        "protocol ==",
        "protocol ==",
        "(protocol == tcp",
        "protocol tcp",
        "== tcp",
        "protocol in ()",
        "protocol == tcp and",
        "protocol @ tcp",
        "protocol == tcp extra",
        "protocol == tcp or",
        "not",
    ],
)
def test_malformed_filters_raise_filter_error(expression):
    with pytest.raises(FilterError):
        compile_filter(expression)


def test_quoted_values_may_contain_spaces():
    frame = {"field": "value with spaces"}
    assert frame_matches("field == 'value with spaces'", frame) is True


def test_numeric_comparison_is_not_lexicographic():
    # "9" > "10" lexicographically, but 9 < 10 numerically.
    frame = {"count": 9}
    assert frame_matches("count > 10", frame) is False
    assert frame_matches("count < 10", frame) is True


def test_boolean_field_compares_as_boolean():
    frame = {"is_response": True}
    assert frame_matches("is_response == true", frame) is False  # 'true' is a string
    assert frame_matches("is_response == 1", frame) is True


def test_filter_rejects_a_non_string_expression():
    with pytest.raises(FilterError):
        compile_filter(123)  # type: ignore[arg-type]


def test_case_insensitive_substring():
    frame = {"name": "Echo-Request"}
    assert frame_matches("name ~ 'echo-request'", frame) is True
    assert frame_matches("name ~ 'ECHO'", frame) is True
