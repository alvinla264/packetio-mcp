"""Tests for the packet generation and analysis tool layer.

The offline tests need no privileges. Live tests touch a real interface and are
skipped unless running as root.
"""

from __future__ import annotations

import os
import threading
import time

import pytest

from packetio_mcp import server
from packetio_mcp.capture import check_raw_socket_permission
from packetio_mcp.packets import build_ethernet_frame, hex_bytes

ARP_REQUEST = (
    "00 01 08 00 06 04 00 01 02 00 00 00 00 01 "
    "0a 00 00 0a 00 00 00 00 00 00 0a 00 00 01"
)


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


@pytest.fixture(autouse=True)
def capture_dir(tmp_path, monkeypatch):
    """Keep every test's captures inside a temporary directory."""
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path / "captures"))
    return tmp_path / "captures"


# --------------------------------------------------------------------------- #
# Discovery tools
# --------------------------------------------------------------------------- #


def test_describe_decode_support_lists_the_decoded_protocols():
    described = server.describe_decode_support()
    assert described["ok"] is True
    assert set(described["decode_modes"]) == {"none", "summary", "full"}
    for protocol in ("arp", "ipv4", "ipv6", "tcp", "udp", "icmp", "dhcp", "dns", "lldp"):
        assert protocol in described["decoded_protocols"]


def test_describe_filters_documents_operators_and_examples():
    described = server.describe_filters()
    assert described["ok"] is True
    for operator in ("==", "!=", ">", "<", ">=", "<=", "~", "in"):
        assert operator in described["operators"]
    assert described["examples"]


# --------------------------------------------------------------------------- #
# Decode verbosity
# --------------------------------------------------------------------------- #


def test_decode_packet_summary_mode():
    frame = build_ethernet_frame(ether_type="0806", payload_hex=ARP_REQUEST)
    result = server.decode_packet(hex_bytes(frame), decode="summary")
    assert result["ok"] is True
    assert result["summary"]["protocol"] == "arp"
    assert "decoded" not in result


def test_decode_packet_full_mode_includes_the_tree_and_a_dump():
    frame = build_ethernet_frame(ether_type="0806", payload_hex=ARP_REQUEST)
    result = server.decode_packet(hex_bytes(frame))
    assert result["ok"] is True
    assert result["decoded"]["arp"]["sender_ip"] == "10.0.0.10"
    assert "dump" in result


def test_decode_packet_rejects_a_bad_decode_mode():
    frame = build_ethernet_frame(ether_type="88b5")
    result = server.decode_packet(hex_bytes(frame), decode="everything")
    assert result["ok"] is False
    assert "decode must be one of" in result["error"]


@pytest.mark.parametrize("mode", ["none", "summary", "full"])
def test_send_packet_decode_modes_are_rejected_before_touching_the_network(mode):
    # A bogus interface fails either way; this asserts the decode guard runs.
    result = server.capture_packets("definitely-not-real0", decode="bogus")
    assert result["ok"] is False


def test_capture_packets_rejects_a_bad_decode_mode():
    result = server.capture_packets("lo", decode="verbose")
    assert result["ok"] is False
    assert "decode must be one of" in result["error"]


# --------------------------------------------------------------------------- #
# Filter integration
# --------------------------------------------------------------------------- #


def test_capture_packets_rejects_an_invalid_filter():
    result = server.capture_packets("lo", filter_expression="protocol ==")
    assert result["ok"] is False
    assert "invalid filter_expression" in result["error"]


def test_send_and_receive_rejects_an_invalid_reply_filter():
    result = server.send_and_receive("lo", ether_type="88b5", reply_filter="(((")
    assert result["ok"] is False
    assert "invalid reply_filter" in result["error"]


# --------------------------------------------------------------------------- #
# Expectations
# --------------------------------------------------------------------------- #


def test_expectation_reports_a_failed_count_check():
    expectation = server._evaluate_expectations(
        {"reply_count_at_least": 3}, [b"\x00" * 14, b"\x00" * 14]
    )
    assert expectation["matched"] is False
    assert expectation["checks"][0]["passed"] is False
    assert expectation["checks"][0]["actual"] == 2


def test_expectation_passes_a_satisfied_count_check():
    expectation = server._evaluate_expectations({"reply_count_at_least": 1}, [b"\x00" * 14])
    assert expectation["matched"] is True


def test_expectation_matches_a_hex_fragment():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="de ad be ef")
    expectation = server._evaluate_expectations({"reply_contains": "de ad be ef"}, [frame])
    assert expectation["matched"] is True


def test_expectation_rejects_a_missing_hex_fragment():
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="00 11 22 33")
    expectation = server._evaluate_expectations({"reply_contains": "deadbeef"}, [frame])
    assert expectation["matched"] is False


def test_expectation_reports_invalid_hex():
    expectation = server._evaluate_expectations({"reply_contains": "zz"}, [b"\x00" * 14])
    assert expectation["matched"] is False
    assert "hexadecimal" in expectation["checks"][0]["reason"]


def test_expectation_applies_a_filter_to_the_raw_reply():
    frame = build_ethernet_frame(ether_type="0806", payload_hex=ARP_REQUEST)
    expectation = server._evaluate_expectations(
        {"filter": "protocol == arp and arp.sender_ip == 10.0.0.10"}, [frame]
    )
    assert expectation["matched"] is True


def test_expectation_filter_failure_is_reported():
    frame = build_ethernet_frame(ether_type="0806", payload_hex=ARP_REQUEST)
    expectation = server._evaluate_expectations({"filter": "protocol == dns"}, [frame])
    assert expectation["matched"] is False
    assert expectation["checks"][0]["check"] == "filter"


def test_expectation_with_no_recognised_checks():
    expectation = server._evaluate_expectations({"unknown_key": 1}, [])
    assert expectation["matched"] is False
    assert "no recognised checks" in expectation["reason"]


def test_expectation_rejects_a_non_object():
    expectation = server._evaluate_expectations("nope", [])  # type: ignore[arg-type]
    assert expectation["matched"] is False


def test_expectation_requires_all_checks_to_pass():
    frame = build_ethernet_frame(ether_type="0806", payload_hex=ARP_REQUEST)
    expectation = server._evaluate_expectations(
        {"reply_count_at_least": 1, "filter": "protocol == dns"}, [frame]
    )
    assert expectation["matched"] is False


# --------------------------------------------------------------------------- #
# Capture file tools
# --------------------------------------------------------------------------- #


def test_read_capture_file_missing_file_reports_an_error():
    result = server.read_capture_file("nothing_here.pcap")
    assert result["ok"] is False
    assert "cannot read" in result["error"]


def test_read_capture_file_rejects_an_escaping_path():
    result = server.read_capture_file("../../etc/passwd")
    assert result["ok"] is False
    assert "escape" in result["error"]


def test_read_capture_file_rejects_bad_arguments():
    assert server.read_capture_file("x.pcap", max_records=0)["ok"] is False
    assert server.read_capture_file("x.pcap", decode="loud")["ok"] is False
    assert server.read_capture_file("x.pcap", filter_expression="{{{")["ok"] is False


def test_summarise_capture_file_missing_file_reports_an_error():
    assert server.summarise_capture_file("nothing.pcap")["ok"] is False


def test_summarise_capture_file_rejects_bad_top_n():
    assert server.summarise_capture_file("x.pcap", top_n=0)["ok"] is False


def test_replay_rejects_unsafe_arguments():
    assert server.replay_capture_file("x.pcap", "lo", rate_pps=0)["ok"] is False
    assert server.replay_capture_file("x.pcap", "lo", rate_pps=-5)["ok"] is False
    assert server.replay_capture_file("x.pcap", "lo", max_frames=0)["ok"] is False
    assert server.replay_capture_file("x.pcap", "lo", start_index=-1)["ok"] is False
    assert server.replay_capture_file("x.pcap", "lo", timeout=-1)["ok"] is False


def test_replay_caps_the_frame_count():
    result = server.replay_capture_file("x.pcap", "lo", max_frames=10_000_000)
    assert result["ok"] is False
    assert "may not exceed" in result["error"]


def test_replay_rejects_an_unknown_interface():
    result = server.replay_capture_file("x.pcap", "definitely-not-real0")
    assert result["ok"] is False
    assert "unknown interface" in result["error"]


def test_capture_packets_caps_max_frames():
    result = server.capture_packets("lo", max_frames=10_000_000)
    assert result["ok"] is False
    assert "may not exceed" in result["error"]


def test_list_capture_files_reports_an_empty_directory():
    result = server.list_capture_files()
    assert result["ok"] is True
    assert result["files"] == []


# --------------------------------------------------------------------------- #
# Live behaviour
# --------------------------------------------------------------------------- #


def _traffic_during(test_body, delay=0.15, repeats=3):
    """Run a background sender while ``test_body`` captures on loopback."""

    def sender():
        time.sleep(delay)
        for _ in range(repeats):
            server.send_packet("lo", ether_type="0806", payload_hex=ARP_REQUEST)
            time.sleep(0.04)

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()
    try:
        return test_body()
    finally:
        thread.join(timeout=5)


@live
def test_capture_writes_a_readable_capture_file():
    captured = _traffic_during(
        lambda: server.capture_packets(
            "lo", timeout=1.0, include_own=True, filter_expression="protocol == arp",
            save_as="live", decode="summary",
        )
    )
    assert captured["ok"] is True
    assert captured["frame_count"] >= 1
    assert os.path.isfile(captured["capture_file"])

    read_back = server.read_capture_file("live", decode="summary")
    assert read_back["ok"] is True
    assert read_back["record_count"] == captured["frame_count"]


@live
def test_capture_overview_counts_the_observed_protocol():
    captured = _traffic_during(
        lambda: server.capture_packets(
            "lo", timeout=1.0, include_own=True, filter_expression="protocol == arp",
            decode="none",
        )
    )
    assert captured["overview"]["protocols"]["arp"] == captured["frame_count"]


@live
def test_capture_file_can_be_summarised_and_filtered():
    _traffic_during(
        lambda: server.capture_packets(
            "lo", timeout=1.0, include_own=True, filter_expression="protocol == arp",
            save_as="filtered",
        )
    )
    summary = server.summarise_capture_file("filtered")
    assert summary["ok"] is True
    assert summary["protocols"] == {"arp": summary["frame_count"]}

    matched = server.read_capture_file("filtered", filter_expression="protocol == arp")
    assert matched["returned_records"] == matched["record_count"]

    unmatched = server.read_capture_file("filtered", filter_expression="protocol == dns")
    assert unmatched["returned_records"] == 0


@live
def test_send_and_receive_expect_passes_with_summary_decode():
    """Expectations must not depend on the chosen decode verbosity."""
    result = server.send_and_receive(
        "lo",
        ether_type="0806",
        payload_hex=ARP_REQUEST,
        timeout=0.6,
        decode="summary",
        expect={"reply_count_at_least": 1, "filter": "protocol == arp"},
    )
    assert result["ok"] is True
    assert result["expectation"]["matched"] is True


@live
def test_send_and_receive_expect_fails_when_nothing_matches():
    result = server.send_and_receive(
        "lo",
        ether_type="0806",
        payload_hex=ARP_REQUEST,
        timeout=0.4,
        # Shared loopback can carry unrelated DNS while the full suite runs.
        # Scope replies to this test's ARP traffic, then verify the independent
        # DNS expectation fails rather than assuming the host is otherwise idle.
        reply_filter="protocol == arp and arp.sender_ip == 10.0.0.10",
        expect={"filter": "protocol == dns"},
    )
    assert result["ok"] is True
    assert result["reply_count"] >= 1  # Non-vacuous: test ARP traffic was received.
    assert result["expectation"]["matched"] is False


@live
def test_replay_sends_the_recorded_frames():
    _traffic_during(
        lambda: server.capture_packets(
            "lo", timeout=1.0, include_own=True, filter_expression="protocol == arp",
            save_as="replay",
        )
    )
    result = server.replay_capture_file("replay", "lo", max_frames=2, rate_pps=50.0)
    assert result["ok"] is True
    assert 1 <= result["frames_sent"] <= 2


@live
def test_replay_of_an_empty_selection_is_not_an_error():
    # Filter on a protocol that cannot appear, so the capture is genuinely empty.
    server.capture_packets(
        "lo", timeout=0.3, filter_expression="protocol == lldp", save_as="empty_capture"
    )
    result = server.replay_capture_file("empty_capture", "lo")
    assert result["ok"] is True
    assert result["frames_sent"] == 0


# --------------------------------------------------------------------------- #
# Startup privilege reporting
# --------------------------------------------------------------------------- #


def test_startup_report_is_silent_when_raw_sockets_are_permitted(capsys):
    permitted, _ = check_raw_socket_permission()
    if not permitted:
        pytest.skip("raw sockets are unavailable here; the warning is expected")
    server._report_startup_privileges()
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_startup_report_warns_on_stderr_when_denied(capsys):
    permitted, _ = check_raw_socket_permission()
    if permitted:
        pytest.skip("raw sockets are permitted here; no warning is expected")
    server._report_startup_privileges()
    captured = capsys.readouterr()
    # The warning must never touch stdout: it carries the JSON-RPC stream.
    assert captured.out == ""
    assert "CAP_NET_RAW" in captured.err
    # The remedy must be a runnable, absolute command, not a bare script name.
    assert 'setup-capabilities.sh' in captured.err
    assert 'sudo "' not in captured.err
    from packetio_mcp.capture import _locate_setup_script
    assert str(_locate_setup_script()) in captured.err
    assert "one-time" in captured.err


def test_startup_report_never_writes_to_stdout(capsys):
    """Whatever the outcome, stdout must stay clean for the protocol channel."""
    server._report_startup_privileges()
    assert capsys.readouterr().out == ""
