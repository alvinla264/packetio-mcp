"""Regression coverage for bounded AI-facing workflows."""
import struct

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.utils import RawPcapNgWriter

from packetio_mcp.pcap import read_pcap, write_pcap, resolve_capture_path
from packetio_mcp.workflows import protocol_frame, tshark_query
from packetio_mcp.server import describe_capabilities, read_capture_file


def test_pagination(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    frame = bytes(Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/UDP())
    write_pcap(tmp_path/"pages.pcap", [(frame, float(i)) for i in range(4)])
    first = read_capture_file("pages.pcap", max_records=2, decode="summary")
    assert first["next_index"] == 2
    assert first["scan_truncated"]
    second = read_capture_file("pages.pcap", max_records=2, start_index=2)
    assert [f["packet_index"] for f in second["frames"]] == [2, 3]
    assert not second["scan_truncated"]
    assert not read_capture_file("pages.pcap", max_records=201)["ok"]


def test_pcapng_metadata(tmp_path):
    target = tmp_path/"metadata.pcapng"
    frame = bytes(Ether()/IP(dst="192.0.2.2")/UDP())
    with RawPcapNgWriter(str(target)) as writer:
        writer.linktype = 1
        writer.write_header(None)
        writer._write_packet(frame, linktype=1, sec=123.25, ifname=b"test0", direction=1)
    parsed = read_pcap(target)
    assert parsed.format == "pcapng"
    record = parsed.records[0]
    assert record.data == frame
    assert record.link_type == 1
    assert record.interface_name == "test0"
    assert record.direction == 1
    assert abs(record.timestamp - 123.25) < 0.000001


def test_protocol_builder_checksums():
    result = protocol_frame([
        {"protocol": "ethernet", "fields": {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}},
        {"protocol": "ipv4", "fields": {"src": "192.0.2.1", "dst": "192.0.2.2"}},
        {"protocol": "udp", "fields": {"sport": 1234, "dport": 4321}},
    ], "deadbeef")
    assert result["ok"], result
    packet = Ether(bytes.fromhex(result["hex"]))
    assert packet[IP].len == 32
    assert packet[IP].chksum
    assert packet[UDP].chksum
    assert len(bytes(packet)) == 60


def test_mixed_link_pcapng(tmp_path, monkeypatch):
    from packetio_mcp.server import summarise_capture_file, replay_capture_file
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    target = tmp_path/"mixed.pcapng"
    ip = bytes(IP(src="192.0.2.1", dst="192.0.2.2")/UDP())
    ethernet = bytes(Ether()/IP(ip))
    with RawPcapNgWriter(str(target)) as writer:
        writer.linktype = 1
        writer.write_header(None)
        writer._write_packet(ethernet, linktype=1, sec=1, ifname=b"eth0")
        writer._write_packet(ip, linktype=101, sec=2, ifname=b"raw0")
    parsed = read_pcap(target)
    assert parsed.link_type == -1
    assert [r.link_type for r in parsed.records] == [1, 101]
    result = read_capture_file("mixed.pcapng", decode="full")
    assert [r["protocol"] for r in result["frames"]] == ["udp", "udp"]
    assert result["analysis_backend"] == "scapy"
    summary = summarise_capture_file("mixed.pcapng")
    assert summary["protocols"] == {"udp": 2}
    assert not replay_capture_file("mixed.pcapng", "lo")["ok"]


def test_unanswered_arp(tmp_path, monkeypatch):
    from scapy.layers.l2 import ARP
    from packetio_mcp.workflows import unanswered_arp
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    request = Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,
        hwsrc="02:00:00:00:00:01", psrc="192.0.2.1", pdst="192.0.2.2")
    reply = Ether()/ARP(op=2, psrc="192.0.2.2", pdst="192.0.2.1", hwdst="02:00:00:00:00:01")
    write_pcap(tmp_path/"arp.pcap", [(bytes(request), 1), (bytes(reply), 2)])
    assert unanswered_arp("arp.pcap")["matching_requests"] == 0
    partial = unanswered_arp("arp.pcap", 1)
    assert partial["matching_requests"] == 1
    assert partial["scan_truncated"]


def test_builder_rejects_code_and_dns():
    assert not protocol_frame([{"protocol": "python", "fields": {}}])["ok"]
    assert not protocol_frame([{"protocol": "ethernet", "fields": {"src": "foo", "dst": "bar"}}])["ok"]
    assert not protocol_frame([
        {"protocol": "ethernet", "fields": {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}},
        {"protocol": "ipv4", "fields": {"src": "192.0.2.1", "dst": "example.com"}},
    ])["ok"]


def test_query_requires_tshark(monkeypatch):
    monkeypatch.setattr("packetio_mcp.workflows.shutil.which", lambda _: None)
    assert not tshark_query("absent.pcap", "arp", ["frame.number"])["ok"]
    assert "pcapng" in describe_capabilities()["read_formats"]


def test_exchange_spaces_every_frame_and_preserves_reply_window(monkeypatch):
    from packetio_mcp import capture
    clock = [0.0]
    sent = []
    received = []
    class FakeRaw:
        def __init__(self, interface): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def bind(self): pass
        def set_promiscuous(self, value): pass
        def drain(self): return []
        def send(self, frame): sent.append(clock[0])
        def recv(self, timeout):
            received.append(timeout)
            clock[0] += timeout
            return None
    monkeypatch.setattr(capture, "RawInterface", FakeRaw)
    monkeypatch.setattr(capture.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(capture.time, "sleep", lambda value: clock.__setitem__(0, clock[0] + value))
    capture.exchange("lo", [b"a", b"b", b"c"], count=2, interval=0.5, timeout=2)
    import pytest
    assert sent == pytest.approx([0, 0.5, 1, 1.5, 2, 2.5], abs=0.001)
    assert clock[0] == pytest.approx(4.5, abs=0.001)
    assert len(received) >= 6  # Reception also runs between sends.


def test_recv_rejects_other_interfaces():
    from packetio_mcp.capture import RawInterface
    class FakeSocket:
        def settimeout(self, timeout): pass
        def recvfrom(self, size):
            return entries.pop(0)
    entries = [(b"wrong", ("other0", 0, 0, 1, b"")),
               (b"right", ("lo", 0, 0, 1, b""))]
    raw = object.__new__(RawInterface)
    raw.interface = "lo"
    raw._socket = FakeSocket()
    assert raw.recv(1).data == b"right"


def test_ng_filename(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    assert resolve_capture_path("sample.pcapng").suffix == ".pcapng"
