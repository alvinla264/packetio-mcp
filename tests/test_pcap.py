"""Tests for capture file reading and writing.

The writer is validated by checking the bytes it produces against the pcap
format directly, and the reader is exercised on both byte orders and on damaged
files. Independent verification with an external tool is performed outside the
test suite.
"""

from __future__ import annotations

import struct

import pytest

from packetio_mcp.packets import build_ethernet_frame
from packetio_mcp.pcap import (
    DLT_EN10MB,
    PCAP_MAGIC_US,
    PcapError,
    capture_dir,
    list_captures,
    read_pcap,
    resolve_capture_path,
    write_pcap,
)


def _frames() -> list[tuple[bytes, float]]:
    return [
        (build_ethernet_frame(ether_type="88b5", payload_hex="de ad be ef"), 1700000000.123456),
        (build_ethernet_frame(ether_type="0806", payload_hex="00" * 28), 1700000001.5),
        (build_ethernet_frame(ether_type="0800", vlan_mode="802.1q", vlan_id=300), 1700000002.000001),
    ]


def test_write_then_read_round_trips_bytes_and_timestamps(tmp_path):
    path = tmp_path / "capture.pcap"
    original = _frames()
    write_pcap(path, original)

    parsed = read_pcap(path)
    assert parsed.link_type == DLT_EN10MB
    assert parsed.byte_order == "little"
    assert parsed.nanosecond_resolution is False
    assert len(parsed.records) == len(original)
    for (expected_bytes, expected_ts), record in zip(original, parsed.records):
        assert record.data == expected_bytes
        assert record.timestamp == pytest.approx(expected_ts, abs=1e-6)


def test_written_header_is_a_little_endian_pcap(tmp_path):
    path = tmp_path / "header.pcap"
    write_pcap(path, _frames())
    header = path.read_bytes()[:24]

    # The classic magic, written little-endian, is d4 c3 b2 a1 on disk.
    assert header[:4] == bytes.fromhex("d4c3b2a1")
    magic, major, minor, _, _, snaplen, link_type = struct.unpack("<IHHiIII", header)
    assert magic == PCAP_MAGIC_US
    assert major == 2
    assert link_type == DLT_EN10MB
    assert snaplen > 0


def test_record_header_carries_both_lengths(tmp_path):
    path = tmp_path / "record.pcap"
    frame = build_ethernet_frame(ether_type="88b5", payload_hex="aa")
    write_pcap(path, [(frame, 1700000000.25)])

    content = path.read_bytes()
    seconds, microseconds, included, original = struct.unpack("<IIII", content[24:40])
    assert seconds == 1700000000
    assert microseconds == 250000
    assert included == len(frame)
    assert original == len(frame)
    assert content[40:] == frame


def test_timestamps_that_round_up_to_a_whole_second(tmp_path):
    path = tmp_path / "rounding.pcap"
    # 1.9999999 should not produce a microsecond field of 1000000.
    write_pcap(path, [(b"\x00" * 14, 1.9999999)])
    parsed = read_pcap(path)
    assert parsed.records[0].timestamp == pytest.approx(2.0, abs=1e-6)


def test_reading_a_big_endian_file(tmp_path):
    path = tmp_path / "bigendian.pcap"
    frame = b"\x00" * 14
    with open(path, "wb") as handle:
        handle.write(struct.pack(">IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 65535, DLT_EN10MB))
        handle.write(struct.pack(">IIII", 1700000000, 500000, len(frame), len(frame)))
        handle.write(frame)

    parsed = read_pcap(path)
    assert parsed.byte_order == "big"
    assert parsed.records[0].timestamp == pytest.approx(1700000000.5, abs=1e-6)


def test_reading_a_nanosecond_file(tmp_path):
    path = tmp_path / "nano.pcap"
    frame = b"\x00" * 14
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, DLT_EN10MB))
        handle.write(struct.pack("<IIII", 1700000000, 123456789, len(frame), len(frame)))
        handle.write(frame)

    parsed = read_pcap(path)
    assert parsed.nanosecond_resolution is True
    assert parsed.records[0].timestamp == pytest.approx(1700000000.123456789, abs=1e-9)


def test_max_records_limits_reading(tmp_path):
    path = tmp_path / "many.pcap"
    write_pcap(path, _frames())
    assert len(read_pcap(path, max_records=2).records) == 2


def test_max_records_zero_returns_only_metadata(tmp_path):
    path = tmp_path / "zero.pcap"
    write_pcap(path, _frames())
    assert read_pcap(path, max_records=0).records == []


def test_max_records_negative_is_rejected(tmp_path):
    with pytest.raises(PcapError):
        read_pcap(tmp_path / "capture.pcap", max_records=-1)


def test_scapy_reader_preserves_original_wire_length(tmp_path):
    from scapy.utils import RawPcapWriter

    path = tmp_path / "snaplen.pcap"
    frame = _frames()[0][0][:20]
    with RawPcapWriter(str(path), linktype=DLT_EN10MB, endianness="<") as writer:
        writer.write_header(None)
        writer.write_packet(frame, sec=123, usec=456, caplen=20, wirelen=60)
    record = read_pcap(path).records[0]
    assert record.data == frame
    assert record.original_length == 60
    assert record.timestamp == pytest.approx(123.000456)


def test_scapy_can_read_our_written_capture(tmp_path):
    from scapy.utils import RawPcapReader

    path = tmp_path / "interop.pcap"
    write_pcap(path, _frames())
    with RawPcapReader(str(path)) as reader:
        records = list(reader)
    assert [data for data, _ in records] == [data for data, _ in _frames()]


def test_writer_wraps_filesystem_errors(tmp_path):
    with pytest.raises(PcapError, match="cannot write"):
        write_pcap(tmp_path, _frames())


def test_pcapng_preserves_bytes(tmp_path):
    from scapy.utils import PcapNgWriter
    from scapy.layers.l2 import Ether

    path = tmp_path / "capture.pcapng"
    with PcapNgWriter(str(path)) as writer:
        writer.write(Ether(_frames()[0][0]))
    parsed = read_pcap(path)
    assert parsed.format == "pcapng"
    assert parsed.records[0].data == _frames()[0][0]


def test_truncated_final_record_is_tolerated(tmp_path):
    path = tmp_path / "truncated.pcap"
    write_pcap(path, _frames())
    content = path.read_bytes()
    # Drop the last 10 bytes so the final record is incomplete.
    (tmp_path / "cut.pcap").write_bytes(content[:-10])
    parsed = read_pcap(tmp_path / "cut.pcap")
    assert len(parsed.records) == 2


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not a pcap file at all",
        b"\x00" * 30,
        struct.pack("<I", 0xDEADBEEF) + b"\x00" * 40,
    ],
)
def test_invalid_files_raise_pcap_error(tmp_path, content):
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(PcapError):
        read_pcap(path)


def test_missing_file_raises_pcap_error(tmp_path):
    with pytest.raises(PcapError):
        read_pcap(tmp_path / "does_not_exist.pcap")


def test_unsupported_major_version_is_rejected(tmp_path):
    path = tmp_path / "future.pcap"
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 9, 4, 0, 0, 65535, DLT_EN10MB))
    with pytest.raises(PcapError):
        read_pcap(path)


def test_empty_capture_writes_a_valid_header(tmp_path):
    path = tmp_path / "empty.pcap"
    write_pcap(path, [])
    parsed = read_pcap(path)
    assert parsed.records == []
    assert path.stat().st_size == 24


# --------------------------------------------------------------------------- #
# Path handling
# --------------------------------------------------------------------------- #


def test_capture_dir_defaults_and_env_override(monkeypatch):
    monkeypatch.delenv("PACKETIO_CAPTURE_DIR", raising=False)
    from pathlib import Path
    assert capture_dir() == Path.home() / '.local/state/packetio-mcp/captures'
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", "/tmp/elsewhere")
    assert str(capture_dir()) == "/tmp/elsewhere"


def test_resolve_capture_path_adds_a_pcap_suffix(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    assert resolve_capture_path("run1").name == "run1.pcap"
    assert resolve_capture_path("run2.pcap").name == "run2.pcap"
    assert resolve_capture_path("run3.cap").name == "run3.cap"


@pytest.mark.parametrize(
    "filename",
    [
        "/etc/passwd",
        "/tmp/absolute.pcap",
        "../escape.pcap",
        "../../etc/passwd",
        "sub/../../escape.pcap",
        "",
        "a\x00b.pcap",
        "..",
    ],
)
def test_resolve_capture_path_rejects_escapes(monkeypatch, tmp_path, filename):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    with pytest.raises(PcapError):
        resolve_capture_path(filename)


def test_resolve_capture_path_allows_a_subdirectory(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    resolved = resolve_capture_path("sub/dir/capture")
    assert resolved.name == "capture.pcap"
    assert str(tmp_path) in str(resolved)


def test_resolve_capture_path_for_write_creates_the_file_parent(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path / "nested"))
    resolved = resolve_capture_path("deep/capture", for_write=True)
    assert resolved.parent.is_dir()


def test_list_captures_reports_only_capture_files(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    (tmp_path / "one.pcap").write_bytes(b"x")
    (tmp_path / "two.cap").write_bytes(b"x")
    (tmp_path / "ignored.txt").write_bytes(b"x")

    names = {entry["name"] for entry in list_captures()}
    assert names == {"one.pcap", "two.cap"}
    assert all(entry["size_bytes"] == 1 for entry in list_captures())


def test_list_captures_on_a_missing_directory_is_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path / "nothing_here"))
    assert list_captures() == []


def test_write_pcap_creates_missing_parent_directories(tmp_path):
    path = tmp_path / "a" / "b" / "c.pcap"
    write_pcap(path, _frames())
    assert path.is_file()


def test_write_pcap_rejects_non_bytes_records(tmp_path):
    path = tmp_path / "bad_records.pcap"
    with pytest.raises(PcapError):
        write_pcap(path, [("not bytes", 1.0)])  # type: ignore[list-item]
