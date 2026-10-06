"""Optional tshark selection, subprocess bounds and compatibility tests."""
import json
import sys

from packetio_mcp import pcap_analysis, server
from packetio_mcp.pcap import PcapRecord, write_pcap
from packetio_mcp.packets import build_ethernet_frame


def records():
    return [PcapRecord(build_ethernet_frame(ether_type="88b5"), 1.0, 60)]


def fake_tshark(tmp_path, monkeypatch, body):
    executable = tmp_path / "tshark-test"
    executable.write_text(f"#!{sys.executable}\n" + body)
    executable.chmod(0o700)
    monkeypatch.setattr(pcap_analysis.shutil, "which", lambda _: str(executable))


def test_missing_tshark_falls_back(monkeypatch):
    monkeypatch.setattr(pcap_analysis.shutil, "which", lambda _: None)
    result = pcap_analysis.analyze_records(records())
    assert result["backend"] == "scapy"
    assert "not installed" in result["reason"]


def test_tshark_success_and_bounded_fields(tmp_path, monkeypatch):
    data = [{"_source": {"layers": {"frame": {"frame.protocols": "eth:data"},
                                    "data": {"data.data": "x" * 1000}}}}]
    fake_tshark(tmp_path, monkeypatch, f"print({json.dumps(data)!r})\n")
    result = pcap_analysis.analyze_records(records())
    assert result["backend"] == "tshark"
    assert result["packets"][0]["protocols"] == "eth:data"
    assert len(result["packets"][0]["layers"]["data"]["data.data"]) < 300


def test_failure_falls_back(tmp_path, monkeypatch):
    fake_tshark(tmp_path, monkeypatch, "raise SystemExit(2)\n")
    result = pcap_analysis.analyze_records(records())
    assert result["backend"] == "scapy"
    assert "status 2" in result["reason"]


def test_invalid_json_falls_back(tmp_path, monkeypatch):
    fake_tshark(tmp_path, monkeypatch, "print('not json')\n")
    assert pcap_analysis.analyze_records(records())["backend"] == "scapy"


def test_timeout_falls_back(tmp_path, monkeypatch):
    fake_tshark(tmp_path, monkeypatch, "import time; time.sleep(10)\n")
    monkeypatch.setattr(pcap_analysis, "TIMEOUT_SECONDS", 0.05)
    result = pcap_analysis.analyze_records(records())
    assert result["backend"] == "scapy"
    assert "timed out" in result["reason"]


def test_excessive_output_falls_back(tmp_path, monkeypatch):
    fake_tshark(tmp_path, monkeypatch, "print('x' * 4096)\n")
    monkeypatch.setattr(pcap_analysis, "MAX_OUTPUT_BYTES", 1024)
    result = pcap_analysis.analyze_records(records())
    assert result["backend"] == "scapy"
    assert "output exceeded" in result["reason"]


def test_input_bounds_skip_subprocess(monkeypatch):
    monkeypatch.setattr(pcap_analysis.shutil, "which", lambda _: "/not/executed")
    monkeypatch.setattr(pcap_analysis, "MAX_PACKETS", 0)
    assert "bounds" in pcap_analysis.analyze_records(records())["reason"]


def test_mcp_full_summary_and_filters_keep_compatibility(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIO_CAPTURE_DIR", str(tmp_path))
    write_pcap(tmp_path / "test.pcap", [(r.data, r.timestamp) for r in records()])
    data = [{"_source": {"layers": {"frame": {"frame.protocols": "eth:data"}}}}]
    fake_tshark(tmp_path, monkeypatch, f"print({json.dumps(data)!r})\n")
    result = server.read_capture_file("test.pcap", decode="full", filter_expression="ether_type == 0x88b5")
    assert result["analysis_backend"] == "tshark"
    assert result["returned_records"] == 1
    assert result["frames"][0]["scapy"]["backend"] == "scapy"
    assert result["frames"][0]["tshark"]["protocols"] == "eth:data"
    assert result["frames"][0]["hex"]
    summary = server.read_capture_file("test.pcap", decode="summary")
    assert summary["frames"][0]["tshark"] == {"protocols": "eth:data"}
    overview = server.summarise_capture_file("test.pcap")
    assert overview["tshark_protocol_stacks"] == {"eth:data": 1}
    assert server.read_capture_file("test.pcap", decode="none")["analysis_backend"] == "none"


def test_wrong_packet_count_falls_back(tmp_path, monkeypatch):
    fake_tshark(tmp_path, monkeypatch, "print('[]')\n")
    result = pcap_analysis.analyze_records(records())
    assert result["backend"] == "scapy"
    assert "packet count" in result["reason"]
