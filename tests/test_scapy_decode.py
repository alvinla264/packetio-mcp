"""Scapy integration: bounded dissection, compatibility and link-type safety."""
import json

from scapy.layers.l2 import Ether, Dot1Q, Dot1AD, ARP, CookedLinux
from scapy.layers.inet import IP, UDP, GRE
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from pktgen_mcp.decode import decode_link_frame, summarize_frame
from pktgen_mcp.analysis import summarise_frames
from pktgen_mcp.pcap import write_pcap
from pktgen_mcp import server


def test_scapy_dns_fields_and_legacy_schema():
    frame = bytes(Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/UDP(dport=53)/
                  DNS(id=42, qd=DNSQR(qname="example.org")))
    decoded = decode_link_frame(frame)
    assert decoded["protocol"] == "dns"
    assert decoded["ipv4"]["source_ip"] == "192.0.2.1"
    layers = {x["name"]: x["fields"] for x in decoded["scapy"]["layers"]}
    assert layers["DNS"]["id"] == 42
    assert decoded["hex"].replace(" ", "") == frame.hex()
    json.dumps(decoded)


def test_scapy_exposes_gre_beyond_legacy_decoder():
    frame = bytes(Ether()/IP()/GRE(key_present=1, key=123)/IP()/UDP()/Raw(b"test"))
    decoded = decode_link_frame(frame)
    gre = next(x for x in decoded["scapy"]["layers"] if x["name"] == "GRE")
    assert gre["fields"]["key"] == 123
    assert "GRE" in summarize_frame(frame)["layer_names"]
    assert summarise_frames([frame])["scapy_layers"]["GRE"] == 1


def test_qinq_and_arp_compatibility():
    frame = bytes(Ether()/Dot1AD(vlan=456)/Dot1Q(vlan=123)/ARP(op=2))
    decoded = decode_link_frame(frame)
    assert decoded["vlan_ids"] == [456, 123]
    assert decoded["arp"]["operation"] == 2
    assert decoded["scapy"]["layer_names"][:4] == ["Ether", "Dot1AD", "Dot1Q", "ARP"]


def test_unknown_payload_is_bounded_and_raw_bytes_retained():
    frame = bytes(Ether(type=0x88b5)/Raw(b"x" * 2000))
    decoded = decode_link_frame(frame, payload_limit=8)
    raw = next(x for x in decoded["scapy"]["layers"] if x["name"] == "Raw")
    assert raw["fields"]["load"]["hex"] == (b"x" * 8).hex()
    assert raw["fields"]["load"]["truncated"]
    assert decoded["hex"].replace(" ", "") == frame.hex()


def test_malformed_input_never_loses_raw_bytes():
    for frame in [b"", b"\0" * 4, b"\0" * 14, bytes(Ether()/IP())[:-3]]:
        decoded = decode_link_frame(frame)
        assert decoded["hex"].replace(" ", "") == frame.hex()
        json.dumps(decoded)


def test_raw_ip_and_linux_cooked_are_not_ethernet():
    for link_type, frame, name in [
        (228, bytes(IP()/UDP()), "IP"),
        (113, bytes(CookedLinux()/IP()/UDP()), "CookedLinux"),
    ]:
        decoded = decode_link_frame(frame, link_type=link_type)
        assert "source_mac" not in decoded
        assert decoded["scapy"]["layer_names"][0] == name


def test_unknown_link_type_is_explicit():
    decoded = decode_link_frame(b"x" * 60, link_type=999)
    assert "unsupported capture link type" in decoded["error"]
    assert "source_mac" not in decoded


def test_pcap_tools_use_link_type_and_prevent_non_ethernet_replay(tmp_path, monkeypatch):
    monkeypatch.setenv("PKTGEN_CAPTURE_DIR", str(tmp_path))
    write_pcap(tmp_path/"ip.pcap", [(bytes(IP()/UDP()), 1.0)], link_type=228)
    full = server.read_capture_file("ip.pcap", decode="full")
    assert full["ok"]
    assert "source_mac" not in full["frames"][0]
    assert full["frames"][0]["scapy"]["layer_names"][0] == "IP"
    assert server.read_capture_file("ip.pcap", filter_expression="scapy.protocol == udp")["returned_records"] == 1
    summary = server.summarise_capture_file("ip.pcap")
    assert summary["scapy_layers"]["IP"] == 1
    monkeypatch.setattr(server, "resolve_interface", lambda x: x)
    replay = server.replay_capture_file("ip.pcap", "test-interface")
    assert not replay["ok"]
    assert "Ethernet capture" in replay["error"]
