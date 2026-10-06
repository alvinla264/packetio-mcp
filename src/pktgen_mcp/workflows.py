"""Task-oriented, bounded analysis and safe protocol construction helpers."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .pcap import read_pcap, resolve_capture_path, write_pcap, write_pcapng, PcapError
from .pcap_analysis import MAX_OUTPUT_BYTES, TIMEOUT_SECONDS, _bounded
from .decode import decode_link_frame

DIAGNOSTICS = {
    "tcp_retransmissions": "tcp.analysis.retransmission || tcp.analysis.fast_retransmission",
    "dns_failures": "dns.flags.response == 1 && dns.flags.rcode != 0",
    "arp_requests": "arp.opcode == 1",
    "dhcp_exchanges": "udp.port == 67 || udp.port == 68",
}


def tshark_query(filename: str, display_filter: str | None, fields: list[str],
                 max_packets: int = 200, start_index: int = 0) -> dict:
    """Explicit Wireshark query; failure is not silently given Scapy semantics."""
    executable = shutil.which("tshark")
    if not executable:
        return {"ok": False, "error": "tshark is required for Wireshark display filters and diagnostics",
                "alternative": "read_capture_file uses Scapy without tshark"}
    if not 1 <= max_packets <= 200:
        return {"ok": False, "error": "max_packets must be between 1 and 200"}
    if not fields or len(fields) > 16 or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", f) for f in fields):
        return {"ok": False, "error": "provide 1 to 16 valid tshark field names"}
    if display_filter and len(display_filter) > 2048:
        return {"ok": False, "error": "display_filter exceeds 2048 characters"}
    try:
        parsed = read_pcap(resolve_capture_path(filename), max_records=max_packets, start_index=start_index)
        if sum(len(r.data) for r in parsed.records) > 4 * 1024 * 1024:
            return {"ok": False, "error": "analysis input exceeds 4 MiB"}
        with tempfile.TemporaryDirectory(prefix="pktgen-query-") as directory:
            capture = Path(directory)/"query.pcapng"
            write_pcapng(capture, parsed.records)
            args = [executable, "-n", "-r", str(capture), "-T", "json"]
            if display_filter:
                args.extend(["-Y", display_filter])
            for field in dict.fromkeys(["frame.number", *fields]):
                args.extend(["-e", field])
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err) as process:
                    deadline = time.monotonic() + TIMEOUT_SECONDS
                    while process.poll() is None:
                        if out.tell() + err.tell() > MAX_OUTPUT_BYTES or time.monotonic() >= deadline:
                            process.kill()
                            process.wait()
                            return {"ok": False, "error": "tshark query exceeded runtime or output limit"}
                        try:
                            process.wait(timeout=0.05)
                        except subprocess.TimeoutExpired:
                            pass
                    if process.returncode:
                        err.seek(0)
                        return {"ok": False, "error": "tshark rejected the query",
                                "detail": err.read(1024).decode(errors="replace")}
                    if out.tell() + err.tell() > MAX_OUTPUT_BYTES:
                        return {"ok": False, "error": "tshark output exceeded limit"}
                    out.seek(0)
                    decoded = json.loads(out.read(MAX_OUTPUT_BYTES + 1))
        rows = []
        for packet in decoded[:max_packets]:
            row = _bounded(packet["_source"]["layers"])
            local = row.get("frame.number", [])
            number = int(local[0] if isinstance(local, list) else local)
            if not 1 <= number <= len(parsed.records):
                raise ValueError("unexpected tshark frame number")
            row["source_packet_index"] = parsed.records[number - 1].packet_index
            row["source_frame_number"] = row["source_packet_index"] + 1
            rows.append(row)
        return {"ok": True, "analysis_backend": "tshark", "rows": rows,
                "display_filter": display_filter, "fields": fields,
                "packets_scanned": len(parsed.records), "scan_truncated": parsed.scan_truncated,
                "next_index": parsed.next_index,
                "scope": "bounded selected range; source_packet_index is original zero-based position, source_frame_number is original one-based position; native frame.number filters/fields refer to the temporary range",
                "start_index": start_index, "scan_reason": parsed.scan_reason,
                "note": "zero matches in this prefix do not prove absence in the full capture"}
    except (OSError, ValueError, TypeError, KeyError, PcapError) as error:
        return {"ok": False, "error": str(error)}


def unanswered_arp(filename: str, max_packets: int = 200, start_index: int = 0) -> dict:
    """Correlate ARP requests/replies in a bounded prefix, without a DUT verdict."""
    if not 1 <= max_packets <= 200:
        return {"ok": False, "error": "max_packets must be between 1 and 200"}
    try:
        parsed = read_pcap(resolve_capture_path(filename), max_records=max_packets, start_index=start_index)
        pending = []
        for record in parsed.records:
            arp = decode_link_frame(record.data, payload_limit=0, link_type=record.link_type).get("arp", {})
            if arp.get("operation") == 1:
                pending.append((record, arp))
            elif arp.get("operation") == 2:
                pending = [(r, a) for r, a in pending if not (
                    a.get("target_ip") == arp.get("sender_ip") and
                    a.get("sender_ip") == arp.get("target_ip") and
                    a.get("sender_mac") == arp.get("target_mac"))]
        return {"ok": True, "analysis_backend": "normalized ARP correlation",
                "diagnostic": "unanswered_arp", "packets_scanned": len(parsed.records),
                "scan_truncated": parsed.scan_truncated, "next_index": parsed.next_index,
                "requests_without_observed_reply": [
                    {"packet_index": r.packet_index, "arp": a, "evidence": r.to_dict()}
                    for r, a in pending[:20]], "matching_requests": len(pending),
                "evidence_truncated": len(pending) > 20,
                "interpretation": "no matching later reply in scanned prefix; responses outside the capture/prefix or capture loss are possible"}
    except PcapError as error:
        return {"ok": False, "error": str(error)}


def protocol_frame(layers: list[dict], payload_hex: str = "", pad: bool = True) -> dict:
    """Allowlisted Scapy layers/fields only. No expressions or arbitrary code."""
    from scapy.layers.l2 import Ether, Dot1Q, Dot1AD, ARP
    from scapy.layers.inet import IP, UDP, TCP, ICMP
    from scapy.layers.inet6 import (IPv6, ICMPv6EchoRequest, ICMPv6EchoReply,
        ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr)
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.packet import Raw
    from .packets import parse_hex_bytes, hex_bytes, parse_mac

    allowed = {
        "ethernet": (Ether, {"src", "dst", "type"}),
        "vlan": (Dot1Q, {"vlan", "prio", "id", "type"}),
        "qinq": (Dot1AD, {"vlan", "prio", "id", "type"}),
        "arp": (ARP, {"op", "hwsrc", "hwdst", "psrc", "pdst"}),
        "ipv4": (IP, {"src", "dst", "ttl", "id", "flags", "frag", "tos", "chksum", "len"}),
        "ipv6": (IPv6, {"src", "dst", "hlim", "tc", "fl"}),
        "udp": (UDP, {"sport", "dport", "chksum", "len"}),
        "tcp": (TCP, {"sport", "dport", "seq", "ack", "flags", "window", "options", "chksum"}),
        "icmp": (ICMP, {"type", "code", "id", "seq", "chksum"}),
        "icmpv6_echo": (ICMPv6EchoRequest, {"id", "seq", "cksum"}),
        "icmpv6_echo_reply": (ICMPv6EchoReply, {"id", "seq", "cksum"}),
        "nd_solicitation": (ICMPv6ND_NS, {"tgt", "cksum"}),
        "nd_advertisement": (ICMPv6ND_NA, {"tgt", "R", "S", "O", "cksum"}),
        "nd_source_lladdr": (ICMPv6NDOptSrcLLAddr, {"lladdr"}),
        "nd_destination_lladdr": (ICMPv6NDOptDstLLAddr, {"lladdr"}),
        "dns": (DNS, {"id", "qr", "rd", "rcode", "qname", "qtype"}),
        "bootp": (BOOTP, {"op", "xid", "flags", "ciaddr", "yiaddr", "siaddr", "giaddr", "chaddr"}),
        "dhcp": (DHCP, {"message_type", "requested_addr", "server_id", "lease_time", "hostname"}),
    }
    try:
        if not 1 <= len(layers) <= 8 or layers[0].get("protocol") != "ethernet":
            raise ValueError("provide 1 to 8 layers starting with ethernet")
        packet = None
        for specification in layers:
            name = specification.get("protocol")
            if name not in allowed:
                raise ValueError(f"unsupported layer {name}")
            cls, names = allowed[name]
            fields = dict(specification.get("fields", {}))
            if not isinstance(fields, dict) or not set(fields) <= names:
                raise ValueError(f"unsupported fields for {name}")
            options = fields.pop("options", None) if name == "tcp" else None
            if any(isinstance(v, bool) or not isinstance(v, (str, int)) or
                   (isinstance(v, str) and len(v) > 128) for v in fields.values()):
                raise ValueError("fields must be bounded strings or integers")
            if name == "ethernet" and not {"src", "dst"} <= fields.keys():
                raise ValueError("explicit Ethernet src and dst are required; no network address resolution")
            if name in ("ipv4", "ipv6") and not {"src", "dst"} <= fields.keys():
                raise ValueError("explicit source and destination IP addresses are required")
            for key in ({"ethernet": ("src", "dst"), "arp": ("hwsrc", "hwdst")}.get(name, ())):
                if key in fields:
                    parse_mac(fields[key])
            if name in ("ipv4", "ipv6", "arp"):
                import ipaddress
                for key in (("src", "dst") if name != "arp" else ("psrc", "pdst")):
                    if key in fields:
                        ipaddress.ip_address(fields[key])  # No DNS lookup from a builder.
            if name.startswith("nd_"):
                import ipaddress
                if "tgt" in fields:
                    ipaddress.IPv6Address(fields["tgt"])
                if "lladdr" in fields:
                    parse_mac(fields["lladdr"])
            if name == "bootp":
                import ipaddress
                for key in ("ciaddr", "yiaddr", "siaddr", "giaddr"):
                    if key in fields:
                        ipaddress.IPv4Address(fields[key])
                if "chaddr" in fields:
                    fields["chaddr"] = parse_mac(fields["chaddr"])
            if name == "dns":
                qname = fields.pop("qname", None)
                qtype = fields.pop("qtype", "A")
                if qname is not None:
                    fields["qd"] = DNSQR(qname=qname, qtype=qtype)
            if name == "dhcp":
                kind = fields.pop("message_type", "discover")
                if kind not in ("discover", "offer", "request", "decline", "ack", "nak", "release", "inform"):
                    raise ValueError("unsupported DHCP message_type")
                import ipaddress
                for key in ("requested_addr", "server_id"):
                    if key in fields:
                        ipaddress.IPv4Address(fields[key])
                fields = {"options": [("message-type", kind), *fields.items(), "end"]}
            if options is not None:
                if not isinstance(options, list) or len(options) > 8:
                    raise ValueError("TCP options must be a list of at most 8 objects")
                tcp_options = []
                for option in options:
                    if not isinstance(option, dict) or set(option) - {"name", "value"}:
                        raise ValueError("invalid TCP option")
                    label, value = option.get("name"), option.get("value")
                    if label in ("MSS", "WScale"):
                        if type(value) is not int or not 0 <= value <= (65535 if label == "MSS" else 14):
                            raise ValueError("invalid TCP option value")
                    elif label == "Timestamp":
                        if not isinstance(value, list) or len(value) != 2 or any(type(v) is not int or not 0 <= v <= 0xffffffff for v in value):
                            raise ValueError("Timestamp requires two uint32 values")
                        value = tuple(value)
                    elif label in ("SAckOK", "NOP", "EOL"):
                        value = b"" if label == "SAckOK" else None
                    else:
                        raise ValueError("unsupported TCP option")
                    tcp_options.append((label, value))
                fields["options"] = tcp_options
            layer = cls(**fields)
            packet = layer if packet is None else packet/layer
        payload = parse_hex_bytes(payload_hex)
        if len(payload) > 9000:
            raise ValueError("payload exceeds 9000 bytes")
        if payload:
            packet = packet/Raw(payload)
        frame = bytes(packet)  # Scapy computes unset lengths and checksums here.
        if len(frame) > 9216:
            raise ValueError("frame exceeds 9216 bytes")
        if pad:
            frame = frame.ljust(60, b"\0")
        return {"ok": True, "length": len(frame), "hex": hex_bytes(frame),
                "decoded": decode_link_frame(frame), "note": "built only; nothing transmitted"}
    except Exception as error:
        return {"ok": False, "error": f"invalid protocol frame: {error}"}
