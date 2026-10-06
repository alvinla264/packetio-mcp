"""Capture analysis: summarise a set of frames into an overview.

The analyser is the triage step before detailed inspection. It answers questions
such as "which protocols are present", "who is talking to whom", "which VLANs
were seen" and "which hosts are acting as DHCP servers", so a caller can decide
which individual frames are worth reading in full.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from .decode import decode_link_frame, summarize_frame

# Protocols that are treated as a conversation, with the transports that carry
# an application identification worth reporting separately.
_APPLICATION_PROTOCOLS = {"dhcp", "dns"}


def _conversation_key(decoded: dict) -> tuple[str, str] | None:
    """Return a normalised, direction-independent host pair when one exists."""
    network = decoded.get("ipv4") or decoded.get("ipv6")
    if isinstance(network, dict):
        source = network.get("source_ip")
        destination = network.get("destination_ip")
        if source and destination:
            return tuple(sorted((str(source), str(destination))))  # type: ignore[return-value]
        return None
    # Non-IP traffic is summarised by MAC pair so L2-only tests still show talkers.
    source_mac = decoded.get("source_mac")
    destination_mac = decoded.get("destination_mac")
    if source_mac and destination_mac and source_mac != "00:00:00:00:00:00":
        return tuple(sorted((f"mac:{source_mac}", f"mac:{destination_mac}")))  # type: ignore[return-value]
    return None


def _service_label(decoded: dict) -> str | None:
    """Describe the transport endpoint when a port is meaningful."""
    network = decoded.get("ipv4") or decoded.get("ipv6")
    if not isinstance(network, dict):
        return None
    for transport_name in ("tcp", "udp"):
        transport = network.get(transport_name)
        if isinstance(transport, dict):
            source_port = transport.get("source_port")
            destination_port = transport.get("destination_port")
            # Report the lower port as the service so both directions agree.
            ports = [port for port in (source_port, destination_port) if port is not None]
            if ports:
                return f"{transport_name}/{min(ports)}"
    return None


def summarise_frames(frames: Iterable[bytes], *, top_n: int = 10, link_type: int = 1) -> dict[str, Any]:
    """Summarise an iterable of raw frames into an overview dictionary."""
    protocol_counts: Counter[str] = Counter()
    layer_counts: Counter[str] = Counter()
    ethertype_counts: Counter[str] = Counter()
    vlan_counts: Counter[int] = Counter()
    conversation_counts: Counter[tuple[str, str]] = Counter()
    talker_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    dhcp_servers: set[str] = set()
    dhcp_offered: set[str] = set()
    dns_questions: Counter[str] = Counter()
    arp_requesters: Counter[str] = Counter()
    arp_responders: Counter[str] = Counter()
    frame_count = 0
    total_bytes = 0
    parse_errors = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    for item in frames:
        frame, timestamp = _split_item(item)
        packet_link_type = item[2] if isinstance(item, tuple) and len(item) == 3 else link_type
        frame_count += 1
        total_bytes += len(frame)
        if timestamp is not None:
            if first_timestamp is None or timestamp < first_timestamp:
                first_timestamp = timestamp
            if last_timestamp is None or timestamp > last_timestamp:
                last_timestamp = timestamp

        decoded = decode_link_frame(frame, payload_limit=0, link_type=packet_link_type)
        for name in set(decoded.get("scapy", {}).get("layer_names", [])):
            layer_counts[name] += 1
        if decoded.get("error"):
            parse_errors += 1
            continue

        protocol = decoded.get("protocol") or "unknown"
        protocol_counts[protocol] += 1
        ethertype = decoded.get("ether_type")
        if ethertype:
            ethertype_counts[ethertype] += 1
        for vlan_id in decoded.get("vlan_ids") or []:
            vlan_counts[vlan_id] += 1

        conversation = _conversation_key(decoded)
        if conversation:
            conversation_counts[conversation] += 1
        source = _source_host(decoded)
        if source:
            talker_counts[source] += 1
        service = _service_label(decoded)
        if service:
            service_counts[service] += 1

        network = decoded.get("ipv4") or decoded.get("ipv6")
        if isinstance(network, dict):
            dhcp = network.get("dhcp")
            if isinstance(dhcp, dict):
                server = dhcp.get("server_identifier")
                if server:
                    dhcp_servers.add(str(server))
                offered = dhcp.get("your_ip")
                if offered and offered != "0.0.0.0":
                    dhcp_offered.add(str(offered))
            dns = network.get("dns")
            if isinstance(dns, dict) and not dns.get("is_response"):
                question = dns.get("question")
                if isinstance(question, dict) and question.get("name"):
                    dns_questions[str(question["name"])] += 1

        arp = decoded.get("arp")
        if isinstance(arp, dict):
            if arp.get("operation") == 1 and arp.get("sender_ip"):
                arp_requesters[str(arp["sender_ip"])] += 1
            elif arp.get("operation") == 2 and arp.get("sender_ip"):
                arp_responders[str(arp["sender_ip"])] += 1

    summary: dict[str, Any] = {
        "frame_count": frame_count,
        "total_bytes": total_bytes,
        "unparsed_frames": parse_errors,
        "protocols": dict(protocol_counts.most_common()),
        "scapy_layers": dict(layer_counts.most_common()),
        "ethertypes": dict(ethertype_counts.most_common(top_n)),
        "vlans": {str(vlan): count for vlan, count in vlan_counts.most_common()},
        "top_conversations": [
            {"hosts": list(pair), "frames": count}
            for pair, count in conversation_counts.most_common(top_n)
        ],
        "top_talkers": [
            {"host": host, "frames": count} for host, count in talker_counts.most_common(top_n)
        ],
        "top_services": [
            {"service": service, "frames": count}
            for service, count in service_counts.most_common(top_n)
        ],
    }

    if dhcp_servers:
        summary["dhcp_servers"] = sorted(dhcp_servers)
    if dhcp_offered:
        summary["dhcp_offered_addresses"] = sorted(dhcp_offered)
    if dns_questions:
        summary["dns_questions"] = dict(dns_questions.most_common(top_n))
    if arp_requesters:
        summary["arp_requesters"] = dict(arp_requesters.most_common(top_n))
    if arp_responders:
        summary["arp_responders"] = dict(arp_responders.most_common(top_n))
    if first_timestamp is not None and last_timestamp is not None:
        summary["first_timestamp"] = round(first_timestamp, 6)
        summary["last_timestamp"] = round(last_timestamp, 6)
        summary["duration_seconds"] = round(last_timestamp - first_timestamp, 6)
    return summary


def _split_item(item: Any) -> tuple[bytes, float | None]:
    """Accept either raw frames or (frame, timestamp) pairs."""
    if isinstance(item, tuple) and len(item) in (2, 3):
        frame, timestamp = item[:2]
        return bytes(frame), (float(timestamp) if timestamp is not None else None)
    return bytes(item), None


def _source_host(decoded: dict) -> str | None:
    network = decoded.get("ipv4") or decoded.get("ipv6")
    if isinstance(network, dict) and network.get("source_ip"):
        return str(network["source_ip"])
    source_mac = decoded.get("source_mac")
    if source_mac and source_mac != "00:00:00:00:00:00":
        return f"mac:{source_mac}"
    return None


def frame_summaries(
    frames: Iterable[bytes], *, limit: int | None = None
) -> list[dict[str, Any]]:
    """Return a compact summary line per frame, optionally capped."""
    out: list[dict[str, Any]] = []
    for index, item in enumerate(frames):
        if limit is not None and index >= limit:
            break
        frame, timestamp = _split_item(item)
        entry = summarize_frame(frame)
        if timestamp is not None:
            entry["captured_at"] = round(timestamp, 6)
        out.append(entry)
    return out


def count_protocols(frames: Iterable[bytes]) -> dict[str, int]:
    """Return a protocol histogram, using no timestamps."""
    counts: Counter[str] = Counter()
    for item in frames:
        frame, _ = _split_item(item)
        decoded = decode_link_frame(frame, payload_limit=0)
        counts[decoded.get("protocol") or "unknown"] += 1
    return dict(counts.most_common())
