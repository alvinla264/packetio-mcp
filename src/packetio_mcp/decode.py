"""Shallow but broad protocol decoding for packet analysis.

The decoder exists to compress captures, not to be an oracle. It extracts a
handful of identifying fields per protocol so a caller can decide which frames
are worth reading in full. Every decode path is best-effort: a frame that cannot
be interpreted is still returned with its raw hex intact.

Nothing here is protocol-complete by design. A field that is missing from the
output is not evidence that the field was absent on the wire.
"""

from __future__ import annotations

import struct

from .packets import format_mac, hex_bytes, parse_vlan_stack

# EtherTypes that carry an IPv4 payload.
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_LLDP = 0x88CC
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_VLAN_9100 = 0x9100
ETHERTYPE_VLAN_9200 = 0x9200

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

_VLAN_TPIDS = {
    ETHERTYPE_VLAN,
    ETHERTYPE_QINQ,
    ETHERTYPE_VLAN_9100,
    ETHERTYPE_VLAN_9200,
}

_IP_PROTOCOL_NAMES = {
    0: "hopopt",
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    89: "ospf",
    103: "pim",
    112: "vrrp",
    115: "l2tp",
}

_ICMP_TYPE_NAMES = {
    0: "echo-reply",
    3: "destination-unreachable",
    4: "source-quench",
    5: "redirect",
    8: "echo-request",
    9: "router-advertisement",
    10: "router-solicitation",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp-request",
    14: "timestamp-reply",
}

_ICMPV6_TYPE_NAMES = {
    1: "destination-unreachable",
    2: "packet-too-big",
    3: "time-exceeded",
    4: "parameter-problem",
    128: "echo-request",
    129: "echo-reply",
    130: "multicast-listener-query",
    131: "multicast-listener-report",
    132: "multicast-listener-done",
    133: "router-solicitation",
    134: "router-advertisement",
    135: "neighbor-solicitation",
    136: "neighbor-advertisement",
    137: "redirect",
}

_TCP_FLAG_BITS = (
    (0x100, "ns"),
    (0x080, "cwr"),
    (0x040, "ece"),
    (0x020, "urg"),
    (0x010, "ack"),
    (0x008, "psh"),
    (0x004, "rst"),
    (0x002, "syn"),
    (0x001, "fin"),
)

_DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}

_DHCP_OPTION_MESSAGE_TYPE = 53
_DHCP_OPTION_REQUESTED_IP = 50
_DHCP_OPTION_SERVER_ID = 54
_DHCP_OPTION_LEASE_TIME = 51
_DHCP_OPTION_SUBNET_MASK = 1
_DHCP_OPTION_ROUTER = 3
_DHCP_OPTION_HOSTNAME = 12
_DHCP_OPTION_PARAMETER_LIST = 55
_DHCP_OPTION_END = 255
_DHCP_OPTION_PAD = 0
_DHCP_MAGIC = b"\x63\x82\x53\x63"

_DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    65: "HTTPS",
    255: "ANY",
}


def _ipv4(value: bytes) -> str:
    return ".".join(str(byte) for byte in value)


def _ipv6(value: bytes) -> str:
    """Format 16 bytes as a compact IPv6 address."""
    if len(value) != 16:
        return ""
    groups = [f"{struct.unpack('!H', value[i : i + 2])[0]:x}" for i in range(0, 16, 2)]
    # Collapse the longest run of zero groups into "::".
    best_start = best_len = 0
    current_start = current_len = 0
    for index, group in enumerate(groups):
        if group == "0":
            if current_len == 0:
                current_start = index
            current_len += 1
            if current_len > best_len:
                best_start, best_len = current_start, current_len
        else:
            current_len = 0
    if best_len < 2:
        return ":".join(groups)
    head = ":".join(groups[:best_start])
    tail = ":".join(groups[best_start + best_len :])
    return f"{head}::{tail}"


def _tcp_flags(value: int) -> dict:
    names = [name for bit, name in _TCP_FLAG_BITS if value & bit]
    return {"raw": value, "names": names, "flag_string": ",".join(names) or "none"}


# --------------------------------------------------------------------------- #
# Transport and network decoders
# --------------------------------------------------------------------------- #


def decode_tcp(payload: bytes) -> dict | None:
    """Decode a TCP header enough to identify the segment."""
    if len(payload) < 20:
        return None
    src_port, dst_port, seq, ack = struct.unpack("!HHII", payload[0:12])
    data_offset, flags = payload[12], struct.unpack("!H", payload[12:14])[0] & 0x1FF
    header_length = (data_offset >> 4) * 4
    out = {
        "source_port": src_port,
        "destination_port": dst_port,
        "sequence": seq,
        "acknowledgement": ack,
        "flags": _tcp_flags(flags),
        "header_length": header_length,
    }
    if len(payload) >= 14:
        out["window"] = struct.unpack("!H", payload[14:16])[0]
    if 20 <= header_length <= len(payload):
        options = payload[20:header_length]
        if options:
            out["option_bytes"] = len(options)
        out["payload_length"] = len(payload) - header_length
        if len(payload) > header_length:
            out["payload_hex"] = hex_bytes(payload[header_length:header_length + 64])
    return out


def decode_udp(payload: bytes) -> dict | None:
    """Decode a UDP header enough to identify the datagram."""
    if len(payload) < 8:
        return None
    src_port, dst_port, length, _checksum = struct.unpack("!HHHH", payload[0:8])
    if length < 8:
        return None
    body = payload[8:min(length, len(payload))]
    return {
        "truncated": length > len(payload),
        "checksum": _checksum,
        "source_port": src_port,
        "destination_port": dst_port,
        "length": length,
        "payload_length": len(body),
        "payload_hex": hex_bytes(body[:64]) if body else None,
    }


def decode_icmp(payload: bytes, *, version: int = 4) -> dict | None:
    """Decode an ICMP or ICMPv6 message enough to identify it."""
    if len(payload) < 4:
        return None
    message_type, code = payload[0], payload[1]
    table = _ICMP_TYPE_NAMES if version == 4 else _ICMPV6_TYPE_NAMES
    out = {
        "type": message_type,
        "code": code,
        "type_name": table.get(message_type, f"type-{message_type}"),
    }
    if len(payload) >= 8:
        out["id"] = struct.unpack("!H", payload[4:6])[0]
        out["sequence"] = struct.unpack("!H", payload[6:8])[0]
    # Neighbor discovery carries a target address at a fixed offset.
    if version == 6 and message_type in (135, 136) and len(payload) >= 24:
        out["target_address"] = _ipv6(payload[8:24])
    # Embedded original datagram for error messages, reported as a hint only.
    if message_type in (3, 5, 11, 12) and len(payload) >= 28:
        embedded = payload[8:]
        if len(embedded) >= 20 and (embedded[0] >> 4) == 4:
            out["embedded_source_ip"] = _ipv4(embedded[12:16])
            out["embedded_destination_ip"] = _ipv4(embedded[16:20])
    return out


def decode_arp(payload: bytes) -> dict | None:
    """Decode an ARP or RARP message."""
    if len(payload) < 28:
        return None
    htype, ptype, hlen, plen, operation = struct.unpack("!HHBBH", payload[0:8])
    if hlen != 6 or plen != 4:
        # Non-Ethernet/IPv4 ARP is reported without addresses rather than guessed.
        return {"hardware_type": htype, "protocol_type": f"0x{ptype:04x}", "operation": operation}
    sender_mac = format_mac(payload[8:14])
    sender_ip = _ipv4(payload[14:18])
    target_mac = format_mac(payload[18:24])
    target_ip = _ipv4(payload[24:28])
    return {
        "hardware_type": htype,
        "protocol_type": f"0x{ptype:04x}",
        "operation": operation,
        "operation_name": {1: "request", 2: "reply", 3: "request-reverse", 4: "reply-reverse"}.get(
            operation, f"op-{operation}"
        ),
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip,
    }


def decode_ipv4(payload: bytes) -> dict | None:
    """Decode an IPv4 header and its transport payload."""
    if len(payload) < 20:
        return None
    version_ihl = payload[0]
    if (version_ihl >> 4) != 4:
        return None
    header_length = (version_ihl & 0x0F) * 4
    if header_length < 20 or header_length > len(payload):
        return None

    total_length, identification, flags_fragment = struct.unpack("!HHH", payload[2:8])
    ttl, protocol = payload[8], payload[9]
    out = {
        "version": 4,
        "header_length": header_length,
        "total_length": total_length,
        "identification": identification,
        "ttl": ttl,
        "protocol": protocol,
        "protocol_name": _IP_PROTOCOL_NAMES.get(protocol, f"proto-{protocol}"),
        "source_ip": _ipv4(payload[12:16]),
        "destination_ip": _ipv4(payload[16:20]),
    }
    fragment_offset = flags_fragment & 0x1FFF
    if fragment_offset or (flags_fragment & 0x2000):
        out["fragmented"] = True
        out["fragment_offset"] = fragment_offset
        out["more_fragments"] = bool(flags_fragment & 0x2000)
        out["dont_fragment"] = bool(flags_fragment & 0x4000)

    if total_length < header_length:
        out["malformed_length"] = True
        return out
    out["truncated"] = total_length > len(payload)
    transport = payload[header_length:min(total_length, len(payload))]
    if fragment_offset:
        return out  # Non-initial fragments do not start with a transport header.
    if protocol == IPPROTO_TCP:
        decoded = decode_tcp(transport)
        if decoded:
            out["tcp"] = decoded
    elif protocol == IPPROTO_UDP:
        decoded = decode_udp(transport)
        if decoded:
            out["udp"] = decoded
            _attach_udp_application(out, transport)
    elif protocol == IPPROTO_ICMP:
        decoded = decode_icmp(transport, version=4)
        if decoded:
            out["icmp"] = decoded
    return out


def decode_ipv6(payload: bytes) -> dict | None:
    """Decode an IPv6 header and its transport payload."""
    if len(payload) < 40:
        return None
    if (payload[0] >> 4) != 6:
        return None
    payload_length, next_header, hop_limit = struct.unpack("!HBB", payload[4:8])
    out = {
        "version": 6,
        "payload_length": payload_length,
        "next_header": next_header,
        "next_header_name": _IP_PROTOCOL_NAMES.get(next_header, f"proto-{next_header}"),
        "hop_limit": hop_limit,
        "source_ip": _ipv6(payload[8:24]),
        "destination_ip": _ipv6(payload[24:40]),
    }
    out["truncated"] = 40 + payload_length > len(payload)
    transport = payload[40:min(40 + payload_length, len(payload))]

    # Walk the common extension headers so the transport layer is still found.
    current_header = next_header
    offset = 0
    guard = 0
    while current_header in (0, 43, 44, 60) and guard < 8:
        guard += 1
        if current_header == 44:  # fragment header is a fixed 8 bytes
            if offset + 8 > len(transport):
                return out
            fragment = struct.unpack("!H", transport[offset + 2:offset + 4])[0]
            out["fragment_offset"] = fragment >> 3
            out["more_fragments"] = bool(fragment & 1)
            if fragment >> 3:
                return out
            current_header = transport[offset]
            offset += 8
            continue
        if offset + 2 > len(transport):
            return out
        current_header = transport[offset]
        header_length = (transport[offset + 1] + 1) * 8
        offset += header_length
    transport = transport[offset:]
    out["effective_next_header"] = current_header

    if current_header == IPPROTO_TCP:
        decoded = decode_tcp(transport)
        if decoded:
            out["tcp"] = decoded
    elif current_header == IPPROTO_UDP:
        decoded = decode_udp(transport)
        if decoded:
            out["udp"] = decoded
            _attach_udp_application(out, transport)
    elif current_header == IPPROTO_ICMPV6:
        decoded = decode_icmp(transport, version=6)
        if decoded:
            out["icmpv6"] = decoded
    return out


def _attach_udp_application(out: dict, transport: bytes) -> None:
    """Attach DHCP or DNS detail when the ports identify the application."""
    udp = out.get("udp")
    if not udp:
        return
    body = transport[8:min(udp["length"], len(transport))]
    ports = {udp["source_port"], udp["destination_port"]}
    if ports & {67, 68}:
        decoded = decode_dhcp(body)
        if decoded:
            out["dhcp"] = decoded
    if ports & {53}:
        decoded = decode_dns(body)
        if decoded:
            out["dns"] = decoded


# --------------------------------------------------------------------------- #
# Application decoders
# --------------------------------------------------------------------------- #


def decode_dhcp(payload: bytes) -> dict | None:
    """Decode a DHCP message, reporting the operation and key options."""
    if len(payload) < 240 or payload[236:240] != _DHCP_MAGIC:
        return None
    operation, htype, hlen = payload[0], payload[1], payload[2]
    transaction_id = payload[4:8].hex()
    client_mac = format_mac(payload[28:34]) if hlen >= 6 else None
    your_ip = _ipv4(payload[16:20])
    server_ip = _ipv4(payload[20:24])

    out = {
        "operation": operation,
        "operation_name": "request" if operation == 1 else "reply" if operation == 2 else str(operation),
        "hardware_type": htype,
        "hardware_length": hlen,
        "transaction_id": transaction_id,
        "client_mac": client_mac,
        "your_ip": your_ip,
        "server_ip": server_ip,
    }
    if client_mac and payload[28:34] != b"\x00" * 6:
        out["client_identifier_mac"] = client_mac

    options: dict = {}
    index = 240
    while index < len(payload):
        option = payload[index]
        if option == _DHCP_OPTION_END:
            break
        if option == _DHCP_OPTION_PAD:
            index += 1
            continue
        if index + 1 >= len(payload):
            break
        length = payload[index + 1]
        value = payload[index + 2 : index + 2 + length]
        if len(value) < length:
            break
        _store_dhcp_option(options, option, value)
        index += 2 + length

    if "message_type" in options:
        out["message_type"] = options["message_type"]
        out["message_type_name"] = _DHCP_MESSAGE_TYPES.get(
            options["message_type"], f"type-{options['message_type']}"
        )
    for key in (
        "requested_ip",
        "server_identifier",
        "lease_time",
        "subnet_mask",
        "routers",
        "hostname",
        "parameter_request_list",
    ):
        if key in options:
            out[key] = options[key]
    return out


def _store_dhcp_option(options: dict, option: int, value: bytes) -> None:
    if option == _DHCP_OPTION_MESSAGE_TYPE and value:
        options["message_type"] = value[0]
    elif option == _DHCP_OPTION_REQUESTED_IP and len(value) >= 4:
        options["requested_ip"] = _ipv4(value[:4])
    elif option == _DHCP_OPTION_SERVER_ID and len(value) >= 4:
        options["server_identifier"] = _ipv4(value[:4])
    elif option == _DHCP_OPTION_LEASE_TIME and len(value) >= 4:
        options["lease_time"] = struct.unpack("!I", value[:4])[0]
    elif option == _DHCP_OPTION_SUBNET_MASK and len(value) >= 4:
        options["subnet_mask"] = _ipv4(value[:4])
    elif option == _DHCP_OPTION_ROUTER and len(value) >= 4:
        options["routers"] = [_ipv4(value[i : i + 4]) for i in range(0, len(value) - 3, 4)]
    elif option == _DHCP_OPTION_HOSTNAME:
        options["hostname"] = value.decode("utf-8", errors="replace").rstrip("\x00")
    elif option == _DHCP_OPTION_PARAMETER_LIST:
        options["parameter_request_list"] = list(value)


def decode_dns(payload: bytes) -> dict | None:
    """Decode a DNS message header and its first question or answer."""
    if len(payload) < 12:
        return None
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", payload[0:12]
    )
    out = {
        "transaction_id": f"0x{transaction_id:04x}",
        "flags": f"0x{flags:04x}",
        "is_response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0x0F,
        "rcode": flags & 0x0F,
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
    }
    offset = 12
    if qdcount:
        parsed, offset = _decode_dns_name(payload, offset)
        if parsed is not None and offset + 4 <= len(payload):
            qtype, qclass = struct.unpack("!HH", payload[offset : offset + 4])
            offset += 4
            out["question"] = {
                "name": parsed,
                "type": qtype,
                "type_name": _DNS_TYPES.get(qtype, f"type-{qtype}"),
                "class": qclass,
            }
    if ancount:
        parsed, offset = _decode_dns_name(payload, offset)
        if parsed is not None and offset + 10 <= len(payload):
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
            rdata = payload[offset + 10 : offset + 10 + rdlength]
            answer = {
                "name": parsed,
                "type": rtype,
                "type_name": _DNS_TYPES.get(rtype, f"type-{rtype}"),
                "class": rclass,
                "ttl": ttl,
                "data_length": rdlength,
            }
            if rtype == 1 and len(rdata) >= 4:
                answer["address"] = _ipv4(rdata[:4])
            elif rtype == 28 and len(rdata) >= 16:
                answer["address"] = _ipv6(rdata[:16])
            elif rtype in (5, 2, 12):
                target, _ = _decode_dns_name(payload, offset + 10)
                if target is not None:
                    answer["target"] = target
            out["first_answer"] = answer
    return out


def _decode_dns_name(payload: bytes, offset: int) -> tuple[str | None, int]:
    """Decode a DNS name, following compression pointers with a bounded budget."""
    labels: list[str] = []
    jumps = 0
    position = offset
    end_offset = offset
    while position < len(payload):
        length = payload[position]
        if length == 0:
            position += 1
            if jumps == 0:
                end_offset = position
            break
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(payload):
                return None, end_offset
            pointer = struct.unpack("!H", payload[position : position + 2])[0] & 0x3FFF
            if jumps == 0:
                end_offset = position + 2
            jumps += 1
            if jumps > 8 or pointer >= len(payload):
                # A pointer loop or out-of-range pointer is reported as unknown.
                return ".".join(labels) if labels else None, end_offset
            position = pointer
            continue
        if position + 1 + length > len(payload):
            return None, end_offset
        labels.append(payload[position + 1 : position + 1 + length].decode("ascii", "replace"))
        position += 1 + length
    if not jumps:
        end_offset = position
    return ".".join(labels) if labels else None, end_offset


_LLDP_TLV_NAMES = {
    0: "end",
    1: "chassis-id",
    2: "port-id",
    3: "ttl",
    4: "port-description",
    5: "system-name",
    6: "system-description",
    7: "system-capabilities",
    8: "management-address",
    9: "organizationally-specific",
}

_LLDP_CHASSIS_SUBTYPES = {
    1: "chassis-component",
    2: "interface-alias",
    3: "port-component",
    4: "mac-address",
    5: "network-address",
    6: "interface-name",
    7: "locally-assigned",
}


def decode_lldp(payload: bytes) -> dict | None:
    """Decode LLDP TLVs, reporting identity and capability fields."""
    if not payload:
        return None
    out: dict = {"tlvs": []}
    index = 0
    guard = 0
    while index + 2 <= len(payload) and guard < 64:
        guard += 1
        header = struct.unpack("!H", payload[index : index + 2])[0]
        tlv_type = header >> 9
        length = header & 0x1FF
        value = payload[index + 2 : index + 2 + length]
        if len(value) < length:
            break
        name = _LLDP_TLV_NAMES.get(tlv_type, f"tlv-{tlv_type}")
        out["tlvs"].append({"type": tlv_type, "type_name": name, "length": length})
        _store_lldp_tlv(out, tlv_type, value)
        index += 2 + length
        if tlv_type == 0:
            break
    return out


def _store_lldp_tlv(out: dict, tlv_type: int, value: bytes) -> None:
    if tlv_type == 1 and value:
        subtype = value[0]
        out["chassis_id_subtype"] = _LLDP_CHASSIS_SUBTYPES.get(subtype, str(subtype))
        if subtype == 4 and len(value) >= 7:
            out["chassis_id"] = format_mac(value[1:7])
        else:
            out["chassis_id"] = value[1:].decode("utf-8", errors="replace").rstrip("\x00")
    elif tlv_type == 2 and value:
        subtype = value[0]
        out["port_id_subtype"] = _LLDP_CHASSIS_SUBTYPES.get(subtype, str(subtype))
        if subtype == 3 and len(value) >= 7:
            out["port_id"] = format_mac(value[1:7])
        else:
            out["port_id"] = value[1:].decode("utf-8", errors="replace").rstrip("\x00")
    elif tlv_type == 3 and len(value) >= 2:
        out["ttl"] = struct.unpack("!H", value[:2])[0]
    elif tlv_type == 4:
        out["port_description"] = value.decode("utf-8", errors="replace").rstrip("\x00")
    elif tlv_type == 5:
        out["system_name"] = value.decode("utf-8", errors="replace").rstrip("\x00")
    elif tlv_type == 6:
        out["system_description"] = value.decode("utf-8", errors="replace").rstrip("\x00")
    elif tlv_type == 7 and len(value) >= 4:
        out["system_capabilities"] = struct.unpack("!H", value[0:2])[0]
        out["enabled_capabilities"] = struct.unpack("!H", value[2:4])[0]


# --------------------------------------------------------------------------- #
# Frame-level entry point
# --------------------------------------------------------------------------- #


def _protocol_label(ether_type: int, decoded: dict) -> str:
    """Name the innermost protocol identified in a frame, for summarising."""
    if ether_type == ETHERTYPE_ARP:
        return "arp"
    if ether_type == ETHERTYPE_LLDP:
        return "lldp"
    if ether_type in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
        network = decoded.get("ipv4") or decoded.get("ipv6")
        if not isinstance(network, dict):
            return "ipv4" if ether_type == ETHERTYPE_IPV4 else "ipv6"
        if "dhcp" in network:
            return "dhcp"
        if "dns" in network:
            return "dns"
        if "tcp" in network:
            return "tcp"
        if "udp" in network:
            return "udp"
        if "icmp" in network:
            return "icmp"
        if "icmpv6" in network:
            return "icmpv6"
        return "ipv4" if ether_type == ETHERTYPE_IPV4 else "ipv6"
    if ether_type in _VLAN_TPIDS:
        return "vlan"
    return f"0x{ether_type:04x}"


def decode_link_frame(frame: bytes, *, payload_limit: int = 64, link_type: int = 1) -> dict:
    """Decode an Ethernet frame into summary fields plus the protocol tree.

    The returned dictionary always includes ``hex`` so the raw bytes remain
    available regardless of how much could be interpreted.
    """
    from .scapy_decode import dissect_frame

    scapy = dissect_frame(frame, link_type=link_type, payload_limit=payload_limit)
    out: dict = {"length": len(frame), "hex": hex_bytes(frame), "scapy": scapy}
    if link_type != 1:
        out["link_type"] = link_type
        out["protocol"] = scapy.get("protocol", "unknown")
        if scapy.get("error"):
            out["error"] = scapy["error"]
        return out
    if len(frame) < 14:
        out["error"] = "frame shorter than the 14-byte Ethernet header"
        return out

    out["destination_mac"] = format_mac(frame[0:6])
    out["source_mac"] = format_mac(frame[6:12])
    tags, offset, ether_type = parse_vlan_stack(frame)
    out["vlan_tags"] = tags
    out["ether_type"] = f"0x{ether_type:04x}"
    out["vlan_ids"] = [tag["vlan_id"] for tag in tags]

    if ether_type <= 1500 and ether_type != 0:
        out["frame_kind"] = "ieee-802.3-length"
        out["llc_length"] = ether_type
    else:
        out["frame_kind"] = "ethernet-ii"

    payload = frame[offset:]
    if payload:
        out["payload_length"] = len(payload)
        out["payload_hex"] = hex_bytes(payload[:payload_limit])
        if len(payload) > payload_limit:
            out["payload_truncated"] = True
    else:
        out["payload_length"] = 0

    if ether_type == ETHERTYPE_ARP:
        arp = decode_arp(payload)
        if arp:
            out["arp"] = arp
    elif ether_type == ETHERTYPE_IPV4:
        ipv4 = decode_ipv4(payload)
        if ipv4:
            out["ipv4"] = ipv4
            _trim_transport_payload(out, payload_limit)
    elif ether_type == ETHERTYPE_IPV6:
        ipv6 = decode_ipv6(payload)
        if ipv6:
            out["ipv6"] = ipv6
            _trim_transport_payload(out, payload_limit)
    elif ether_type == ETHERTYPE_LLDP:
        lldp = decode_lldp(payload)
        if lldp:
            out["lldp"] = lldp

    out["protocol"] = _protocol_label(ether_type, out)
    return out


def _trim_transport_payload(decoded: dict, payload_limit: int) -> None:
    """Respect the payload limit on any nested transport payload hex."""
    for layer_name in ("ipv4", "ipv6"):
        layer = decoded.get(layer_name)
        if not isinstance(layer, dict):
            continue
        for transport_name in ("tcp", "udp", "icmp", "icmpv6"):
            transport = layer.get(transport_name)
            if isinstance(transport, dict) and transport.get("payload_hex"):
                raw = transport["payload_hex"].replace(" ", "")
                if len(raw) > payload_limit * 2:
                    trimmed = raw[: payload_limit * 2]
                    transport["payload_hex"] = " ".join(
                        trimmed[i : i + 2] for i in range(0, len(trimmed), 2)
                    )
                    transport["payload_truncated"] = True


def summarize_frame(frame: bytes, *, link_type: int = 1) -> dict:
    """Return a compact one-line description of a frame.

    This is the context-compression entry point: enough to triage a capture
    without returning every decoded field.
    """
    decoded = decode_link_frame(frame, payload_limit=0, link_type=link_type)
    summary = {
        "length": len(frame),
        "protocol": decoded.get("protocol"),
        "source_mac": decoded.get("source_mac"),
        "destination_mac": decoded.get("destination_mac"),
        "ether_type": decoded.get("ether_type"),
    }
    scapy = decoded.get("scapy", {})
    if scapy.get("layer_names"):
        summary["layer_names"] = scapy["layer_names"]
    if scapy.get("error"):
        summary["dissection_error"] = scapy["error"]
    if decoded.get("vlan_ids"):
        summary["vlan_ids"] = decoded["vlan_ids"]

    network = decoded.get("ipv4") or decoded.get("ipv6")
    if isinstance(network, dict):
        summary["source_ip"] = network.get("source_ip")
        summary["destination_ip"] = network.get("destination_ip")
        for transport_name in ("tcp", "udp"):
            transport = network.get(transport_name)
            if isinstance(transport, dict):
                summary["source_port"] = transport.get("source_port")
                summary["destination_port"] = transport.get("destination_port")
                if transport_name == "tcp" and transport.get("flags"):
                    summary["tcp_flags"] = transport["flags"].get("flag_string")
                break
        if "icmp" in network:
            summary["icmp_type"] = network["icmp"].get("type_name")
        if "icmpv6" in network:
            summary["icmpv6_type"] = network["icmpv6"].get("type_name")
        if "dhcp" in network:
            summary["dhcp_message_type"] = network["dhcp"].get("message_type_name")
        if "dns" in network:
            question = network["dns"].get("question")
            if question:
                summary["dns_question"] = question.get("name")
    elif decoded.get("arp"):
        arp = decoded["arp"]
        summary["arp"] = {
            "operation": arp.get("operation_name"),
            "sender_ip": arp.get("sender_ip"),
            "target_ip": arp.get("target_ip"),
        }
    elif decoded.get("lldp"):
        lldp = decoded["lldp"]
        summary["lldp"] = {
            "system_name": lldp.get("system_name"),
            "port_id": lldp.get("port_id"),
        }
    return {key: value for key, value in summary.items() if value is not None}
