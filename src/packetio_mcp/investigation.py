"""Bounded streaming orientation, conversation evidence and payload inspection."""
from __future__ import annotations

from collections import Counter
import hashlib
import json

from .pcap import CaptureStream, PcapError, resolve_capture_path
from .decode import decode_link_frame

MAX_GROUPS = 2048


def _flow(record, decoded):
    network = decoded.get('ipv4') or decoded.get('ipv6') or {}
    protocol = 'tcp' if 'tcp' in network else 'udp' if 'udp' in network else None
    if protocol is None or network.get('fragment_offset') or network.get('more_fragments'):
        return None
    transport = network[protocol]
    source = (network['source_ip'], transport['source_port'])
    destination = (network['destination_ip'], transport['destination_port'])
    endpoints = sorted([source, destination])
    key = [protocol, endpoints, decoded.get('vlan_ids', []),
           record.section_index, record.interface_id, record.interface_name]
    identity = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:16]
    return identity, protocol, source, destination, transport


def scan_capture(filename, max_packets=100000, top_n=20, conversations=False):
    if not 1 <= max_packets <= 1000000 or not 1 <= top_n <= 100:
        return {'ok': False, 'error': 'max_packets must be 1..1000000 and top_n 1..100'}
    protocols = Counter()
    groups = {}
    omitted = 0
    total_bytes = 0
    truncated_records = 0
    try:
        with CaptureStream(resolve_capture_path(filename), max_packets=max_packets) as stream:
            for record in stream:
                decoded = decode_link_frame(record.data, payload_limit=0, link_type=record.link_type)
                protocol = decoded.get('protocol', 'unknown')
                protocols[protocol if protocol in protocols or len(protocols) < 256 else 'other'] += 1
                total_bytes += len(record.data)
                truncated_records += len(record.data) < record.original_length
                flow = _flow(record, decoded)
                if flow is None:
                    continue
                identity, protocol, source, destination, transport = flow
                if identity not in groups:
                    if len(groups) >= MAX_GROUPS:
                        omitted += 1
                        continue
                    groups[identity] = {'conversation_id': identity, 'protocol': protocol,
                        'endpoints': sorted([source, destination]), 'frames': 0, 'bytes': 0,
                        'first_packet_index': record.packet_index, 'last_packet_index': record.packet_index,
                        'first_timestamp': record.timestamp if record.timestamp_available else None,
                        'last_timestamp': None, 'evidence_indexes': [], 'tcp_flags': Counter()}
                group = groups[identity]
                group['frames'] += 1
                group['bytes'] += len(record.data)
                group['last_packet_index'] = record.packet_index
                group['last_timestamp'] = record.timestamp if record.timestamp_available else None
                if len(group['evidence_indexes']) < 5:
                    group['evidence_indexes'].append(record.packet_index)
                for flag in transport.get('flags', {}).get('names', []):
                    group['tcp_flags'][flag] += 1
            scope = stream.scope()
        return {'ok': True, **scope, 'total_bytes': total_bytes, 'protocols': dict(protocols),
                'truncated_records': truncated_records, 'conversation_count': len(groups),
                'conversation_tracking_truncated': omitted > 0,
                'untracked_flow_packets': omitted,
                'conversations': sorted(groups.values(), key=lambda g: g['frames'], reverse=True)[:top_n],
                'conversation_list_truncated': len(groups) > top_n,
                'scope': 'streamed scan; at most 2048 tracked flows, 15 seconds and 1 GiB input',
                'note': 'conversation IDs group endpoint pairs/VLAN/interface; reused TCP tuples are not separated into connection incarnations'}
    except (PcapError, OSError, ValueError) as error:
        return {'ok': False, 'error': str(error)}


def inspect_stream(filename, conversation_id, max_packets=200, max_payload_bytes=16384):
    """Bounded TCP sequence-space inspection, explicitly not full TCP reassembly."""
    if not 1 <= max_packets <= 200 or not 0 <= max_payload_bytes <= 65536:
        return {'ok': False, 'error': 'max_packets must be 1..200; max_payload_bytes 0..65536'}
    timeline = []
    directions = {}
    try:
        from scapy.config import conf
        from scapy.layers.inet import TCP, UDP
        from .scapy_decode import dissect_frame  # Register standard dissectors.
        with CaptureStream(resolve_capture_path(filename)) as stream:
            for record in stream:
                decoded = decode_link_frame(record.data, payload_limit=0, link_type=record.link_type)
                flow = _flow(record, decoded)
                if flow is None or flow[0] != conversation_id:
                    continue
                identity, protocol, source, destination, transport = flow
                direction = f'{source[0]}:{source[1]} -> {destination[0]}:{destination[1]}'
                state = directions.setdefault(direction, {'base_sequence': None, 'bytes': {},
                    'overlap_bytes': 0, 'conflicting_bytes': 0, 'payload_truncated': False,
                    'datagrams': []})
                row = {'packet_index': record.packet_index,
                       'captured_at': record.timestamp if record.timestamp_available else None,
                       'direction': direction, 'protocol': protocol, **transport}
                row.pop('payload_hex', None)
                row['capture_truncated'] = len(record.data) < record.original_length
                network = decoded.get('ipv4') or decoded.get('ipv6') or {}
                row['network_truncated'] = bool(network.get('truncated'))
                timeline.append(row)
                cls = conf.l2types.get(record.link_type)
                packet = cls(record.data) if cls else None
                layer = packet.getlayer(TCP if protocol == 'tcp' else UDP) if packet else None
                body = bytes(layer.payload)[:transport.get('payload_length', 0)] if layer else b''
                if protocol == 'udp':
                    if len(state['datagrams']) < 16:
                        state['datagrams'].append({'packet_index': record.packet_index,
                            'hex': body[:min(max_payload_bytes, 256)].hex(), 'length': len(body),
                            'truncated': len(body) > min(max_payload_bytes, 256)})
                elif body:
                    sequence = (transport['sequence'] + int('syn' in transport.get('flags', {}).get('names', []))) & 0xffffffff
                    if state['base_sequence'] is None:
                        state['base_sequence'] = sequence
                    offset = (sequence - state['base_sequence']) & 0xffffffff
                    if offset >= 0x80000000:
                        offset -= 0x100000000
                    for position, value in enumerate(body):
                        at = offset + position
                        if at in state['bytes']:
                            state['overlap_bytes'] += 1
                            state['conflicting_bytes'] += state['bytes'][at] != value
                        elif len(state['bytes']) < max_payload_bytes:
                            state['bytes'][at] = value
                        else:
                            state['payload_truncated'] = True
                if len(timeline) >= max_packets:
                    stream.reason = 'matching_packet_limit'
                    break
            scope = stream.scope()
        output = {}
        for direction, state in directions.items():
            values = sorted(state.pop('bytes').items())
            ranges = []
            for offset, byte in values:
                if ranges and offset == ranges[-1]['end_offset']:
                    ranges[-1]['data'].append(byte)
                    ranges[-1]['end_offset'] += 1
                else:
                    ranges.append({'start_offset': offset, 'end_offset': offset + 1, 'data': bytearray([byte])})
            state['gap_count'] = max(0, len(ranges) - 1)
            state['ranges_truncated'] = len(ranges) > 16
            state['payload_ranges'] = [{'start_offset': r['start_offset'], 'end_offset': r['end_offset'],
                                        'hex': r['data'].hex()} for r in ranges[:16]]
            output[direction] = state
        return {'ok': True, **scope, 'conversation_id': conversation_id,
                'found': bool(timeline), 'timeline': timeline, 'directions': output,
                'interpretation': 'bounded sequence-space inspection; first-seen bytes win overlaps, gaps are never filled',
                'limitations': ['not full TCP reassembly or application decryption',
                    'gaps/overlaps may reflect capture loss, retransmission or tuple reuse',
                    'absence in scanned scope is not absence in the full capture']}
    except (PcapError, OSError, ValueError, KeyError) as error:
        return {'ok': False, 'error': str(error)}
