"""Declarative, bounded packet tests. Validate everything before transmitting."""
from __future__ import annotations

import json
import math

from .capture import exchange, CaptureError
from .filters import compile_filter, FilterError
from .packets import parse_ethernet_frame, PacketError
from .pcap import resolve_capture_path, write_pcap, write_pcapng, PcapRecord, PcapError
from .decode import decode_link_frame
from .workflows import protocol_frame
from .file_safety import check_new_output, write_private_text


def run_test(interface, steps, assertions, timeout=2.0, save_as=None, max_frames=500):
    try:
        if not 1 <= len(steps) <= 100 or not 1 <= max_frames <= 5000:
            raise ValueError('provide 1..100 steps and max_frames 1..5000')
        if not math.isfinite(timeout) or not 0 <= timeout <= 30:
            raise ValueError('timeout must be finite and 0..30 seconds')
        if not 1 <= len(assertions) <= 32:
            raise ValueError('provide 1..32 assertions')
        frames, delays = [], []
        for step in steps:
            if set(step) - {'frame_hex', 'layers', 'payload_hex', 'delay_before'}:
                raise ValueError('unknown step field')
            delay = float(step.get('delay_before', 0))
            if not math.isfinite(delay) or not 0 <= delay <= 5:
                raise ValueError('delay_before must be finite and 0..5 seconds')
            if ('frame_hex' in step) == ('layers' in step):
                raise ValueError('each step must provide exactly one of frame_hex or layers')
            if 'layers' in step:
                built = protocol_frame(step['layers'], step.get('payload_hex', ''))
                if not built['ok']:
                    raise ValueError(built['error'])
                frame = parse_ethernet_frame(built['hex'])
            else:
                frame = parse_ethernet_frame(step['frame_hex'])
            if len(frame) > 9216:
                raise ValueError('frame exceeds 9216 bytes')
            frames.append(frame)
            delays.append(delay)
        if sum(delays) + timeout > 90:
            raise ValueError('test duration exceeds 90 seconds')
        prepared = []
        for assertion in assertions:
            if set(assertion) - {'filter', 'count_at_least', 'count_at_most', 'after_send_index', 'within_seconds'}:
                raise ValueError('unknown assertion field')
            predicate = compile_filter(assertion.get('filter'))
            if predicate is None:
                raise ValueError('each assertion requires a nonempty filter')
            minimum = assertion.get('count_at_least', 0 if 'count_at_most' in assertion else 1)
            maximum = assertion.get('count_at_most', max_frames)
            if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= max_frames:
                raise ValueError('assertion count bounds must be integers within max_frames')
            send_index = assertion.get('after_send_index')
            if send_index is not None and (type(send_index) is not int or not 0 <= send_index < len(steps)):
                raise ValueError('invalid after_send_index')
            within = assertion.get('within_seconds')
            if within is not None and (send_index is None or not math.isfinite(within) or not 0 <= within <= 90):
                raise ValueError('within_seconds requires after_send_index and must be 0..90')
            prepared.append((assertion, predicate, minimum, maximum, send_index, within))
        target = resolve_capture_path(save_as, for_write=True) if save_as else None
        report_path = target.with_suffix('.report.json') if target else None
        if report_path:
            check_new_output(report_path)
        result = exchange(interface, frames, timeout=timeout, frame_delays=delays,
                          capture_own=True, max_capture_frames=max_frames)
        checks = []
        evidence = []
        for index, captured in enumerate(result.frames):
            if not captured.is_outgoing:
                evidence.append((index, captured, decode_link_frame(captured.data, payload_limit=0)))
        for assertion, predicate, minimum, maximum, send_index, within in prepared:
            matches = []
            for index, captured, decoded in evidence:
                if not predicate(decoded):
                    continue
                if send_index is not None:
                    if send_index >= len(result.transmissions):
                        continue
                    elapsed = captured.timestamp - result.transmissions[send_index]['sent_at']
                    if elapsed < 0 or (within is not None and elapsed > within):
                        continue
                matches.append(index)
            checks.append({'assertion': assertion, 'passed': minimum <= len(matches) <= maximum,
                           'matching_count': len(matches), 'evidence_packet_indexes': matches[:20]})
        quality = result.quality
        complete = quality.get('capture_complete', False) and quality.get('frames_sent') == len(steps)
        verdict = 'inconclusive' if not complete else 'passed' if all(c['passed'] for c in checks) else 'failed'
        report = {'ok': True, 'verdict': verdict, 'checks': checks, 'capture_quality': quality,
                  'transmissions': result.transmissions, 'frames_captured': len(result.frames),
                  'timeline': [dict(packet_index=i, **f.to_dict(decode='summary'))
                               for i, f in enumerate(result.frames[:100])],
                  'timeline_truncated': len(result.frames) > 100,
                  'interpretation': 'assertions apply only to incoming frames in this observation window; pass is not DUT conformance',
                  'warnings': [] if quality.get('drop_counters_available') else ['socket drop counters unavailable; loss cannot be excluded']}
        if target:
            if target.suffix.lower() == '.pcapng':
                write_pcapng(target, [PcapRecord(f.data, f.timestamp, len(f.data), interface_name=interface,
                    direction=2 if f.is_outgoing else 1,
                    comment=f"timestamp_source={f.timestamp_source};vlan_reconstructed={f.vlan_reconstructed}")
                    for f in result.frames])
            else:
                write_pcap(target, [(f.data, f.timestamp) for f in result.frames])
            report['capture_file'] = str(target)
            report['report_file'] = str(report_path)
            write_private_text(report_path, json.dumps(report, indent=2))
        return report
    except (ValueError, TypeError, CaptureError, PacketError, FilterError, PcapError, OSError) as error:
        return {'ok': False, 'error': str(error)}
