"""Linux VLAN ancillary metadata fidelity regressions."""
import socket
import struct
import pytest
from packetio_mcp.capture import _restore_vlan, RawInterface, CaptureError
from packetio_mcp.packets import build_ethernet_frame


def aux(tci=0, tpid=0, status=1 << 4):
    return [(263, 8, struct.pack('=IIIHHHH', status, 60, 60, 0, 14, tci, tpid))]


@pytest.mark.parametrize('tci', [0, 591, (5 << 13) | (1 << 12) | 123])
def test_vlan_tci_and_fallback(tci):
    frame = build_ethernet_frame(ether_type='88ca')
    restored, changed = _restore_vlan(frame, aux(tci))
    assert changed
    assert restored == frame[:12] + struct.pack('!HH', 0x8100, tci) + frame[12:]


def test_qinq_stripped_outer():
    frame = build_ethernet_frame(ether_type='88b5', vlan_mode='802.1q', vlan_id=123)
    restored, changed = _restore_vlan(frame, aux(456, 0x88a8, (1 << 4) | (1 << 6)))
    assert changed
    assert restored[12:22] == bytes.fromhex('88a801c88100007b88b5')


def test_no_valid_status_does_not_invent_tag():
    frame = build_ethernet_frame(ether_type='88ca')
    assert _restore_vlan(frame, aux(591, 0x8100, 0)) == (frame, False)
    assert _restore_vlan(frame, [(263, 8, b'\0'*10)]) == (frame, False)
    assert _restore_vlan(frame, []) == (frame, False)


def test_incomplete_header():
    with pytest.raises(CaptureError, match='incomplete Ethernet'):
        _restore_vlan(b'123', aux())


def test_recv_metadata_and_provenance():
    frame = build_ethernet_frame(ether_type='88ca')
    class FakeSocket:
        def settimeout(self, timeout): pass
        def recvmsg(self, size, ancsize):
            return frame, aux(591), 0, ('lo', 0, 0, 1, b'')
    raw = object.__new__(RawInterface)
    raw.interface = 'lo'
    raw._socket = FakeSocket()
    result = raw.recv(1)
    assert result.vlan_reconstructed
    assert result.to_dict(decode='full')['vlan_ids'] == [591]
    assert result.to_dict()['vlan_reconstructed']
