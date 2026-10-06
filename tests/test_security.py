"""Offline security regressions; never open a raw socket or send traffic."""
import os
import stat

import pytest

from packetio_mcp.pcap import (PcapError, PcapRecord, resolve_capture_path,
                              read_pcap, write_pcap, write_pcapng, list_captures)
from packetio_mcp.file_safety import private_output
from packetio_mcp.filters import FilterError, compile_filter
from packetio_mcp.packets import PacketError, parse_hex_bytes, MAX_PACKET_BYTES
from packetio_mcp import server, testing


@pytest.fixture
def capture_root(tmp_path, monkeypatch):
    root = tmp_path / 'captures'
    root.mkdir(mode=0o700)
    monkeypatch.setenv('PACKETIO_CAPTURE_DIR', str(root))
    return root


@pytest.mark.parametrize('extension', ['.pcap', '.pcapng'])
def test_suffix_symlink_rejected_before_write(capture_root, tmp_path, extension):
    victim = tmp_path / 'victim'
    victim.write_bytes(b'sentinel')
    (capture_root / ('alias' + extension)).symlink_to(victim)
    name = 'alias' if extension == '.pcap' else 'alias.pcapng'
    with pytest.raises(PcapError):
        resolve_capture_path(name, for_write=True)
    assert victim.read_bytes() == b'sentinel'


def test_read_rejects_final_and_intermediate_symlinks(capture_root, tmp_path):
    outside = tmp_path / 'outside.pcap'
    write_pcap(outside, [])
    (capture_root / 'alias.pcap').symlink_to(outside)
    with pytest.raises(PcapError):
        read_pcap(capture_root / 'alias.pcap')
    (capture_root / 'sub').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(PcapError):
        read_pcap(capture_root / 'sub' / 'outside.pcap')


def test_writer_rejects_intermediate_symlink(capture_root, tmp_path):
    (capture_root / 'sub').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(PcapError):
        write_pcap(capture_root / 'sub' / 'outside.pcap', [])
    assert not (tmp_path / 'outside.pcap').exists()


def test_sidecar_symlink_rejected_before_send(capture_root, tmp_path, monkeypatch):
    victim = tmp_path / 'victim'
    victim.write_text('sentinel')
    (capture_root / 'test.report.json').symlink_to(victim)
    def no_send(*args, **kwargs):
        pytest.fail('invalid sidecar must be rejected before exchange')
    monkeypatch.setattr(testing, 'exchange', no_send)
    result = testing.run_test('unused', [{'frame_hex': 'ff'*14}],
                              [{'filter': 'protocol == arp'}], save_as='test')
    assert not result['ok']
    assert victim.read_text() == 'sentinel'


def test_writers_use_private_modes_and_preserve_bytes(capture_root):
    pcap = resolve_capture_path('classic', for_write=True)
    ng = resolve_capture_path('modern.pcapng', for_write=True)
    data = bytes.fromhex('ff'*14)
    write_pcap(pcap, [(data, 1.25)])
    write_pcapng(ng, [PcapRecord(data, 1.25, len(data))])
    for path in (pcap, ng):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert read_pcap(path).records[0].data == data
    assert stat.S_IMODE(capture_root.stat().st_mode) == 0o700


def test_existing_files_and_publish_race_are_not_overwritten(capture_root):
    target = capture_root / 'existing.pcap'
    target.write_bytes(b'sentinel')
    with pytest.raises(PcapError):
        write_pcap(target, [])
    assert target.read_bytes() == b'sentinel'
    raced = capture_root / 'race'
    with pytest.raises(FileExistsError):
        with private_output(raced) as handle:
            handle.write(b'new')
            raced.write_bytes(b'race winner')
    assert raced.read_bytes() == b'race winner'
    assert not list(capture_root.glob('.packetio-*.tmp'))


def test_failed_write_does_not_publish_partial_capture(capture_root):
    target = capture_root / 'bad.pcap'
    with pytest.raises(PcapError):
        write_pcap(target, [('not bytes', 1.0)])
    assert not target.exists()
    assert not list(capture_root.glob('.packetio-*.tmp'))


def test_fifo_read_rejected_without_blocking(capture_root):
    fifo = capture_root / 'fifo.pcap'
    os.mkfifo(fifo)
    with pytest.raises(PcapError):
        read_pcap(fifo)


def test_insecure_existing_root_is_rejected(capture_root):
    capture_root.chmod(0o755)
    with pytest.raises(PcapError, match='0700'):
        resolve_capture_path('new', for_write=True)
    assert stat.S_IMODE(capture_root.stat().st_mode) == 0o755


def test_list_ignores_symlinks(capture_root, tmp_path):
    victim = tmp_path / 'victim'
    victim.write_bytes(b'sentinel')
    (capture_root / 'alias.pcap').symlink_to(victim)
    assert list_captures() == []


@pytest.mark.parametrize('expression', [
    'not '*1200 + 'protocol == arp',
    '('*1200 + 'protocol == arp' + ')'*1200,
    ' and '.join(['protocol == arp']*100),
    'x'*4097,
])
def test_filters_have_length_and_recursion_bounds(expression):
    with pytest.raises(FilterError):
        compile_filter(expression)


def test_large_hex_rejected_before_decode():
    with pytest.raises(PacketError):
        parse_hex_bytes('ff'*(MAX_PACKET_BYTES+1))
    with pytest.raises(PacketError):
        parse_hex_bytes(' '*100000)


@pytest.mark.parametrize('expect', [
    {'filter': 'protocol =='}, {'filter': ''}, {'filter': 12},
    {'reply_count_at_least': -1}, {'reply_count_at_least': True},
    {'reply_contains': ''}, {'reply_contains': 'not hex'},
    {'unknown': 'value'}, {},
])
def test_invalid_expectations_never_send(monkeypatch, expect):
    def no_send(*args, **kwargs):
        pytest.fail('invalid expectations must not transmit')
    monkeypatch.setattr(server, 'exchange', no_send)
    monkeypatch.setattr(server, 'resolve_interface', lambda interface: interface)
    result = server.send_and_receive('unused', builder='raw',
                                     frame_hex='ff'*14, expect=expect)
    assert not result['ok']
