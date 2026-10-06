import struct
import json
import pytest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.packet import Raw

from packetio_mcp.decode import decode_link_frame
from packetio_mcp.pcap import write_pcap, write_pcapng, read_pcap, PcapRecord
from packetio_mcp.investigation import scan_capture, inspect_stream
from packetio_mcp.workflows import protocol_frame

ETH = {'protocol':'ethernet','fields':{'src':'02:00:00:00:00:01','dst':'02:00:00:00:00:02'}}
IP4 = {'protocol':'ipv4','fields':{'src':'192.0.2.1','dst':'192.0.2.2'}}


def test_padding_is_not_udp_payload():
    frame = bytes(Ether()/IP(src='192.0.2.1', dst='192.0.2.2')/UDP()/Raw(b'ab')).ljust(60,b'\0')
    decoded = decode_link_frame(frame)
    assert decoded['ipv4']['udp']['payload_length'] == 2
    assert decoded['ipv4']['udp']['payload_hex'] == '61 62'


def test_non_initial_fragment_has_no_transport():
    frame = bytes(Ether()/IP(src='192.0.2.1',dst='192.0.2.2',frag=1,proto=17)/Raw(b'\0'*20))
    assert 'udp' not in decode_link_frame(frame)['ipv4']


def test_stream_ranges_and_conflicts(tmp_path, monkeypatch):
    monkeypatch.setenv('PACKETIO_CAPTURE_DIR',str(tmp_path))
    records=[]
    for seq, body in [(100,b'abc'),(106,b'ghi'),(103,b'def'),(100,b'abc'),(101,b'X')]:
        frame=Ether()/IP(src='192.0.2.1',dst='192.0.2.2')/TCP(sport=1234,dport=80,seq=seq,flags='PA')/Raw(body)
        records.append((bytes(frame), float(len(records))))
    write_pcap(tmp_path/'stream.pcap',records)
    summary=scan_capture('stream.pcap')
    assert summary['conversation_count']==1
    assert summary['protocols']=={'tcp':5}
    identity=summary['conversations'][0]['conversation_id']
    result=inspect_stream('stream.pcap',identity)
    assert result['found']
    direction=next(iter(result['directions'].values()))
    assert direction['payload_ranges'][0]['hex']==b'abcdefghi'.hex()
    assert direction['overlap_bytes']==4
    assert direction['conflicting_bytes']==1
    assert direction['gap_count']==0
    partial=inspect_stream('stream.pcap',identity,max_packets=2)
    assert next(iter(partial['directions'].values()))['gap_count']==1
    assert partial['scan_truncated']


def test_scan_bounds(tmp_path, monkeypatch):
    monkeypatch.setenv('PACKETIO_CAPTURE_DIR',str(tmp_path))
    frame=bytes(Ether()/IP(dst='192.0.2.2')/UDP())
    write_pcap(tmp_path/'bounds.pcap',[(frame,1),(frame,2)])
    result=scan_capture('bounds.pcap',max_packets=1)
    assert result['packets_scanned']==1
    assert result['scan_reason']=='packet_limit'
    assert result['next_index']==1


def test_page_beyond_old_limit(tmp_path):
    frame=bytes(Ether()/IP(dst='192.0.2.2')/UDP())
    write_pcap(tmp_path/'long.pcap',[(frame,1)]*50003)
    result=read_pcap(tmp_path/'long.pcap',max_records=2,start_index=50001)
    assert [r.packet_index for r in result.records]==[50001,50002]
    assert not result.scan_truncated


def test_pcapng_write_roundtrip(tmp_path):
    frame=bytes(Ether()/IP(dst='192.0.2.2')/UDP())
    path=tmp_path/'roundtrip.pcapng'
    write_pcapng(path,[PcapRecord(frame,12.25,len(frame),interface_name='test0',direction=1,comment='evidence')])
    record=read_pcap(path).records[0]
    assert record.interface_name=='test0'
    assert record.direction==1
    assert record.interface_id is not None
    assert record.comment=='evidence'
    assert record.timestamp==12.25
    assert record.data==frame


def test_extended_builder():
    dns=protocol_frame([ETH,IP4,{'protocol':'udp','fields':{'sport':1234,'dport':53}},
                       {'protocol':'dns','fields':{'qname':'example.test','id':42}}])
    assert dns['ok'],dns
    packet=Ether(bytes.fromhex(dns['hex']))
    assert packet[DNS].id==42
    tcp=protocol_frame([ETH,IP4,{'protocol':'tcp','fields':{'sport':1234,'dport':80,'flags':'S',
        'options':[{'name':'MSS','value':1460},{'name':'Timestamp','value':[1,2]}],'chksum':0}}])
    assert tcp['ok'],tcp
    assert Ether(bytes.fromhex(tcp['hex']))[TCP].chksum==0
    assert ('MSS',1460) in Ether(bytes.fromhex(tcp['hex']))[TCP].options
    nd=protocol_frame([ETH,{'protocol':'ipv6','fields':{'src':'2001:db8::1','dst':'ff02::1:ff00:2'}},
        {'protocol':'nd_solicitation','fields':{'tgt':'2001:db8::2'}},
        {'protocol':'nd_source_lladdr','fields':{'lladdr':'02:00:00:00:00:01'}}])
    assert nd['ok'],nd
    assert Ether(bytes.fromhex(nd['hex']))[ICMPv6ND_NS].tgt=='2001:db8::2'
    dhcp=protocol_frame([ETH,IP4,{'protocol':'udp','fields':{'sport':68,'dport':67}},
        {'protocol':'bootp','fields':{'xid':123,'chaddr':'02:00:00:00:00:01'}},
        {'protocol':'dhcp','fields':{'message_type':'discover'}}])
    assert dhcp['ok'],dhcp
    assert Ether(bytes.fromhex(dhcp['hex'])).haslayer(DHCP)


def test_kernel_timestamp():
    from packetio_mcp.capture import RawInterface
    import socket
    class FakeSocket:
        def settimeout(self, value): pass
        def recvmsg(self, size, ancsize):
            return b'frame',[(socket.SOL_SOCKET,35,struct.pack('@ll',123,250000000))],0,('lo',0,0,1,b'')
    raw=object.__new__(RawInterface)
    raw.interface='lo'
    raw._socket=FakeSocket()
    frame=raw.recv(1)
    assert frame.timestamp==123.25
    assert frame.timestamp_source=='kernel_software'


def test_runner_validates_before_sending(monkeypatch):
    from packetio_mcp import testing
    monkeypatch.setattr(testing,'exchange',lambda *a,**k: pytest.fail('must not transmit'))
    invalid=testing.run_test('lo',[{'layers':[ETH,IP4]}],[{'filter':'protocol == arp','unexpected':1}])
    assert not invalid['ok']


def test_runner_assertions_and_evidence(tmp_path,monkeypatch):
    from packetio_mcp import testing
    from packetio_mcp.capture import CapturedFrame, ExchangeResult
    monkeypatch.setenv('PACKETIO_CAPTURE_DIR',str(tmp_path))
    reply=bytes(Ether()/ARP(op=2,psrc='192.0.2.2'))
    result=ExchangeResult('lo',frames=[CapturedFrame(reply,'lo',0,0,1.1)])
    result.transmissions=[{'send_index':0,'sent_at':1}]
    result.quality={'capture_complete':True,'frames_sent':1,'drop_counters_available':True}
    monkeypatch.setattr(testing,'exchange',lambda *a,**k: result)
    report=testing.run_test('lo',[{'layers':[ETH,IP4]}],[{'filter':'protocol == arp',
        'after_send_index':0,'within_seconds':1}],save_as='test.pcapng')
    assert report['ok'],report
    assert report['verdict']=='passed'
    assert report['checks'][0]['evidence_packet_indexes']==[0]
    assert read_pcap(tmp_path/'test.pcapng').records[0].direction==1
    assert json.loads((tmp_path/'test.report.json').read_text())['verdict']=='passed'
    result.quality['capture_complete']=False
    assert testing.run_test('lo',[{'layers':[ETH,IP4]}],[{'filter':'protocol == arp'}])['verdict']=='inconclusive'
