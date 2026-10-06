"""Scapy-backed classic pcap I/O, preserving raw bytes and MCP metadata.

Writes little-endian Ethernet captures with microsecond timestamps.
Reads classic pcap in either byte order with microsecond or nanosecond timestamps.
"""

from __future__ import annotations

import os
import struct
import stat

from .file_safety import directory_fd, check_new_output, open_regular, private_output

from scapy.error import Scapy_Exception
from scapy.utils import RawPcapReader, RawPcapWriter, RawPcapNgReader, RawPcapNgWriter
import time

MAX_READ_RECORDS = 50_000
MAX_READ_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_SCAN_PACKETS = 1_000_000
MAX_SCAN_SECONDS = 15
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
DLT_EN10MB = 1
DEFAULT_SNAPLEN = 262144

DEFAULT_CAPTURE_DIR = str(Path.home() / '.local' / 'state' / 'pktgen-mcp' / 'captures')


class PcapError(RuntimeError):
    """Raised when a capture file cannot be read, written or validated."""


@dataclass
class PcapRecord:
    """One packet record from a capture file."""

    data: bytes
    timestamp: float
    original_length: int
    link_type: int = DLT_EN10MB
    packet_index: int = 0
    interface_name: str | None = None
    direction: int | None = None
    timestamp_available: bool = True
    timestamp_resolution: int = 1_000_000
    interface_id: int | None = None
    section_index: int = 0
    comment: str | None = None

    def to_dict(self, *, include_hex: bool = True) -> dict:
        entry = {
            "length": len(self.data),
            "original_length": self.original_length,
            "captured_at": round(self.timestamp, 6) if self.timestamp_available else None,
            "packet_index": self.packet_index,
            "link_type": self.link_type,
            "interface_name": self.interface_name,
            "interface_id": self.interface_id,
            "section_index": self.section_index,
            "comment": self.comment,
            "direction": self.direction,
            "timestamp_resolution": self.timestamp_resolution,
            "captured_truncated": len(self.data) < self.original_length,
        }
        if include_hex:
            from .packets import hex_bytes

            entry["hex"] = hex_bytes(self.data)
        return entry


@dataclass
class PcapFile:
    """A parsed capture file."""

    path: str
    link_type: int
    byte_order: str
    nanosecond_resolution: bool
    snaplen: int
    records: list[PcapRecord]
    format: str = "pcap"
    scan_truncated: bool = False
    next_index: int | None = None
    scan_reason: str = "eof"
    interfaces: list[dict] | None = None
    statistics: list[dict] | None = None

    def to_dict(self, *, include_records: bool = False, include_hex: bool = True) -> dict:
        out = {
            "path": self.path,
            "format": self.format,
            "scan_truncated": self.scan_truncated,
            "next_index": self.next_index,
            "scan_reason": self.scan_reason,
            "interfaces": self.interfaces or [],
            "interface_statistics": self.statistics or [],
            "link_type": self.link_type,
            "link_type_name": "ethernet" if self.link_type == DLT_EN10MB else str(self.link_type),
            "byte_order": self.byte_order,
            "timestamp_resolution": ("per-packet" if self.format == "pcapng" else
                                     "nanosecond" if self.nanosecond_resolution else "microsecond"),
            "snaplen": self.snaplen,
            "record_count": len(self.records),
        }
        timed_records = [r for r in self.records if r.timestamp_available]
        if timed_records:
            out["first_timestamp"] = round(timed_records[0].timestamp, 6)
            out["last_timestamp"] = round(timed_records[-1].timestamp, 6)
            out["duration_seconds"] = round(
                timed_records[-1].timestamp - timed_records[0].timestamp, 6
            )
        if include_records:
            out["records"] = [
                record.to_dict(include_hex=include_hex) for record in self.records
            ]
        return out


def capture_dir() -> Path:
    """Return the directory captures are written to.

    Controlled by ``PKTGEN_CAPTURE_DIR`` so a caller supplies a filename while
    the deployment decides the root.
    """
    return Path(os.environ.get("PKTGEN_CAPTURE_DIR") or DEFAULT_CAPTURE_DIR)


def resolve_capture_path(filename: str, *, for_write: bool = False) -> Path:
    """Resolve a capture filename inside the capture directory.

    Only a bare filename or a relative path within the capture directory is
    accepted. Absolute paths and parent-directory traversal are rejected so a
    caller cannot read or overwrite arbitrary files.
    """
    if not filename or not isinstance(filename, str):
        raise PcapError("a capture filename is required")
    if "\x00" in filename:
        raise PcapError("capture filename contains a null byte")

    candidate = Path(filename)
    if candidate.is_absolute():
        raise PcapError("capture filename must be relative to the capture directory")

    if '..' in candidate.parts:
        raise PcapError('capture filename may not escape the capture directory')
    if candidate == Path('.'):
        raise PcapError('capture filename must name a file')
    if not candidate.name.lower().endswith((".pcap", ".cap", ".pcapng")):
        candidate = candidate.with_name(candidate.name + '.pcap')
    root = Path(os.path.abspath(capture_dir()))
    resolved = root / candidate
    try:
        fd = directory_fd(root, create=for_write, private=True)
        os.close(fd)
        if for_write:
            check_new_output(resolved)
        elif resolved.is_symlink():
            raise PcapError('capture inputs may not be symlinks')
    except FileNotFoundError as error:
        if for_write:
            raise PcapError(f'unsafe capture path: {error}') from error
        # Missing inputs are reported by the reader; no directory is created
        # merely to validate a read filename.
    except OSError as error:
        raise PcapError(f'unsafe capture path: {error}') from error
    return resolved


def write_pcap(
    path: str | Path,
    records: list[tuple[bytes, float]],
    *,
    link_type: int = DLT_EN10MB,
    snaplen: int = DEFAULT_SNAPLEN,
) -> Path:
    """Write raw frames through Scapy without dissecting or rebuilding them."""
    target = Path(path)
    try:
        with private_output(target) as handle, RawPcapWriter(handle, linktype=link_type, endianness="<",
                           snaplen=snaplen, nano=False) as writer:
            writer.write_header(None)
            for frame, timestamp in records:
                if not isinstance(frame, (bytes, bytearray)):
                    raise PcapError("each record must carry bytes")
                # Normalize rounding before handing the timestamp to Scapy.
                seconds, microseconds = divmod(round(timestamp * 1_000_000), 1_000_000)
                writer.write_packet(bytes(frame), sec=seconds, usec=microseconds,
                                    caplen=len(frame), wirelen=len(frame))
    except (OSError, Scapy_Exception, ValueError, OverflowError, struct.error) as error:
        raise PcapError(f"cannot write {target}: {error}") from error
    return target


def _text(value):
    if isinstance(value, list):
        value = value[0] if value else None
    return value.decode("utf-8", errors="replace")[:256] if isinstance(value, bytes) else value


class MetadataNgReader(RawPcapNgReader):
    """Keep section-scoped interface IDs and bounded pcapng metadata."""
    def __init__(self, *args, **kwargs):
        self.section_index = -1
        self.current_interface = None
        self.interface_metadata = []
        self.interface_statistics = []
        super().__init__(*args, **kwargs)
        self.blocktypes[5] = self._read_statistics

    def _read_block_shb(self):
        super()._read_block_shb()
        self.section_index += 1
        self.interfaces = []  # IDs restart in each section.

    def _read_block_idb(self, block, size):
        super()._read_block_idb(block, size)
        options = self._read_options(block[8:])
        linktype, snaplen, info = self.interfaces[-1]
        if len(self.interface_metadata) < 256:
            self.interface_metadata.append({"section_index": self.section_index,
                "interface_id": len(self.interfaces) - 1, "link_type": linktype,
                "snaplen": snaplen, "name": _text(info.get("name")),
                "description": _text(options.get(3)), "comment": _text(options.get(1))})
        if len(self.interfaces) > 256:
            raise PcapError("pcapng exceeds 256 interfaces per section")

    def _read_block_epb(self, block, size):
        self.current_interface = struct.unpack(self.endian + "I", block[:4])[0]
        return super()._read_block_epb(block, size)

    def _read_block_pkt(self, block, size):
        self.current_interface = struct.unpack(self.endian + "H", block[:2])[0]
        return super()._read_block_pkt(block, size)

    def _read_block_spb(self, block, size):
        self.current_interface = 0
        return super()._read_block_spb(block, size)

    def _read_statistics(self, block, size):
        if len(block) < 12:
            raise PcapError("malformed pcapng interface statistics")
        interface_id, high, low = struct.unpack(self.endian + "III", block[:12])
        options = self._read_options(block[12:])
        row = {"section_index": self.section_index, "interface_id": interface_id}
        for code, name in ((4, "received"), (5, "dropped"), (6, "filter_accepted"), (7, "os_dropped")):
            value = options.get(code)
            if isinstance(value, bytes) and len(value) == 8:
                row[name] = struct.unpack(self.endian + "Q", value)[0]
        if len(self.interface_statistics) < 256:
            self.interface_statistics.append(row)
        return None


class _BoundedFile:
    """Reject huge record/block allocations before Scapy reads them."""
    def __init__(self, handle):
        self.handle = handle
        self.deadline = time.monotonic() + MAX_SCAN_SECONDS
    def read(self, size=-1):
        if time.monotonic() >= self.deadline:
            raise PcapError("capture parser exceeded 15-second time limit")
        if size < 0 or size > 4 * 1024 * 1024:
            raise PcapError("capture block exceeds 4 MiB parser limit")
        return self.handle.read(size)
    def __getattr__(self, name):
        return getattr(self.handle, name)


class CaptureStream:
    """Streaming reader with packet, file, time and block bounds."""
    def __init__(self, path, max_packets=MAX_SCAN_PACKETS):
        self.path = Path(path)
        self.max_packets = max_packets
        self.index = 0
        self.reason = "eof"
        self.reader = None

    def __enter__(self):
        self.handle = open_regular(self.path)
        try:
            self.size = os.fstat(self.handle.fileno()).st_size
            if self.size > MAX_FILE_BYTES:
                raise PcapError("capture exceeds 1 GiB file limit")
            header = self.handle.read(24)
            if len(header) < 24:
                raise PcapError("capture is too short to be a pcap file")
            self.is_ng = header[:4] == b"\x0a\x0d\x0d\x0a"
            if not self.is_ng:
                endian = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
                          b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}.get(header[:4])
                if endian is None:
                    raise PcapError("not a supported pcap or pcapng file")
                major, minor = struct.unpack(endian + "HH", header[4:8])
                if major != 2:
                    raise PcapError(f"unsupported pcap version {major}.{minor}")
            self.handle.seek(0)
            cls = MetadataNgReader if self.is_ng else RawPcapReader
            self.reader = cls(_BoundedFile(self.handle))
            self.deadline = time.monotonic() + MAX_SCAN_SECONDS
            return self
        except Exception:
            self.handle.close()
            raise

    def __exit__(self, *args):
        self.handle.close()

    def __iter__(self):
        return self

    def __next__(self):
        if self.index >= self.max_packets or time.monotonic() >= self.deadline:
            self.reason = "packet_limit" if self.index >= self.max_packets else "time_limit"
            raise StopIteration
        try:
            data, meta = self.reader._read_packet(size=DEFAULT_SNAPLEN)
        except EOFError:
            self.reason = "eof" if self.handle.tell() >= self.size else "malformed_tail"
            raise StopIteration
        if not self.is_ng and len(data) != meta.caplen:
            self.reason = "incomplete_record"
            raise StopIteration
        available = not self.is_ng or meta.tshigh is not None
        resolution = meta.tsresol if self.is_ng else (1_000_000_000 if self.reader.nano else 1_000_000)
        stamp = (((meta.tshigh << 32) + meta.tslow) / resolution if available else 0) if self.is_ng else meta.sec + meta.usec / resolution
        record = PcapRecord(data=data, timestamp=stamp, original_length=meta.wirelen,
            link_type=meta.linktype if self.is_ng else self.reader.linktype,
            packet_index=self.index, interface_name=_text(meta.ifname) if self.is_ng else None,
            direction=meta.direction if self.is_ng else None, timestamp_available=available,
            timestamp_resolution=resolution,
            interface_id=self.reader.current_interface if self.is_ng else None,
            section_index=self.reader.section_index if self.is_ng else 0,
            comment=_text(meta.comments) if self.is_ng else None)
        self.index += 1
        return record

    def scope(self):
        return {"packets_scanned": self.index, "scan_reason": self.reason,
                "scan_truncated": self.reason != "eof",
                "next_index": self.index if self.reason != "eof" else None}


def read_pcap(path: str | Path, *, max_records: int | None = None,
              start_index: int = 0) -> PcapFile:
    """Retain a bounded page while streaming over skipped packet positions."""
    if not 0 <= start_index < MAX_SCAN_PACKETS:
        raise PcapError("start_index must be between 0 and 999999")
    if max_records is not None and max_records < 0:
        raise PcapError("max_records cannot be negative")
    limit = min(max_records if max_records is not None else MAX_READ_RECORDS, MAX_READ_RECORDS)
    records = []
    retained = 0
    try:
        with CaptureStream(path) as stream:
            if limit:
                for record in stream:
                    if record.packet_index < start_index:
                        continue
                    if retained + len(record.data) > MAX_READ_BYTES:
                        stream.index -= 1
                        stream.reason = "byte_limit"
                        break
                    records.append(record)
                    retained += len(record.data)
                    if len(records) >= limit:
                        stream.reason = "page_limit" if stream.handle.tell() < stream.size else "eof"
                        break
            types = {r.link_type for r in records}
            link = next(iter(types)) if len(types) == 1 else (-1 if types else getattr(stream.reader, "linktype", 1))
            return PcapFile(path=str(path), link_type=link,
                byte_order="little" if stream.reader.endian == "<" else "big",
                nanosecond_resolution=False if stream.is_ng else stream.reader.nano,
                snaplen=getattr(stream.reader, "snaplen", DEFAULT_SNAPLEN), records=records,
                format="pcapng" if stream.is_ng else "pcap", scan_truncated=stream.reason != "eof",
                next_index=stream.index if stream.reason != "eof" else None,
                scan_reason=stream.reason,
                interfaces=getattr(stream.reader, "interface_metadata", []),
                statistics=getattr(stream.reader, "interface_statistics", []))
    except (OSError, Scapy_Exception, ValueError, struct.error, EOFError) as error:
        raise PcapError(f"cannot read {path}: {error}") from error


def write_pcapng(path, records):
    """Write raw records and available name/direction/comment metadata.

    Output interface IDs are regenerated; timestamps use microsecond resolution.
    """
    try:
        # Scapy's pcapng writer accepts only a filename. This Linux procfs
        # path refers to our already securely opened temporary inode, never
        # to the caller's pathname. Its duplicate descriptor closes separately.
        with private_output(path) as handle, RawPcapNgWriter(
                f'/proc/self/fd/{handle.fileno()}') as writer:
            writer.linktype = records[0].link_type if records else 1
            writer.write_header(None)
            names = {}
            identities = {}
            for record in records:
                if not record.timestamp_available:
                    raise PcapError("pcapng output requires available timestamps; will not invent missing times")
                identity = (record.section_index, record.interface_id, record.interface_name, record.link_type)
                if identity not in identities:
                    name = (record.interface_name or f"interface-{record.section_index}-{record.interface_id or 0}").encode()[:200]
                    if name in names and names[name] != identity:
                        name += f"-section{record.section_index}-id{record.interface_id}-dlt{record.link_type}".encode()
                    identities[identity] = name
                    names[name] = identity
                name = identities[identity]
                writer._write_packet(record.data, linktype=record.link_type,
                    sec=record.timestamp if record.timestamp_available else 0,
                    caplen=len(record.data), wirelen=record.original_length,
                    ifname=name, direction=record.direction,
                    comments=[record.comment.encode()] if record.comment else None)
        return Path(path)
    except (OSError, Scapy_Exception, ValueError, struct.error) as error:
        raise PcapError(f"cannot write pcapng: {error}") from error


def list_captures() -> list[dict]:
    """List capture files in the capture directory, newest first."""
    try:
        fd = directory_fd(capture_dir(), private=True)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise PcapError(f'unsafe capture directory: {error}') from error
    entries = []
    try:
        for name in os.listdir(fd):
            if not name.lower().endswith(('.pcap', '.cap', '.pcapng')):
                continue
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                entries.append({'name': name, 'size_bytes': info.st_size,
                                'modified': info.st_mtime})
    finally:
        os.close(fd)
    entries.sort(key=lambda entry: entry['modified'], reverse=True)
    return entries
