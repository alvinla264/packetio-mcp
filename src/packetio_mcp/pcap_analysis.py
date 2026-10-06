"""Optional, bounded offline tshark dissection with explicit Scapy fallback."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .pcap import PcapError, write_pcap

MAX_PACKETS = 200
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_INPUT_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 10


def _bounded(value, depth=0):
    """Bound returned JSON independently of the subprocess-output bound."""
    if depth >= 6:
        return {"truncated": True}
    if isinstance(value, dict):
        result = {str(k)[:256]: _bounded(v, depth + 1)
                  for k, v in list(value.items())[:64]}
        if len(value) > 64:
            result["_truncated"] = True
        return result
    if isinstance(value, list):
        result = [_bounded(v, depth + 1) for v in value[:16]]
        if len(value) > 16:
            result.append({"truncated": True})
        return result
    if isinstance(value, str):
        return value if len(value) <= 256 else value[:256] + " [truncated]"
    return value


def analyze_records(records, *, link_type: int = 1) -> dict:
    """Prefer tshark for a bounded capture prefix, otherwise report fallback.

    The caller keeps Scapy/normalized results and original bytes. tshark fields
    are supplemental and never silently change existing filter semantics.
    No shell, live capture, name resolution or user-supplied command arguments.
    """
    executable = shutil.which("tshark")
    fallback = {"backend": "scapy", "packets": []}
    if executable is None:
        return {**fallback, "reason": "tshark is not installed or not on PATH"}
    if not records:
        return {"backend": "tshark", "packets": [], "note": "no records to dissect"}
    if link_type < 0:
        return {**fallback, "reason": "mixed-link capture uses per-packet Scapy decoding"}
    if len(records) > MAX_PACKETS or sum(len(r.data) for r in records) > MAX_INPUT_BYTES:
        return {**fallback, "reason": "capture exceeds optional tshark analysis bounds"}
    try:
        with tempfile.TemporaryDirectory(prefix="packetio-analysis-") as directory:
            capture = Path(directory) / "input.pcap"
            write_pcap(capture, [(r.data, r.timestamp) for r in records], link_type=link_type)
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                with subprocess.Popen(
                    [executable, "-n", "-r", str(capture), "-T", "json", "-c", str(MAX_PACKETS)],
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                ) as process:
                    deadline = time.monotonic() + TIMEOUT_SECONDS
                    while True:
                        if stdout.tell() + stderr.tell() > MAX_OUTPUT_BYTES:
                            process.kill()
                            process.wait()
                            return {**fallback, "reason": "tshark output exceeded limit"}
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            process.kill()
                            process.wait()
                            return {**fallback, "reason": "tshark analysis timed out"}
                        try:
                            process.wait(timeout=min(0.05, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                    if process.returncode != 0:
                        return {**fallback, "reason": f"tshark exited with status {process.returncode}"}
                    if stdout.tell() + stderr.tell() > MAX_OUTPUT_BYTES:
                        return {**fallback, "reason": "tshark output exceeded limit"}
                    stdout.seek(0)
                    decoded = json.loads(stdout.read(MAX_OUTPUT_BYTES + 1))
            if not isinstance(decoded, list) or len(decoded) != len(records):
                return {**fallback, "reason": "tshark returned unexpected packet count"}
            packets = []
            for packet in decoded:
                layers = packet["_source"]["layers"]
                protocols = layers.get("frame", {}).get("frame.protocols", "")
                if not isinstance(protocols, str) or not isinstance(layers, dict):
                    raise ValueError("invalid tshark layer metadata")
                packets.append({"protocols": protocols[:256], "layers": _bounded(layers)})
            return {"backend": "tshark", "packets": packets}
    except (OSError, ValueError, KeyError, TypeError, PcapError) as error:
        return {**fallback, "reason": f"tshark unavailable: {type(error).__name__}"}
