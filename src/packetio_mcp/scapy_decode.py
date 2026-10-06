"""Bounded, JSON-safe Scapy dissection; no live sockets or packet rebuilding."""

from __future__ import annotations

from scapy.config import conf
from scapy.packet import NoPayload, Packet, Padding, Raw
# Import standard layers to register their dissectors and link-type bindings.
from scapy.layers import dhcp, dns, inet, inet6, l2  # noqa: F401

MAX_LAYERS = 16
MAX_FIELDS = 64
MAX_ITEMS = 16
MAX_DEPTH = 4
MAX_TEXT = 256


def dissect_frame(frame: bytes, *, link_type: int = 1, payload_limit: int = 64) -> dict:
    """Expose only parsed fields (not Scapy defaults), retaining unknown payloads.

    Limits apply to the extra dissection tree, not the caller's original bytes.
    Dissection is best-effort: a parsed layer is not a checksum-validity or
    protocol-conformance assertion. Unknown link types are not guessed.
    """
    decoder = conf.l2types.get(link_type)
    result: dict = {"backend": "scapy", "link_type": link_type, "layers": []}
    if decoder is None:
        result["error"] = f"unsupported capture link type {link_type}"
        return result
    clipped = [False]
    byte_limit = max(0, min(payload_limit, MAX_TEXT))

    def bounded(value, depth=0):
        if depth >= MAX_DEPTH:
            clipped[0] = True
            return {"truncated": True}
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, bytes):
            if len(value) > byte_limit:
                clipped[0] = True
            return {"hex": value[:byte_limit].hex(), "length": len(value),
                    "truncated": len(value) > byte_limit}
        if isinstance(value, str):
            if len(value) > MAX_TEXT:
                clipped[0] = True
            return value[:MAX_TEXT]
        if isinstance(value, Packet):
            return {"name": value.__class__.__name__,
                    "fields": bounded(value.fields, depth + 1)}
        if isinstance(value, dict):
            if len(value) > MAX_FIELDS:
                clipped[0] = True
            return {str(k)[:MAX_TEXT]: bounded(v, depth + 1)
                    for k, v in list(value.items())[:MAX_FIELDS]}
        if isinstance(value, (list, tuple)):
            if len(value) > MAX_ITEMS:
                clipped[0] = True
            return [bounded(v, depth + 1) for v in value[:MAX_ITEMS]]
        # Scapy flag/enum-like values have useful bounded string forms.
        text = str(value)
        if len(text) > MAX_TEXT:
            clipped[0] = True
        return text[:MAX_TEXT]

    try:
        packet = decoder(frame)
        layer = packet
        for _ in range(MAX_LAYERS):
            if isinstance(layer, NoPayload):
                break
            result["layers"].append({"name": layer.__class__.__name__,
                                     "fields": bounded(layer.fields)})
            layer = layer.payload
        if not isinstance(layer, NoPayload):
            clipped[0] = True
        result["layer_names"] = [entry["name"] for entry in result["layers"]]
        protocols = [entry["name"] for entry in result["layers"]
                     if entry["name"] not in (Raw.__name__, Padding.__name__)]
        if protocols:
            result["protocol"] = protocols[-1].lower()
    except Exception as error:
        # Dissector failures must not make raw packet evidence inaccessible.
        result["error"] = f"dissection failed: {type(error).__name__}"
    if clipped[0]:
        result["truncated"] = True
    return result
