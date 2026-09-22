"""Best-effort dry-run: apply the same heuristics used for generation to sample lines."""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from .format_detect import DetectionResult, LogFormat
from .xml_generator import FieldMapping, ParserMeta

_IP = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_CISCO = re.compile(
    r"%([A-Z0-9_]+)-(\d+)-([A-Z0-9_]+):\s*(.*)$"
)
_ACL = re.compile(
    r"list\s+(\S+)\s+(permitted|denied|permit|deny)\s+(\w+)\s+"
    r"([\d.]+)\((\d+)\)\s*->\s*([\d.]+)\((\d+)\),\s*(\d+)\s+packet",
    re.I,
)
_KV = re.compile(
    r'([A-Za-z_][\w.-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s,;|]+))'
)
_PROTO = {"tcp": "6", "udp": "17", "icmp": "1", "gre": "47", "esp": "50", "ah": "51"}


def dry_run_lines(
    lines: list[str],
    detection: DetectionResult,
    mappings: list[FieldMapping],
    meta: ParserMeta,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return list of {raw, attrs} for each sample line."""
    results = []
    active = [m for m in mappings if m.forti_attr and m.forti_attr.strip()]
    for line in lines[:limit]:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        attrs = _parse_one(line, detection, active, meta)
        results.append({"raw": line, "attrs": attrs})
    return results


def _parse_one(
    line: str,
    detection: DetectionResult,
    mappings: list[FieldMapping],
    meta: ParserMeta,
) -> dict[str, str]:
    fmt = detection.format
    if fmt == LogFormat.JSON:
        return _parse_json(line, mappings, meta)
    if fmt == LogFormat.KEY_VALUE:
        return _parse_kv(line, mappings, meta)
    if fmt in (LogFormat.CSV, LogFormat.TSV):
        return _parse_delimited(line, detection, mappings, meta)
    if fmt == LogFormat.SYSLOG:
        return _parse_syslog(line, mappings, meta)
    return _parse_unstructured(line, mappings, meta)


def _defaults(meta: ParserMeta) -> dict[str, str]:
    return {
        "eventType": f"{meta.vendor.upper()}-{meta.model.upper()}-EVENT",
        "eventSeverity": "5",
    }


def _apply_proto(attrs: dict[str, str]) -> None:
    if "ipProto" in attrs and attrs["ipProto"].lower() in _PROTO:
        attrs["ipProto"] = _PROTO[attrs["ipProto"].lower()]


def _parse_kv(line: str, mappings: list[FieldMapping], meta: ParserMeta) -> dict[str, str]:
    attrs = _defaults(meta)
    kv = {}
    for m in _KV.finditer(line):
        kv[m.group(1)] = m.group(2) or m.group(3) or m.group(4) or ""
    for mp in mappings:
        key = mp.key or mp.field_name
        if key in kv:
            attrs[mp.forti_attr] = kv[key]
    _apply_proto(attrs)
    if "msg" not in attrs:
        attrs["msg"] = line
    return attrs


def _parse_delimited(
    line: str, detection: DetectionResult, mappings: list[FieldMapping], meta: ParserMeta
) -> dict[str, str]:
    attrs = _defaults(meta)
    delim = detection.delimiter or ","
    if detection.has_header and detection.sample_lines and line == detection.sample_lines[0]:
        attrs["_note"] = "header row skipped"
        return attrs
    if delim == ",":
        try:
            cells = next(csv.reader([line], delimiter=","))
        except Exception:
            cells = line.split(delim)
    else:
        cells = line.split(delim)
    for mp in mappings:
        if mp.position is None:
            continue
        idx = mp.position - 1
        if 0 <= idx < len(cells):
            attrs[mp.forti_attr] = cells[idx].strip().strip('"')
    _apply_proto(attrs)
    return attrs


def _parse_json(line: str, mappings: list[FieldMapping], meta: ParserMeta) -> dict[str, str]:
    attrs = _defaults(meta)
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        attrs["msg"] = line
        return attrs
    if not isinstance(obj, dict):
        attrs["msg"] = line
        return attrs
    for mp in mappings:
        key = mp.key or mp.field_name
        if key in obj:
            v = obj[key]
            attrs[mp.forti_attr] = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    _apply_proto(attrs)
    if "msg" not in attrs:
        attrs["msg"] = line
    return attrs


def _parse_syslog(line: str, mappings: list[FieldMapping], meta: ParserMeta) -> dict[str, str]:
    attrs = _defaults(meta)
    vendor_u = meta.vendor.upper() or "DEV"
    cm = _CISCO.search(line)
    if cm:
        prefix, sev, suffix, body = cm.group(1), cm.group(2), cm.group(3), cm.group(4)
        attrs["eventType"] = f"{vendor_u}-{prefix}-{suffix}"
        try:
            s = int(sev)
            attrs["eventSeverity"] = "9" if s <= 2 else "7" if s <= 4 else "5" if s == 5 else "3"
        except ValueError:
            attrs["eventSeverity"] = sev
        attrs["msg"] = body
        am = _ACL.search(body)
        if am:
            attrs["_aclName"] = am.group(1)
            attrs["_action"] = am.group(2)
            attrs["_proto"] = am.group(3)
            attrs["srcIpAddr"] = am.group(4)
            attrs["srcIpPort"] = am.group(5)
            attrs["destIpAddr"] = am.group(6)
            attrs["destIpPort"] = am.group(7)
            attrs["totPkts"] = am.group(8)
            action = am.group(2).lower()
            if action in ("permitted", "permit"):
                attrs["eventType"] = f"{vendor_u}-{prefix}-{suffix}-PERMITTED"
                attrs["eventSeverity"] = "1"
            elif action in ("denied", "deny"):
                attrs["eventType"] = f"{vendor_u}-{prefix}-{suffix}-DENIED"
                attrs["eventSeverity"] = "3"
            attrs["ipProto"] = _PROTO.get(am.group(3).lower(), am.group(3))
        # time
        tm = re.search(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)", line)
        if tm:
            attrs["deviceTime"] = tm.group(1)
    else:
        ips = _IP.findall(line)
        if ips:
            attrs["srcIpAddr"] = ips[0]
        if len(ips) > 1:
            attrs["destIpAddr"] = ips[1]
        attrs["msg"] = line
        # kv overlay
        kv = {m.group(1): (m.group(2) or m.group(3) or m.group(4) or "") for m in _KV.finditer(line)}
        for mp in mappings:
            key = mp.key or mp.field_name
            if key in kv:
                attrs[mp.forti_attr] = kv[key]

    # honor explicit mappings for fields we may have under original names
    return attrs


def _parse_unstructured(line: str, mappings: list[FieldMapping], meta: ParserMeta) -> dict[str, str]:
    attrs = _defaults(meta)
    ips = _IP.findall(line)
    ip_i = 0
    for mp in mappings:
        attr = mp.forti_attr
        if attr in ("srcIpAddr", "destIpAddr") and ip_i < len(ips):
            attrs[attr] = ips[ip_i]
            ip_i += 1
        elif mp.sample_values and mp.sample_values[0] in line:
            attrs[attr] = mp.sample_values[0]
    attrs.setdefault("msg", line)
    return attrs
