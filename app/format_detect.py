"""Heuristic log format detection."""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LogFormat(str, Enum):
    SYSLOG = "syslog"
    KEY_VALUE = "key_value"
    CSV = "csv"
    TSV = "tsv"
    JSON = "json"
    UNSTRUCTURED = "unstructured"


@dataclass
class DetectedField:
    name: str
    sample_values: list[str] = field(default_factory=list)
    suggested_attr: str | None = None
    position: int | None = None  # for CSV/TSV
    key: str | None = None  # original key for KV


@dataclass
class DetectionResult:
    format: LogFormat
    confidence: float
    fields: list[DetectedField]
    delimiter: str | None = None
    has_header: bool = False
    notes: list[str] = field(default_factory=list)
    sample_lines: list[str] = field(default_factory=list)


# Syslog PRI + optional header cues
_SYSLOG_PRI = re.compile(r"^<\d{1,3}>")
_SYSLOG_CISCO = re.compile(r"%[A-Z0-9_]+-\d+-[A-Z0-9_]+")
_SYSLOG_TIMESTAMP = re.compile(
    r"^(?:<\d{1,3}>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})"
)
_KV_PAIR = re.compile(
    r'(?:^|[\s,;|])([A-Za-z_][\w.-]*)\s*[=:]\s*(?:"[^"]*"|\'[^\']*\'|[^\s,;|]+)'
)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Distinctive key=value keys that indicate structured firewall/NGFW logs
# (Sangfor NGAF and similar) even when wrapped in a syslog PRI/header.
_DISTINCTIVE_KV_KEYS = {
    "log_id",
    "fw_name",
    "src_ip",
    "dst_ip",
    "dest_ip",
    "src_port",
    "dst_port",
    "vdom",
    "policy_id",
    "policyid",
    "session_id",
}


def _nonempty_lines(text: str, limit: int = 50) -> list[str]:
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s:
            lines.append(s)
        if len(lines) >= limit:
            break
    return lines


def _score_json(lines: list[str]) -> tuple[float, list[dict[str, Any]]]:
    objs: list[dict[str, Any]] = []
    ok = 0
    for line in lines:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                objs.append(obj)
                ok += 1
            elif isinstance(obj, list) and line == lines[0] and len(lines) == 1:
                # single JSON array of objects
                for item in obj:
                    if isinstance(item, dict):
                        objs.append(item)
                ok += 1
        except (json.JSONDecodeError, TypeError):
            # try whole-text later
            pass
    if not objs and lines:
        try:
            blob = "\n".join(lines)
            obj = json.loads(blob)
            if isinstance(obj, dict):
                objs = [obj]
                ok = 1
            elif isinstance(obj, list):
                objs = [x for x in obj if isinstance(x, dict)]
                ok = 1 if objs else 0
        except (json.JSONDecodeError, TypeError):
            pass
    if not lines:
        return 0.0, []
    return ok / max(len(lines), 1), objs


def _score_kv(lines: list[str]) -> float:
    if not lines:
        return 0.0
    hits = 0
    for line in lines:
        pairs = _KV_PAIR.findall(line)
        if len(pairs) >= 2:
            hits += 1
    return hits / len(lines)


def _score_syslog(lines: list[str]) -> float:
    if not lines:
        return 0.0
    hits = 0
    for line in lines:
        score = 0
        if _SYSLOG_PRI.search(line):
            score += 1
        if _SYSLOG_CISCO.search(line):
            score += 2
        if _SYSLOG_TIMESTAMP.search(line):
            score += 1
        if score >= 1:
            hits += 1
    return hits / len(lines)


def _detect_delimited(lines: list[str]) -> tuple[LogFormat | None, float, str, bool]:
    """Return format, confidence, delimiter, has_header for CSV/TSV."""
    if not lines:
        return None, 0.0, "", False

    candidates = [
        (LogFormat.TSV, "\t"),
        (LogFormat.CSV, ","),
        (LogFormat.CSV, ";"),
        (LogFormat.CSV, "|"),
    ]
    best: tuple[LogFormat | None, float, str, bool] = (None, 0.0, "", False)

    for fmt, delim in candidates:
        counts = []
        for line in lines[:20]:
            # avoid counting commas inside quotes roughly
            if delim == ",":
                try:
                    row = next(csv.reader([line], delimiter=","))
                    counts.append(len(row))
                except Exception:
                    counts.append(line.count(delim) + 1)
            else:
                counts.append(line.count(delim) + 1)
        if not counts or max(counts) < 2:
            continue
        # consistency of column count
        mode = max(set(counts), key=counts.count)
        consistency = counts.count(mode) / len(counts)
        if mode < 2 or consistency < 0.7:
            continue
        conf = consistency * (0.9 if delim == "\t" else 0.75)
        # header heuristic
        first = lines[0]
        if delim == ",":
            try:
                cells = next(csv.reader([first], delimiter=","))
            except Exception:
                cells = first.split(delim)
        else:
            cells = first.split(delim)
        has_header = _looks_like_header(cells)
        if conf > best[1]:
            best = (fmt if delim != ";" and delim != "|" else LogFormat.CSV, conf, delim, has_header)
    return best


def _looks_like_header(cells: list[str]) -> bool:
    if not cells:
        return False
    alpha = 0
    for c in cells:
        t = c.strip().strip('"').strip("'")
        if not t:
            continue
        if re.match(r"^[A-Za-z_][\w.\-]*$", t) and not _IP.search(t) and not t.isdigit():
            alpha += 1
    return alpha >= max(2, len(cells) // 2)


def _kv_keys_in_line(line: str) -> list[str]:
    """Return key names from key=value pairs in a line."""
    return re.findall(
        r'([A-Za-z_][\w.-]*)\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s,;|]+)',
        line,
    )


def _has_syslog_header(line: str) -> bool:
    return bool(_SYSLOG_PRI.search(line) or _SYSLOG_TIMESTAMP.search(line))


def _is_hybrid_syslog_kv(lines: list[str]) -> bool:
    """
    True when logs look like syslog PRI/header + key=value body (e.g. Sangfor NGAF)
    and do NOT contain Cisco %FAC-SEV-MSG. Prefer KEY_VALUE classification for these.
    """
    if not lines:
        return False
    if any(_SYSLOG_CISCO.search(l) for l in lines):
        return False
    hybrid_hits = 0
    for line in lines:
        if not _has_syslog_header(line):
            continue
        keys = _kv_keys_in_line(line)
        if len(keys) < 2:
            continue
        keyset = {k.lower() for k in keys}
        if keyset & _DISTINCTIVE_KV_KEYS or len(keys) >= 3:
            hybrid_hits += 1
    return hybrid_hits >= max(1, (len(lines) + 1) // 2)


def detect_format(text: str) -> DetectionResult:
    """Detect log format and extract candidate fields with sample values."""
    from .attributes import suggest_attribute

    lines = _nonempty_lines(text)
    if not lines:
        return DetectionResult(
            format=LogFormat.UNSTRUCTURED,
            confidence=0.0,
            fields=[],
            notes=["No non-empty lines provided."],
        )

    json_score, json_objs = _score_json(lines)
    kv_score = _score_kv(lines)
    syslog_score = _score_syslog(lines)
    delim_fmt, delim_score, delimiter, has_header = _detect_delimited(lines)

    scores: dict[LogFormat, float] = {
        LogFormat.JSON: json_score,
        LogFormat.KEY_VALUE: kv_score * 0.95,
        LogFormat.SYSLOG: syslog_score * 0.9,
        LogFormat.UNSTRUCTURED: 0.15,
    }
    if delim_fmt == LogFormat.TSV:
        scores[LogFormat.TSV] = delim_score
    elif delim_fmt == LogFormat.CSV:
        scores[LogFormat.CSV] = delim_score

    # Prefer KEY_VALUE for syslog-header + key=value body (Sangfor NGAF, etc.)
    # when there is no Cisco %FAC-SEV-MSG — do NOT default those to Cisco syslog.
    hybrid_kv = _is_hybrid_syslog_kv(lines)
    if hybrid_kv and kv_score >= 0.5:
        scores[LogFormat.KEY_VALUE] = max(scores[LogFormat.KEY_VALUE], 0.98)
        scores[LogFormat.SYSLOG] = min(scores[LogFormat.SYSLOG], 0.4)
    # Prefer syslog over KV only when Cisco-like signatures present
    elif syslog_score >= 0.6 and any(_SYSLOG_CISCO.search(l) for l in lines):
        scores[LogFormat.SYSLOG] = max(scores[LogFormat.SYSLOG], 0.95)

    best_fmt = max(scores, key=lambda k: scores[k])
    confidence = scores[best_fmt]

    fields: list[DetectedField] = []
    notes: list[str] = []

    if best_fmt == LogFormat.JSON and json_objs:
        fields = _fields_from_json(json_objs, suggest_attribute)
        notes.append(f"Detected JSON objects across {len(json_objs)} sample(s).")
    elif best_fmt in (LogFormat.CSV, LogFormat.TSV) and delimiter:
        fields = _fields_from_delimited(lines, delimiter, has_header, suggest_attribute)
        notes.append(
            f"Detected {'TSV' if best_fmt == LogFormat.TSV else 'CSV'} "
            f"with delimiter {repr(delimiter)}; header={'yes' if has_header else 'no'}."
        )
    elif best_fmt == LogFormat.KEY_VALUE:
        fields = _fields_from_kv(lines, suggest_attribute)
        if hybrid_kv:
            notes.append(
                "Detected hybrid syslog header + key=value body "
                "(prefer KEY_VALUE over Cisco syslog; no %FAC-SEV-MSG)."
            )
        else:
            notes.append("Detected key=value structured logs.")
    elif best_fmt == LogFormat.SYSLOG:
        fields = _fields_from_syslog(lines, suggest_attribute)
        notes.append("Detected syslog-like messages (PRI / Cisco facility pattern).")
    else:
        fields = _fields_from_unstructured(lines, suggest_attribute)
        notes.append("Fell back to unstructured token heuristics.")

    return DetectionResult(
        format=best_fmt,
        confidence=round(confidence, 3),
        fields=fields,
        delimiter=delimiter if best_fmt in (LogFormat.CSV, LogFormat.TSV) else None,
        has_header=has_header if best_fmt in (LogFormat.CSV, LogFormat.TSV) else False,
        notes=notes,
        sample_lines=lines[:10],
    )


def _fields_from_json(objs: list[dict[str, Any]], suggest) -> list[DetectedField]:
    samples: dict[str, list[str]] = {}
    for obj in objs[:20]:
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                val = json.dumps(v, ensure_ascii=False)[:120]
            else:
                val = "" if v is None else str(v)
            samples.setdefault(str(k), [])
            if val and val not in samples[str(k)] and len(samples[str(k)]) < 5:
                samples[str(k)].append(val)
    fields = []
    for name, vals in samples.items():
        fields.append(
            DetectedField(
                name=name,
                sample_values=vals,
                suggested_attr=suggest(name),
                key=name,
            )
        )
    return fields


def _fields_from_delimited(lines, delimiter, has_header, suggest) -> list[DetectedField]:
    rows = []
    for line in lines[:30]:
        if delimiter == ",":
            try:
                rows.append(next(csv.reader([line], delimiter=",")))
            except Exception:
                rows.append(line.split(delimiter))
        else:
            rows.append(line.split(delimiter))
    if not rows:
        return []
    ncol = max(len(r) for r in rows)
    if has_header:
        headers = [(c.strip().strip('"').strip("'") or f"col{i}") for i, c in enumerate(rows[0])]
        data_rows = rows[1:]
    else:
        headers = [f"col{i}" for i in range(ncol)]
        data_rows = rows
    # pad headers
    while len(headers) < ncol:
        headers.append(f"col{len(headers)}")
    fields = []
    for i, name in enumerate(headers):
        vals = []
        for r in data_rows:
            if i < len(r):
                v = r[i].strip().strip('"')
                if v and v not in vals and len(vals) < 5:
                    vals.append(v)
        fields.append(
            DetectedField(
                name=name,
                sample_values=vals,
                suggested_attr=suggest(name),
                position=i + 1,  # 1-based for FortiSIEM collectAndSetAttrByPos
            )
        )
    return fields


def _fields_from_kv(lines, suggest) -> list[DetectedField]:
    samples: dict[str, list[str]] = {}
    for line in lines[:30]:
        for m in re.finditer(
            r'([A-Za-z_][\w.-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s,;|]+))',
            line,
        ):
            key = m.group(1)
            val = m.group(2) or m.group(3) or m.group(4) or ""
            samples.setdefault(key, [])
            if val and val not in samples[key] and len(samples[key]) < 5:
                samples[key].append(val)
    fields = []
    for name, vals in samples.items():
        fields.append(
            DetectedField(
                name=name,
                sample_values=vals,
                suggested_attr=suggest(name),
                key=name,
            )
        )
    return fields


def _fields_from_syslog(lines, suggest) -> list[DetectedField]:
    """Extract common syslog / Cisco ACL style fields via regexes."""
    fields_map: dict[str, DetectedField] = {}

    def add(name: str, val: str, suggested: str | None = None):
        if name not in fields_map:
            fields_map[name] = DetectedField(
                name=name,
                sample_values=[],
                suggested_attr=suggested or suggest(name),
            )
        if val and val not in fields_map[name].sample_values and len(fields_map[name].sample_values) < 5:
            fields_map[name].sample_values.append(val)

    cisco_body = re.compile(
        r"%([A-Z0-9_]+)-(\d+)-([A-Z0-9_]+):\s*(.*)$"
    )
    acl = re.compile(
        r"list\s+(\S+)\s+(permitted|denied|permit|deny)\s+(\w+)\s+"
        r"([\d.]+)\((\d+)\)\s*->\s*([\d.]+)\((\d+)\),\s*(\d+)\s+packet",
        re.I,
    )
    host_re = re.compile(
        r"(?:<\d{1,3}>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\S+)"
    )
    time_re = re.compile(
        r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    )

    for line in lines[:30]:
        tm = time_re.search(line)
        if tm:
            add("deviceTime", tm.group(1), "deviceTime")
        hm = host_re.search(line)
        if hm:
            # avoid treating %FACILITY as host
            h = hm.group(1)
            if not h.startswith("%"):
                add("hostName", h, "hostName")
        cm = cisco_body.search(line)
        if cm:
            add("_evIdPrefix", cm.group(1))
            add("eventSeverity", cm.group(2), "eventSeverity")
            add("_evIdSuffix", cm.group(3))
            add("eventType", f"{cm.group(1)}-{cm.group(3)}", "eventType")
            body = cm.group(4)
            add("msg", body[:80], "msg")
            am = acl.search(body)
            if am:
                add("_aclName", am.group(1))
                add("_action", am.group(2))
                add("_proto", am.group(3))
                add("srcIpAddr", am.group(4), "srcIpAddr")
                add("srcIpPort", am.group(5), "srcIpPort")
                add("destIpAddr", am.group(6), "destIpAddr")
                add("destIpPort", am.group(7), "destIpPort")
                add("totPkts", am.group(8), "totPkts")
                add("ipProto", am.group(3), "ipProto")
        else:
            # generic IPs / ports in message
            ips = _IP.findall(line)
            if len(ips) >= 1:
                add("srcIpAddr", ips[0], "srcIpAddr")
            if len(ips) >= 2:
                add("destIpAddr", ips[1], "destIpAddr")
            # also pick KV pairs embedded in syslog
            for m in re.finditer(
                r'([A-Za-z_][\w.-]*)=([^\s,;]+)',
                line,
            ):
                add(m.group(1), m.group(2), suggest(m.group(1)))

    return list(fields_map.values())


def _fields_from_unstructured(lines, suggest) -> list[DetectedField]:
    fields_map: dict[str, DetectedField] = {}

    def add(name, val, suggested=None):
        if name not in fields_map:
            fields_map[name] = DetectedField(
                name=name, sample_values=[], suggested_attr=suggested or suggest(name)
            )
        if val and val not in fields_map[name].sample_values and len(fields_map[name].sample_values) < 5:
            fields_map[name].sample_values.append(val)

    for line in lines[:20]:
        ips = _IP.findall(line)
        if ips:
            add("srcIpAddr", ips[0], "srcIpAddr")
        if len(ips) > 1:
            add("destIpAddr", ips[1], "destIpAddr")
        emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", line)
        if emails:
            add("user", emails[0].split("@")[0], "user")
        add("msg", line[:100], "msg")
    return list(fields_map.values())
