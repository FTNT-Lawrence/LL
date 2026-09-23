"""End-to-end generate path tests."""

from pathlib import Path

from app.dry_run import dry_run_lines
from app.format_detect import LogFormat, detect_format
from app.xml_generator import FieldMapping, ParserMeta, generate_parser_xml

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _auto_mappings(detection):
    return [
        FieldMapping(
            field_name=f.name,
            forti_attr=f.suggested_attr or "",
            position=f.position,
            key=f.key,
            sample_values=list(f.sample_values),
        )
        for f in detection.fields
        if f.suggested_attr
    ]


def test_e2e_cisco_syslog_xml():
    text = (SAMPLES / "cisco_acl_syslog.log").read_text()
    detection = detect_format(text)
    assert detection.format == LogFormat.SYSLOG
    meta = ParserMeta(parser_name="CiscoIOSCustomParser", vendor="Cisco", model="IOS")
    mappings = _auto_mappings(detection)
    xml, custom = generate_parser_xml(meta, detection, mappings)

    assert '<?xml version="1.0"' in xml
    assert '<eventParser name="CiscoIOSCustomParser">' in xml
    assert "<Vendor>Cisco</Vendor>" in xml
    assert "<Model>IOS</Model>" in xml
    assert "<eventFormatRecognizer>" in xml
    assert "<patternDefinitions>" in xml
    assert "<parsingInstructions>" in xml
    assert "collectFieldsByRegex" in xml or "collectAndSetAttrByRegex" in xml
    assert "combineMsgId" in xml
    assert "convertStrToIntIpProto" in xml
    assert "toDateTime" in xml
    assert "<choose>" in xml
    assert xml.strip().endswith("</eventParser>")

    dry = dry_run_lines(text.splitlines(), detection, mappings, meta)
    assert len(dry) >= 2
    first = dry[0]["attrs"]
    assert "srcIpAddr" in first
    assert first["srcIpAddr"] == "192.168.20.33"
    assert "destIpAddr" in first
    assert "PERMITTED" in first.get("eventType", "") or first.get("eventType")


def test_e2e_keyvalue_xml():
    text = (SAMPLES / "firewall_keyvalue.log").read_text()
    detection = detect_format(text)
    meta = ParserMeta(parser_name="AcmeFWParser", vendor="Acme", model="Firewall")
    mappings = _auto_mappings(detection)
    xml, _ = generate_parser_xml(meta, detection, mappings)
    assert "collectAndSetAttrByKeyValuePair" in xml
    assert "attrKeyMap" in xml
    dry = dry_run_lines(text.splitlines(), detection, mappings, meta)
    assert dry[0]["attrs"].get("srcIpAddr") == "10.0.0.15"


def test_e2e_csv_xml():
    text = (SAMPLES / "app_csv.log").read_text()
    detection = detect_format(text)
    meta = ParserMeta(parser_name="AppCsvParser", vendor="Contoso", model="AppLog")
    mappings = _auto_mappings(detection)
    xml, _ = generate_parser_xml(meta, detection, mappings)
    assert "collectAndSetAttrByPos" in xml
    assert "attrPosMap" in xml
    dry = dry_run_lines(text.splitlines(), detection, mappings, meta)
    # first data row after header
    data_rows = [r for r in dry if r["attrs"].get("_note") != "header row skipped"]
    assert data_rows
    assert data_rows[0]["attrs"].get("srcIpAddr") == "10.0.0.15"


def test_api_generate(client=None):
    """Optional FastAPI test via httpx TestClient."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    text = (SAMPLES / "firewall_keyvalue.log").read_text()
    # detect
    r = client.post("/api/detect", json={"log_text": text})
    assert r.status_code == 200
    det = r.json()
    assert det["format"] == "key_value"
    mappings = [
        {
            "field_name": f["name"],
            "forti_attr": f["suggested_attr"] or "",
            "position": f.get("position"),
            "key": f.get("key"),
            "sample_values": f.get("sample_values") or [],
        }
        for f in det["fields"]
        if f.get("suggested_attr")
    ]
    r2 = client.post(
        "/api/generate",
        json={
            "log_text": text,
            "parser_name": "AcmeFWParser",
            "vendor": "Acme",
            "model": "Firewall",
            "mappings": mappings,
        },
    )
    assert r2.status_code == 200
    body = r2.json()
    assert "<eventParser" in body["xml"]
    assert body["dry_run"]


def test_e2e_sangfor_hybrid_xml():
    text = (SAMPLES / "sangfor_ngaf.log").read_text()
    detection = detect_format(text)
    assert detection.format == LogFormat.KEY_VALUE
    meta = ParserMeta(
        parser_name="Sangfor_Firewall",
        vendor="Sangfor",
        model="NGAF",
    )
    # Explicit mappings covering recognizer + common Sangfor fields
    name_to_field = {f.name: f for f in detection.fields}
    mapping_spec = [
        ("log_id", "log_id"),
        ("time", "deviceTime"),
        ("fw_name", "hostName"),
        ("vdom", "vdom"),
        ("src_ip", "srcIpAddr"),
        ("dst_ip", "destIpAddr"),
        ("src_port", "srcIpPort"),
        ("dst_port", "destIpPort"),
        ("proto", "ipProto"),
        ("action", "action"),
        ("policy_id", "policy_id"),
        ("session_id", "session_id"),
        ("user", "user"),
        ("msg", "msg"),
    ]
    mappings = []
    for key, attr in mapping_spec:
        f = name_to_field.get(key)
        if not f:
            continue
        mappings.append(
            FieldMapping(
                field_name=f.name,
                forti_attr=attr,
                key=f.key or f.name,
                sample_values=list(f.sample_values),
            )
        )
    xml, custom = generate_parser_xml(meta, detection, mappings)
    assert '<eventParser name="Sangfor_Firewall">' in xml
    assert "<Vendor>Sangfor</Vendor>" in xml
    assert "collectAndSetAttrByKeyValuePair" in xml
    assert "attrKeyMap" in xml
    # Recognizer must use distinctive Sangfor keys, not bare PRI / Cisco
    import re as _re
    m = _re.search(
        r"<eventFormatRecognizer>\s*<pattern><!\[CDATA\[(.*?)\]\]></pattern>",
        xml,
        _re.S,
    )
    assert m, "missing eventFormatRecognizer"
    recog = m.group(1)
    assert "fw_name=" in recog or "log_id=" in recog
    assert recog.strip() != r"<\d{1,3}>"
    assert "%[A-Z0-9_]+" not in recog
    assert "srcIpAddr" in xml and 'key="src_ip"' in xml
    assert 'key="fw_name"' in xml
