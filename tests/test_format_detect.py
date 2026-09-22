"""Unit tests for format detection."""

from pathlib import Path

from app.format_detect import LogFormat, detect_format

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_detect_cisco_syslog():
    text = (SAMPLES / "cisco_acl_syslog.log").read_text()
    result = detect_format(text)
    assert result.format == LogFormat.SYSLOG
    assert result.confidence >= 0.6
    names = {f.name for f in result.fields}
    assert "srcIpAddr" in names or any(f.suggested_attr == "srcIpAddr" for f in result.fields)
    assert any(f.suggested_attr == "destIpAddr" for f in result.fields) or "destIpAddr" in names


def test_detect_key_value():
    text = (SAMPLES / "firewall_keyvalue.log").read_text()
    result = detect_format(text)
    assert result.format == LogFormat.KEY_VALUE
    assert result.confidence >= 0.6
    names = {f.name.lower() for f in result.fields}
    assert "src" in names or "dst" in names
    assert any(f.suggested_attr == "srcIpAddr" for f in result.fields)


def test_detect_csv():
    text = (SAMPLES / "app_csv.log").read_text()
    result = detect_format(text)
    assert result.format == LogFormat.CSV
    assert result.has_header is True
    assert result.delimiter == ","
    names = {f.name for f in result.fields}
    assert "src_ip" in names
    assert any(f.suggested_attr == "srcIpAddr" for f in result.fields)


def test_detect_json_lines():
    text = "\n".join(
        [
            '{"src":"10.0.0.1","dst":"10.0.0.2","action":"allow"}',
            '{"src":"10.0.0.3","dst":"10.0.0.4","action":"deny"}',
        ]
    )
    result = detect_format(text)
    assert result.format == LogFormat.JSON
    assert any(f.name == "src" for f in result.fields)


def test_empty_input():
    result = detect_format("   \n  ")
    assert result.format == LogFormat.UNSTRUCTURED
    assert result.confidence == 0.0
