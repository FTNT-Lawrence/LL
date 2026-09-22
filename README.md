# FortiSIEM Parser Generator

Upload third-party security event logs and **auto-generate FortiSIEM custom parser XML** using rule-based heuristics (no paid LLM required).

支援上傳 / 貼上 log → 自動偵測格式 → 對應 FortiSIEM attributes → 下載完整 parser XML。

## Stack

- **Backend:** Python 3 + FastAPI
- **Frontend:** Vanilla HTML / CSS / JS (dark/light wizard UI), served by FastAPI
- **Generator:** Heuristic format detection + FortiSIEM XML constructs

## Install & run

```bash
cd fortisiem-parser-generator
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run the app
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open **http://127.0.0.1:8000**

### Tests

```bash
pytest -q
```

## How to use the UI

1. **Upload** — Drag & drop a `.log` / `.txt` / `.csv` file, paste samples, or click a built-in sample (Cisco ACL / key=value / CSV).
2. **Metadata** — Set Vendor, Product/Model, Parser name (optional App type).
3. **Map fields** — Review detected fields + sample values; map to FortiSIEM attributes (dropdown + custom text).
4. **Preview** — Syntax-highlighted XML, dry-run extraction table, notes for custom Event Attributes → **Download .xml**.

## Supported formats

| Format | Detection cues | XML constructs used |
|--------|----------------|---------------------|
| Syslog / Cisco-like | PRI, `%FAC-SEV-MSG` | `collectFieldsByRegex`, `collectAndSetAttrByRegex`, `choose`, `combineMsgId`, `convertStrToIntIpProto`, `toDateTime` |
| Key=value | `key=value` pairs | `collectAndSetAttrByKeyValuePair` |
| CSV / TSV | Delimiters + header | `collectAndSetAttrByPos` |
| JSON | JSON objects / lines | Per-field `collectAndSetAttrByRegex` |
| Unstructured | Fallback tokens | Best-effort regex |

## Import into FortiSIEM

**Prerequisites** (create before enabling the parser if they don’t exist):

1. **Device / App Types** — Admin → Device Support → Device/App Types  
2. **Event Attributes** — any *custom* attributes listed in the Notes panel  
3. **Event Types** — matching `eventType` values your parser emits  

**Import parser:**

1. Admin → Device Support → **Parsers**
2. Prefer **Import**, or **New** and paste the XML
3. Select matching Device Type, paste a **Test Event**, **Validate** + **Test**
4. **Enable**, **Save**, then **Apply**
5. Check parser order (custom parsers usually sit below system ones; use Fix Order carefully)

Official refs:

- [Parsing Instructions (FortiSIEM 7.6)](https://docs.fortinet.com/document/fortisiem/7.6.0/user-guide/229719/parsing-instructions)
- [Custom Parsers overview](https://www.fortinetguru.com/2017/05/fortisiem-custom-parsers/)

## Project layout

```
app/
  main.py            # FastAPI routes
  format_detect.py   # Format detection
  xml_generator.py   # FortiSIEM XML generation
  dry_run.py         # Best-effort dry-run
  attributes.py      # Common attr catalog + aliases
  models.py          # Request/response schemas
static/              # Wizard UI
samples/             # Example logs
tests/               # pytest
```

## Caveats

- Dry-run is a **Python approximation** of FortiSIEM’s engine — always Validate/Test inside FortiSIEM.
- Global patterns like `gPatMon` exist on the appliance; this generator also ships local `pat*` definitions for portability.
- JSON support is pragmatic (regex extraction), not a full JSON DOM parser inside FortiSIEM.
- Always review generated `eventType` / severity mapping before production enablement.
