"""FortiSIEM Parser Generator — FastAPI application."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from .attributes import COMMON_ATTRIBUTES
from .dry_run import dry_run_lines
from .format_detect import DetectionResult, LogFormat, detect_format
from .models import DetectRequest, DetectResponse, FieldMappingIn, GenerateRequest, GenerateResponse
from .xml_generator import FieldMapping, ParserMeta, generate_parser_xml

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"

app = FastAPI(
    title="FortiSIEM Parser Generator",
    description="Upload third-party logs and generate FortiSIEM custom parser XML.",
    version="1.0.0",
)

if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    index_path = STATIC / "index.html"
    if not index_path.exists():
        raise HTTPException(404, "Frontend not found")
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


@app.get("/api/attributes")
async def list_attributes():
    return {"attributes": COMMON_ATTRIBUTES}


@app.post("/api/detect", response_model=DetectResponse)
async def api_detect(body: DetectRequest):
    text = body.log_text or ""
    if not text.strip():
        raise HTTPException(400, "log_text is empty")
    result = detect_format(text)
    return _detection_to_response(result)


@app.post("/api/detect-upload", response_model=DetectResponse)
async def api_detect_upload(
    file: UploadFile = File(...),
    vendor: str = Form("Generic"),
    model: str = Form("Device"),
    parser_name: str = Form(""),
):
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    if not text.strip():
        raise HTTPException(400, "Uploaded file is empty")
    result = detect_format(text)
    return _detection_to_response(result)


@app.post("/api/generate", response_model=GenerateResponse)
async def api_generate(body: GenerateRequest):
    text = body.log_text or ""
    if not text.strip():
        raise HTTPException(400, "log_text is empty")

    detection = detect_format(text)
    if body.format_override:
        try:
            detection.format = LogFormat(body.format_override)
        except ValueError:
            pass

    meta = ParserMeta(
        parser_name=body.parser_name or f"{body.vendor}{body.model}Parser",
        vendor=body.vendor or "Generic",
        model=body.model or "Device",
        version=body.version or "ANY",
        app_vendor=body.app_vendor,
        app_model=body.app_model,
    )
    mappings = [
        FieldMapping(
            field_name=m.field_name,
            forti_attr=m.forti_attr,
            position=m.position,
            key=m.key,
            sample_values=list(m.sample_values or []),
        )
        for m in body.mappings
    ]
    # If no mappings provided, auto-map from detection suggestions
    if not mappings:
        mappings = [
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

    xml, custom_attrs = generate_parser_xml(meta, detection, mappings)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    # skip header for CSV dry-run display of data rows preference handled inside
    dry = dry_run_lines(lines, detection, mappings, meta)

    notes = list(detection.notes)
    if custom_attrs:
        notes.append(
            "Suggested custom Event Attributes to create in FortiSIEM: "
            + ", ".join(custom_attrs)
        )
    notes.append(
        "Import path: Admin > Device Support > Parsers. "
        "Ensure Device/App Types, Event Attributes, and Event Types exist first."
    )

    return GenerateResponse(
        xml=xml,
        format=detection.format.value,
        confidence=detection.confidence,
        custom_attributes=custom_attrs,
        dry_run=dry,
        notes=notes,
        parser_name=meta.parser_name,
    )


@app.post("/api/download")
async def api_download(body: GenerateRequest):
    gen = await api_generate(body)
    filename = f"{gen.parser_name or 'CustomParser'}.xml"
    return Response(
        content=gen.xml,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _detection_to_response(result: DetectionResult) -> DetectResponse:
    fields = []
    for f in result.fields:
        fields.append(
            {
                "name": f.name,
                "sample_values": f.sample_values,
                "suggested_attr": f.suggested_attr,
                "position": f.position,
                "key": f.key,
            }
        )
    return DetectResponse(
        format=result.format.value,
        confidence=result.confidence,
        fields=fields,
        delimiter=result.delimiter,
        has_header=result.has_header,
        notes=result.notes,
        sample_lines=result.sample_lines,
        common_attributes=COMMON_ATTRIBUTES,
    )


def create_app() -> FastAPI:
    return app
