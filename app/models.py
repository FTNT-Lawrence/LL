"""Pydantic request/response models."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class FieldMappingIn(BaseModel):
    field_name: str
    forti_attr: str = ""
    position: Optional[int] = None
    key: Optional[str] = None
    sample_values: list[str] = Field(default_factory=list)


class DetectRequest(BaseModel):
    log_text: str = ""
    vendor: str = "Generic"
    model: str = "Device"
    parser_name: str = ""


class DetectResponse(BaseModel):
    format: str
    confidence: float
    fields: list[dict[str, Any]]
    delimiter: Optional[str] = None
    has_header: bool = False
    notes: list[str] = Field(default_factory=list)
    sample_lines: list[str] = Field(default_factory=list)
    common_attributes: list[str] = Field(default_factory=list)


class GenerateRequest(BaseModel):
    log_text: str
    parser_name: str = "CustomParser"
    vendor: str = "Generic"
    model: str = "Device"
    version: str = "ANY"
    app_vendor: Optional[str] = None
    app_model: Optional[str] = None
    mappings: list[FieldMappingIn] = Field(default_factory=list)
    # optional: reuse detection overrides
    format_override: Optional[str] = None


class GenerateResponse(BaseModel):
    xml: str
    format: str
    confidence: float
    custom_attributes: list[str] = Field(default_factory=list)
    dry_run: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    parser_name: str = ""
