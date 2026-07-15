"""Pydantic schemas for findings."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class FindingCreate(BaseModel):
    """Schema for creating a new finding from a sensor."""
    source: Literal["sonarqube", "zap"] = Field(
        ..., description="Origin sensor: 'sonarqube' for SAST, 'zap' for DAST"
    )
    raw_payload: dict = Field(
        ..., description="Unmodified finding data from the sensor"
    )


class FindingResponse(BaseModel):
    """Schema returned when querying findings."""
    id: UUID
    source: str
    raw_payload: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class SimulatedFinding(BaseModel):
    """
    A convenience schema for the /analyze-finding endpoint.
    Accepts either a raw payload or pre-structured simulated data
    for quick testing without real sensors.
    """
    source: Literal["sonarqube", "zap"] = Field(
        ..., description="Which sensor this simulates"
    )
    raw_payload: dict = Field(
        ..., description="Simulated finding payload"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "source": "sonarqube",
                    "raw_payload": {
                        "key": "AYz1234",
                        "rule": "python:S5131",
                        "severity": "CRITICAL",
                        "component": "src/api/auth.py",
                        "line": 42,
                        "message": "Change this code to not construct SQL queries directly from user-controlled data.",
                        "type": "VULNERABILITY",
                        "effort": "30min",
                        "tags": ["sql-injection", "cwe-89", "owasp-a03"],
                    },
                },
                {
                    "source": "zap",
                    "raw_payload": {
                        "alertRef": "40012",
                        "alert": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "confidence": "2",
                        "url": "https://example.com/search?q=<script>alert(1)</script>",
                        "method": "GET",
                        "param": "q",
                        "attack": "<script>alert(1)</script>",
                        "evidence": "<script>alert(1)</script>",
                        "description": "Cross-site Scripting (XSS) is an attack technique...",
                        "solution": "Phase: Architecture and Design. Use libraries...",
                        "cweid": "79",
                        "wascid": "8",
                    },
                },
            ]
        }
    }
