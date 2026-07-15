"""Schemas for the fixed command catalog consumed by CLI-style clients."""

from typing import Any

from pydantic import BaseModel, Field


class CommandRequest(BaseModel):
    """A command and structured context; never a shell instruction."""

    command: str = Field(..., min_length=1, max_length=300)
    target: str | None = Field(default=None, min_length=1, max_length=500)
    instruction: str | None = Field(default=None, max_length=2_000)
    reviewed_by: str | None = Field(default=None, max_length=100)
    review_comment: str | None = Field(default=None, max_length=2_000)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "command": "/owasp audit A03",
                    "target": "https://staging.example.com",
                    "instruction": "Prioriza vectores de inyección y evidencia.",
                }
            ]
        }
    }


class CommandResponse(BaseModel):
    """Uniform response rendered by the Web CLI terminal transcript."""

    command: str
    result_type: str
    status: str
    message: str
    data: Any = None
    suggestions: list[str] = Field(default_factory=list)
