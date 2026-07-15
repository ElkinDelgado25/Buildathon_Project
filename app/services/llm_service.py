"""
LLM Service — abstracts the interaction with the OpenAI API.

Builds structured prompts for vulnerability analysis and returns a concise,
auditable rationale rather than hidden model reasoning.
"""

import json
import logging
from dataclasses import dataclass

from openai import AsyncOpenAI

from app.config import settings

logger = logging.getLogger(__name__)


# ── Structured prompt template ───────────────────────────────
ANALYSIS_PROMPT_TEMPLATE = """You are a senior cybersecurity analyst with expertise in application security.
You are reviewing a vulnerability finding from a security scanning tool.

## Your Task
Analyze the following security finding and provide a detailed, traceable assessment.

## Finding Details
- **Source Tool**: {source}
- **Raw Finding Data**:
```json
{raw_payload}
```

## Instructions
Assess the finding using the evidence provided. Do not reveal hidden chain-of-thought
or private reasoning. Instead, give a concise, evidence-based audit summary that a
human reviewer can verify.

1. Identify the vulnerability type and affected component.
2. Assess practical severity considering exploitability, impact, and attack surface.
3. Note concrete false-positive indicators, if any.
4. Classify the finding.
5. Propose a specific remediation or next step.

## Required Output Format
Respond ONLY with a valid JSON object (no markdown, no extra text) with this exact structure:

{{
    "analysis_summary": "A concise, evidence-based explanation suitable for an audit record.",
    "final_decision": "amenaza_confirmada | falso_positivo | requiere_revision_humana",
    "severity_assessed": "critical | high | medium | low | info",
    "confidence_score": 0.85,
    "suggested_action": "Specific remediation advice"
}}

IMPORTANT: confidence_score must be a number between 0.00 and 1.00.
IMPORTANT: final_decision must be exactly one of: amenaza_confirmada, falso_positivo, requiere_revision_humana.
"""


@dataclass
class LLMResponse:
    """Structured result from the LLM analysis."""
    analysis_summary: str
    final_decision: str
    severity_assessed: str
    confidence_score: float
    suggested_action: str
    prompt_used: str
    model_used: str
    raw_response: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class LLMConfigurationError(RuntimeError):
    """Raised when the OpenAI integration has not been configured."""


class LLMService:
    """
    Handles LLM interactions for vulnerability analysis.
    Uses the OpenAI API with a project-provided API key.
    """

    def __init__(self):
        self.provider = "openai"
        self.client: AsyncOpenAI | None = None
        self.model = settings.OPENAI_MODEL

    def _build_prompt(self, source: str, raw_payload: dict) -> str:
        """Build the analysis prompt with the finding data injected."""
        return ANALYSIS_PROMPT_TEMPLATE.format(
            source=source,
            raw_payload=json.dumps(raw_payload, indent=2, ensure_ascii=False),
        )

    async def analyze_finding(self, source: str, raw_payload: dict) -> LLMResponse:
        """
        Send a finding to the LLM and parse the structured response.
        Returns the full LLMResponse including the prompt used for traceability.
        """
        prompt = self._build_prompt(source, raw_payload)
        logger.info(f"Sending finding to {self.provider} ({self.model}) for analysis...")

        raw_text, prompt_tokens, completion_tokens, total_tokens = await self._call_openai(prompt)

        # Parse the JSON response from the LLM
        parsed = self._parse_response(raw_text)

        return LLMResponse(
            analysis_summary=parsed.get(
                "analysis_summary", "No audit summary was provided."
            ),
            final_decision=parsed.get("final_decision", "requiere_revision_humana"),
            severity_assessed=parsed.get("severity_assessed", "medium"),
            confidence_score=min(max(float(parsed.get("confidence_score", 0.5)), 0.0), 1.0),
            suggested_action=parsed.get("suggested_action", "Manual review recommended"),
            prompt_used=prompt,
            model_used=f"{self.provider}/{self.model}",
            raw_response=raw_text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        )

    async def _call_openai(self, prompt: str) -> tuple[str, int, int, int]:
        """Call OpenAI and require a JSON object response."""
        if not settings.OPENAI_API_KEY:
            raise LLMConfigurationError(
                "OPENAI_API_KEY is not configured. Add it to .env before analyzing findings."
            )

        if self.client is None:
            self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior application-security analyst. "
                        "Return only valid JSON and never expose hidden chain-of-thought."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=1200,
        )
        usage = response.usage
        prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        total_tokens = int(getattr(usage, "total_tokens", 0) or 0)
        logger.info(
            "OpenAI usage: input=%s output=%s total=%s",
            prompt_tokens,
            completion_tokens,
            total_tokens,
        )
        return (
            response.choices[0].message.content or "{}",
            prompt_tokens,
            completion_tokens,
            total_tokens,
        )

    def _parse_response(self, raw_text: str) -> dict:
        """
        Parse the LLM's JSON response, handling potential formatting issues.
        Falls back gracefully if the LLM doesn't return valid JSON.
        """
        # Clean up common LLM output issues
        cleaned = raw_text.strip()

        # Remove markdown code fences if present
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Raw response: {raw_text}")

            # Fallback: preserve the raw response as an audit summary.
            return {
                "analysis_summary": (
                    "[RAW LLM OUTPUT - JSON parsing failed]\n\n"
                    f"{raw_text}"
                ),
                "final_decision": "requiere_revision_humana",
                "severity_assessed": "medium",
                "confidence_score": 0.3,
                "suggested_action": "LLM response could not be parsed. Manual review required.",
            }
