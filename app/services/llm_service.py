"""
LLM Service — abstracts the interaction with Gemini or Ollama.

Builds structured prompts for vulnerability analysis and returns
the raw LLM response along with the exact prompt used (for reproducibility).
"""

import json
import logging
from dataclasses import dataclass

import httpx
from google import genai

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
Think step by step. For each step, explain your reasoning clearly.

1. **Understand the finding**: What type of vulnerability is reported? What is the affected component?
2. **Assess real severity**: Based on the context (not just the tool's label), what is the actual risk? Consider exploitability, impact, and attack surface.
3. **Check for false positive indicators**: Are there signs this could be a false positive? (e.g., sanitized input, framework protections, test code, etc.)
4. **Final decision**: Based on your analysis, classify this finding.
5. **Suggested action**: What specific remediation or next step do you recommend?

## Required Output Format
Respond ONLY with a valid JSON object (no markdown, no extra text) with this exact structure:

{{
    "chain_of_thought": "Your complete step-by-step reasoning as a single string. Be thorough — this will be audited by humans.",
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
    chain_of_thought: str
    final_decision: str
    severity_assessed: str
    confidence_score: float
    suggested_action: str
    prompt_used: str
    model_used: str
    raw_response: str


class LLMService:
    """
    Handles LLM interactions for vulnerability analysis.
    Supports Gemini API and Ollama (local).
    """

    def __init__(self):
        self.provider = settings.LLM_PROVIDER

        if self.provider == "gemini":
            self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
            self.model = settings.GEMINI_MODEL
        else:
            self.ollama_url = settings.OLLAMA_BASE_URL
            self.model = settings.OLLAMA_MODEL

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

        if self.provider == "gemini":
            raw_text = await self._call_gemini(prompt)
        else:
            raw_text = await self._call_ollama(prompt)

        # Parse the JSON response from the LLM
        parsed = self._parse_response(raw_text)

        return LLMResponse(
            chain_of_thought=parsed.get("chain_of_thought", "No reasoning provided"),
            final_decision=parsed.get("final_decision", "requiere_revision_humana"),
            severity_assessed=parsed.get("severity_assessed", "medium"),
            confidence_score=min(max(float(parsed.get("confidence_score", 0.5)), 0.0), 1.0),
            suggested_action=parsed.get("suggested_action", "Manual review recommended"),
            prompt_used=prompt,
            model_used=f"{self.provider}/{self.model}",
            raw_response=raw_text,
        )

    async def _call_gemini(self, prompt: str) -> str:
        """Call Gemini API using the google-genai SDK (async)."""
        response = await self.client.aio.models.generate_content(
            model=self.model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                temperature=0.2,  # Low temperature for consistent, analytical outputs
                max_output_tokens=2048,
            ),
        )
        return response.text

    async def _call_ollama(self, prompt: str) -> str:
        """Call Ollama local instance via its REST API."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "num_predict": 2048,
                    },
                },
            )
            response.raise_for_status()
            return response.json()["response"]

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

            # Fallback: wrap the raw text as chain_of_thought
            return {
                "chain_of_thought": f"[RAW LLM OUTPUT - JSON parsing failed]\n\n{raw_text}",
                "final_decision": "requiere_revision_humana",
                "severity_assessed": "medium",
                "confidence_score": 0.3,
                "suggested_action": "LLM response could not be parsed. Manual review required.",
            }
