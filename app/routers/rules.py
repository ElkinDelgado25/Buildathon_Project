"""Rule catalog endpoints used by scanners, policies, and the future CLI."""

from datetime import datetime, timezone
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import SecurityRule
from app.schemas.security_rule import SecurityRuleCreate, SecurityRuleResponse
from app.sensors.sonarqube import SonarQubeClient
from app.sensors.zap import ZAPClient
from app.services.rule_sync_service import sonar_rule_to_schema, zap_rule_to_schema

router = APIRouter(prefix="/rules", tags=["Security Rules"])


async def _upsert(incoming: SecurityRuleCreate, db: AsyncSession) -> SecurityRule:
    result = await db.execute(
        select(SecurityRule).where(
            SecurityRule.source == incoming.source,
            SecurityRule.external_id == incoming.external_id,
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        rule = SecurityRule(**incoming.model_dump())
        db.add(rule)
    else:
        for field, value in incoming.model_dump().items():
            setattr(rule, field, value)
        rule.updated_at = datetime.now(timezone.utc)
    return rule


@router.post("", response_model=SecurityRuleResponse)
async def upsert_rule(
    incoming: SecurityRuleCreate, db: AsyncSession = Depends(get_db)
):
    """Store scanner rule metadata, replacing older metadata from the same source."""
    rule = await _upsert(incoming, db)
    await db.flush()
    return rule


@router.post("/sync/{source}", response_model=list[SecurityRuleResponse])
async def sync_rules(
    source: Literal["sonarqube", "zap"],
    db: AsyncSession = Depends(get_db),
):
    """Download configured scanner rules into the local, auditable catalog."""
    try:
        if source == "sonarqube":
            if not settings.SONARQUBE_BASE_URL or not settings.SONARQUBE_TOKEN:
                raise HTTPException(
                    status_code=503, detail="SonarQube integration is not configured."
                )
            raw_rules = await SonarQubeClient(
                settings.SONARQUBE_BASE_URL, settings.SONARQUBE_TOKEN
            ).fetch_rules()
            incoming_rules = [sonar_rule_to_schema(rule) for rule in raw_rules]
        else:
            raw_rules = await ZAPClient(
                settings.ZAP_BASE_URL, settings.ZAP_API_KEY
            ).fetch_rules()
            incoming_rules = [zap_rule_to_schema(rule) for rule in raw_rules]
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"Could not synchronize {source} rules."
        ) from exc

    stored = [await _upsert(rule, db) for rule in incoming_rules]
    await db.flush()
    return stored


@router.get("", response_model=list[SecurityRuleResponse])
async def list_rules(
    source: str | None = None,
    severity: str | None = None,
    cwe_id: str | None = None,
    owasp_category: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List cached rules for the CLI/UI with optional security filters."""
    statement = select(SecurityRule).order_by(SecurityRule.updated_at.desc())
    if source:
        statement = statement.where(SecurityRule.source == source)
    if severity:
        statement = statement.where(SecurityRule.severity == severity)
    if cwe_id:
        statement = statement.where(SecurityRule.cwe_id == cwe_id)
    if owasp_category:
        statement = statement.where(SecurityRule.owasp_category == owasp_category)
    statement = statement.limit(min(limit, 200)).offset(max(offset, 0))
    result = await db.execute(statement)
    return list(result.scalars().all())

