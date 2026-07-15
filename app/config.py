"""
Application configuration loaded from environment variables.
Uses pydantic-settings for validation and type coercion.
"""

from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    # ── Database ──────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec_agent"
    )

    # ── LLM Provider ─────────────────────────────────────────
    LLM_PROVIDER: Literal["openai"] = "openai"

    # OpenAI
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4.1-mini"

    # Scanner integrations
    SONARQUBE_BASE_URL: str = ""
    SONARQUBE_TOKEN: str = ""
    ZAP_BASE_URL: str = "http://localhost:8080"
    ZAP_API_KEY: str = ""

    # ── App ──────────────────────────────────────────────────
    APP_ENV: Literal["development", "staging", "production"] = "development"
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = "http://localhost:8000,http://localhost:3000"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
