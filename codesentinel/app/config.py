"""CodeSentinel — Configuration & Settings."""

from __future__ import annotations

from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    app_name: str = "CodeSentinel"
    app_version: str = "1.0.0"
    debug: bool = False

    # LLM
    openai_api_key: str = Field(default="", description="OpenAI API key")
    openai_model: str = "gpt-4o-mini"

    # Review settings
    max_code_length: int = 50000
    enable_security_scan: bool = True
    enable_complexity_analysis: bool = True
    complexity_threshold: int = 10

    # GitHub
    github_webhook_secret: str = ""

    # Logging
    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
