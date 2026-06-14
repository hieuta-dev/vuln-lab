# FILE: backend/config.py
# PURPOSE: Application settings loaded from environment variables
# SECURITY NOTE: Never hardcode secrets here — all values come from .env

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://vulnlab:vulnlab123@db:5432/vulnlab"
    anthropic_api_key: str = "sk-ant-REPLACE_ME"
    secret_key: str = "change-me-in-production"
    upload_dir: str = "/app/uploads"
    max_upload_size_mb: int = 10
    frontend_url: str = "http://localhost:4200"
    # LLM provider selection
    ai_provider: str = "ollama"             # "anthropic" | "ollama"
    anthropic_model: str = "claude-sonnet-4-6"
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "llama3.2"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
