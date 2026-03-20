"""
Configuration management for the AI-SOC project.

Loads settings from environment variables or a .env file.
API keys are NEVER hardcoded — always loaded from environment.

Setup:
    1. Copy .env.example to .env
    2. Fill in your API keys (optional — project works without them)
    3. Settings are loaded automatically when this module is imported
"""

import os
from typing import Optional


def _load_dotenv() -> None:
    """Load variables from .env file if it exists."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


# --- Settings ---

# Ollama LLM configuration
OLLAMA_URL: str = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL_NAME: str = os.environ.get("MODEL_NAME", "llama3.1:8b")

# Threat intelligence enrichment
ENRICHMENT_ENABLED: bool = os.environ.get("ENRICHMENT_ENABLED", "true").lower() == "true"
ABUSEIPDB_API_KEY: Optional[str] = os.environ.get("ABUSEIPDB_API_KEY")

# Rate limiting for AbuseIPDB (free tier: 1000 checks/day)
ABUSEIPDB_DAILY_LIMIT: int = int(os.environ.get("ABUSEIPDB_DAILY_LIMIT", "1000"))
