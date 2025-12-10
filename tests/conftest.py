import os
from pathlib import Path

import pytest

ENV_FILE = Path(__file__).parent / ".env"


def load_env():
    """Load .env file if exists."""
    if not ENV_FILE.exists():
        return
    
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


load_env()


@pytest.fixture
def api_url() -> str:
    return os.environ.get("CLOUDFLYER_API_URL", "http://localhost:8000").rstrip("/")


@pytest.fixture
def api_key() -> str:
    return os.environ.get("CLOUDFLYER_API_KEY", "")


@pytest.fixture
def solver_kwargs(api_url, api_key):
    """Common kwargs for solver initialization."""
    return {
        "api_key": api_key,
        "api_base": api_url,
    }
