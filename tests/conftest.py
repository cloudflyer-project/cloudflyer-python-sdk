import asyncio
import os
import sys
from pathlib import Path

import pytest

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

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


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (requires API key)"
    )


@pytest.fixture
def api_url() -> str:
    return os.environ.get("CLOUDFLYER_API_BASE", os.environ.get("CLOUDFLYER_API_URL", "https://solver.zetx.site")).rstrip("/")


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


@pytest.fixture
def mock_solver_kwargs():
    """Kwargs for unit tests that don't need real API."""
    return {
        "api_key": "test-api-key",
        "api_base": "https://solver.zetx.site",
    }
