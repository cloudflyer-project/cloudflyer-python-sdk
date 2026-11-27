import asyncio
import os
import sys
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

if sys.platform == "win32":
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
    return os.environ.get(
        "CLOUDFLYER_API_BASE",
        os.environ.get("CLOUDFLYER_API_URL", "https://solver.zetx.site"),
    ).rstrip("/")


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


@pytest.fixture
def local_http_url():
    """A real HTTP origin for basic requests, without external network access."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.respond({"headers": dict(self.headers)})

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.respond({"json": json.loads(body)})

        def respond(self, payload):
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
