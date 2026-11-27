import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from types import SimpleNamespace

import pytest
from mitmproxy import http

from cfsolver.async_client import AsyncCloudflareSolver
from cfsolver.tproxy import CloudAPIProxyAddon


def request_headers(values):
    return http.Headers([(name.encode(), value.encode()) for name, value in values.items()])


@pytest.fixture
def challenge_server():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            agent = self.headers.get("User-Agent", "")
            requests.append((cookie, agent))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/destination")
                self.send_header("Set-Cookie", "server_session=updated; Path=/")
                self.send_header("Set-Cookie", "another_session=second; Path=/")
                self.end_headers()
                return
            cleared = "cf_clearance=solved" in cookie
            authenticated = "institution_session=valid" in cookie
            status = 403 if not cleared else (200 if authenticated and agent == "solved-agent" else 401)
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", requests
    finally:
        server.shutdown()
        server.server_close()


def test_proxy_solve_preserves_forwarded_session_and_solved_fingerprint(challenge_server, monkeypatch):
    url, requests = challenge_server
    headers = {
        "Cookie": "institution_session=valid; duplicate=one; duplicate=two; cf_clearance=old",
        "User-Agent": "browser-agent",
    }

    async def run():
        async with AsyncCloudflareSolver("test", use_cache=False) as solver:
            session = await solver._get_session()
            session.cookies.set("preexisting", "present", domain="127.0.0.1")

            async def solve(url, html=None, use_cache=None):
                session = await solver._get_session()
                session.cookies.set("cf_clearance", "solved", domain="127.0.0.1")
                session.headers["User-Agent"] = "solved-agent"

            monkeypatch.setattr(solver, "_solve_challenge", solve)
            monkeypatch.setattr(solver, "_detect_challenge", lambda response: response.status_code == 403)
            addon = CloudAPIProxyAddon(api_key="test", no_cache=True)
            addon._solver = solver
            flow = SimpleNamespace(request=SimpleNamespace(method="GET", headers=request_headers(headers), content=b""))
            return await addon._fetch_via_solver(flow, url, solve=True)

    response = asyncio.run(run())

    assert response.status_code == 200
    assert len(requests) == 1
    assert "institution_session=valid" in requests[0][0]
    assert "preexisting=present" in requests[0][0]
    assert requests[0][0].count("duplicate=") == 2
    assert "cf_clearance=solved" in requests[0][0]
    assert "cf_clearance=old" not in requests[0][0]
    assert requests[0][1] == "solved-agent"
    assert headers["User-Agent"] == "browser-agent"
    assert "cf_clearance=old" in headers["Cookie"]


def test_proxy_preserves_redirect_and_records_response_cookies(challenge_server):
    url, requests = challenge_server

    async def run():
        async with AsyncCloudflareSolver("test", use_cache=False) as solver:
            session = await solver._get_session()
            session.cookies.set("existing", "present", domain="127.0.0.1")
            addon = CloudAPIProxyAddon(api_key="test", no_cache=True)
            addon._solver = solver
            flow = SimpleNamespace(request=SimpleNamespace(
                method="GET", headers=request_headers({"Cookie": "institution_session=valid"}), content=b""
            ))
            response = await addon._fetch_via_solver(flow, url + "redirect", solve=False)
            return response, session.cookies.get("server_session", domain="127.0.0.1")

    response, updated_cookie = asyncio.run(run())

    assert response.status_code == 302
    assert response.headers["Location"] == "/destination"
    assert len(response.headers.get_all("Set-Cookie")) == 2
    assert len(requests) == 1
    assert "institution_session=valid" in requests[0][0]
    assert updated_cookie == "updated"


def test_cached_clearance_keeps_lowercase_cookie_header(challenge_server):
    url, requests = challenge_server

    async def run():
        async with AsyncCloudflareSolver("test", use_cache=False) as solver:
            addon = CloudAPIProxyAddon(api_key="test", no_cache=True)
            addon._solver = solver
            flow = SimpleNamespace(request=SimpleNamespace(
                method="GET",
                headers=request_headers({"cookie": "institution_session=valid; cf_clearance=old"}),
                content=b"",
            ))
            return await addon._fetch_via_solver(
                flow, url, solve=False, user_agent="solved-agent", cf_clearance="solved"
            )

    response = asyncio.run(run())

    assert response.status_code == 200
    assert "institution_session=valid" in requests[0][0]
    assert "cf_clearance=solved" in requests[0][0]
    assert "cf_clearance=old" not in requests[0][0]


def test_proxy_preserves_split_cookie_headers(challenge_server):
    url, requests = challenge_server

    async def run():
        async with AsyncCloudflareSolver("test", use_cache=False) as solver:
            addon = CloudAPIProxyAddon(api_key="test", no_cache=True)
            addon._solver = solver
            flow = SimpleNamespace(request=SimpleNamespace(
                method="GET",
                headers=http.Headers([
                    (b"cookie", b"institution_session=valid"),
                    (b"cookie", b"duplicate=one; duplicate=two; cf_clearance=old"),
                ]),
                content=b"",
            ))
            return await addon._fetch_via_solver(
                flow, url, solve=False, user_agent="solved-agent", cf_clearance="solved"
            )

    response = asyncio.run(run())

    assert response.status_code == 200
    assert requests[0][0].split("; ").count("institution_session=valid") == 1
    assert requests[0][0].split("; ").count("duplicate=one") == 1
    assert requests[0][0].split("; ").count("duplicate=two") == 1
    assert "cf_clearance=old" not in requests[0][0]


def test_proxy_solves_already_detected_challenge_without_second_detection(challenge_server, monkeypatch):
    url, requests = challenge_server
    solved = []

    async def run():
        async with AsyncCloudflareSolver("test", use_cache=False) as solver:
            async def solve(url, html=None, use_cache=None):
                solved.append(True)
                session = await solver._get_session()
                session.cookies.set("cf_clearance", "solved", domain="127.0.0.1")
                session.headers["User-Agent"] = "solved-agent"

            monkeypatch.setattr(solver, "_solve_challenge", solve)
            monkeypatch.setattr(solver, "_detect_challenge", lambda response: False)
            addon = CloudAPIProxyAddon(api_key="test", no_cache=True)
            addon._solver = solver
            flow = SimpleNamespace(request=SimpleNamespace(
                method="GET", headers=request_headers({"Cookie": "institution_session=valid"}), content=b""
            ))
            return await addon._fetch_via_solver(flow, url, solve=True)

    response = asyncio.run(run())

    assert solved == [True]
    assert response.status_code == 200
    assert len(requests) == 1


def test_rejected_solve_does_not_populate_sdk_clearance_cache(challenge_server, monkeypatch):
    from cfsolver.async_client import _clearance_cache

    url, _ = challenge_server

    async def run():
        async with AsyncCloudflareSolver("test") as solver:
            key = solver._get_cache_key(url)
            _clearance_cache.pop(key, None)

            async def solve(url, html=None, use_cache=None):
                session = await solver._get_session()
                session.cookies.set("cf_clearance", "rejected", domain="127.0.0.1")
                session.headers["User-Agent"] = "solved-agent"
                if use_cache:
                    await solver._save_to_cache(
                        url, {"cf_clearance": "rejected"}, "solved-agent", None, None
                    )

            monkeypatch.setattr(solver, "_solve_challenge", solve)
            addon = CloudAPIProxyAddon(api_key="test")
            addon._solver = solver
            flow = SimpleNamespace(request=SimpleNamespace(
                method="GET", headers=request_headers({"Cookie": "institution_session=valid"}), content=b""
            ))
            try:
                response = await addon._fetch_via_solver(flow, url, solve=True)
                assert response.status_code == 403
                assert key not in _clearance_cache
            finally:
                _clearance_cache.pop(key, None)

    asyncio.run(run())
