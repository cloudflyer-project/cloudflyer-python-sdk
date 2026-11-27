"""Local HTTP and offline regressions for forwarding and resource ownership."""

import asyncio
import gzip
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import Mock

import pytest

from cfsolver import AsyncCloudflareSolver, CloudflareSolver

PLAIN = b"hello compressed world" * 20


@pytest.fixture
def origin():
    records = []
    exported = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, body, headers=(), status=200):
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.respond(PLAIN, [("Content-Encoding", "gzip")])

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            records.append((self.path, self.headers, body))
            if self.path == "/api/createTask":
                self.respond(b'{"taskId": "local-task"}')
            elif self.path == "/api/waitTaskResult":
                self.respond(
                    json.dumps(
                        {
                            "status": "ready",
                            "success": True,
                            "result": {
                                "cookies": {
                                    "cf_clearance": "clearance-A",
                                    "session": "session-A",
                                },
                                "userAgent": "agent-A",
                            },
                        }
                    ).encode()
                )
            else:
                self.respond(body)

        def do_GET(self):
            records.append((self.path, self.headers, b""))
            if self.path == "/gzip":
                self.respond(gzip.compress(PLAIN), [("Content-Encoding", "gzip")])
            elif self.path == "/cookies":
                self.respond(
                    b"ok",
                    [
                        ("Set-Cookie", "one=1; Path=/"),
                        ("Set-Cookie", "two=2; Path=/"),
                        ("X-Dup", "a"),
                        ("X-Dup", "b"),
                    ],
                )
            elif self.path == "/exported":
                response = exported[0]
                self.respond(
                    response.raw_content,
                    [
                        (name.decode(), value.decode())
                        for name, value in response.headers.fields
                        if name.lower() != b"content-length"
                    ],
                    response.status_code,
                )
            elif self.path == "/redirect":
                self.respond(
                    b"",
                    [
                        (
                            "Location",
                            "http://localhost:%d/landing" % self.server.server_port,
                        )
                    ],
                    302,
                )
            elif self.path == "/landing":
                self.respond(b"landed", [("Set-Cookie", "destination=1; Path=/")])
            elif self.path == "/hop":
                self.respond(
                    b"ok",
                    [
                        ("cOnNeCtIoN", "X-Private, x-another"),
                        ("Connection", "X-Third"),
                        ("X-Private", "secret"),
                        ("X-Another", "secret"),
                        ("X-Third", "secret"),
                        ("Proxy-Authenticate", "Basic realm=proxy"),
                    ],
                )
            else:
                self.respond(json.dumps(dict(self.headers)).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield SimpleNamespace(
            url="http://127.0.0.1:%d" % server.server_port,
            records=records,
            exported=exported,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


@pytest.mark.skipif(
    importlib.util.find_spec("mitmproxy") is None, reason="optional proxy dependency"
)
class TestProxyWireCorrectness:
    async def forward(self, origin, path, method="GET", body=b"", headers=None):
        from mitmproxy import http
        from cfsolver.tproxy import CloudAPIProxyAddon

        request = http.Request.make(method, origin.url + path, body, headers or {})
        async with AsyncCloudflareSolver(
            "local", solve=False, use_cache=False
        ) as solver:
            response = await CloudAPIProxyAddon("local")._fetch_via_solver(
                SimpleNamespace(request=request),
                request.pretty_url,
                solve=False,
                solver=solver,
            )
        assert response is not None
        return request, response

    async def test_compressed_post_preserves_encoded_body(self, origin):
        request, response = await self.forward(
            origin,
            "/post",
            "POST",
            PLAIN,
            {"Content-Encoding": "gzip", "Content-Type": "application/octet-stream"},
        )
        _, headers, body = origin.records[-1]
        assert body == request.raw_content
        assert gzip.decompress(body) == PLAIN
        assert headers["Content-Encoding"] == "gzip"
        assert int(headers["Content-Length"]) == len(body)
        assert response.content == body

    async def test_duplicate_headers_survive_downstream_cookie_jar(self, origin):
        _, response = await self.forward(origin, "/cookies")
        assert response.headers.get_all("Set-Cookie") == [
            "one=1; Path=/",
            "two=2; Path=/",
        ]
        assert response.headers.get_all("X-Dup") == ["a", "b"]
        origin.exported.append(response)
        async with AsyncCloudflareSolver(
            "downstream", solve=False, use_cache=False
        ) as client:
            await client.get(origin.url + "/exported")
            observed = (await client.get(origin.url + "/echo")).json()
        assert "one=1" in observed["Cookie"]
        assert "two=2" in observed["Cookie"]

    async def test_redirect_is_returned_without_destination_request(self, origin):
        _, response = await self.forward(
            origin,
            "/redirect",
            headers={"Cookie": "private=1", "Authorization": "Bearer local"},
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/landing")
        assert not response.headers.get_all("Set-Cookie")
        assert [path for path, _, _ in origin.records] == ["/redirect"]

    async def test_response_compression_remains_valid(self, origin):
        _, response = await self.forward(origin, "/gzip")
        assert response.headers["Content-Encoding"] == "gzip"
        assert gzip.decompress(response.raw_content) == PLAIN
        assert response.content == PLAIN
        assert int(response.headers["Content-Length"]) == len(response.raw_content)

    async def test_request_hop_headers_are_case_insensitive_and_connection_scoped(
        self, origin
    ):
        await self.forward(
            origin,
            "/echo",
            headers={
                "connection": "X-Private, X-Another",
                "X-Private": "secret",
                "x-another": "secret",
                "proxy-connection": "keep-alive",
                "Proxy-Authorization": "Basic local",
                "Keep-Alive": "timeout=5",
                "TE": "trailers",
                "Trailer": "X-Trailer",
                "X-End-To-End": "keep",
            },
        )
        _, headers, _ = origin.records[-1]
        for name in (
            "X-Private",
            "X-Another",
            "Proxy-Connection",
            "Proxy-Authorization",
            "Keep-Alive",
            "TE",
            "Trailer",
        ):
            assert headers.get(name) is None
        assert headers["X-End-To-End"] == "keep"

    async def test_response_hop_headers_include_all_connection_tokens(self, origin):
        _, response = await self.forward(origin, "/hop")
        for name in (
            "Connection",
            "X-Private",
            "X-Another",
            "X-Third",
            "Proxy-Authenticate",
        ):
            assert name not in response.headers

    async def test_head_preserves_representation_length_and_encoding(self, origin):
        _, response = await self.forward(origin, "/head", "HEAD")
        assert response.raw_content == b""
        assert response.headers["Content-Length"] == str(len(PLAIN))
        assert response.headers["Content-Encoding"] == "gzip"


@pytest.mark.parametrize("same_identity", [False, True])
def test_sync_cache_does_not_cross_client_identity(origin, same_identity):
    with CloudflareSolver("account-A", api_base=origin.url, on_challenge=False) as a:
        a._linksocks_config = {"url": "ws://local", "connector_token": "local"}
        a._connect = lambda: None
        a.get(origin.url + "/echo")
        with CloudflareSolver(
            "account-A" if same_identity else "account-B",
            api_base=origin.url if same_identity else origin.url + "/other",
            solve=False,
        ) as b:
            b._get_session().cookies.set("session", "session-B", domain="127.0.0.1")
            observed = b.get(origin.url + "/echo").json()
            assert observed["Cookie"] == "session=session-B"
            observed_agent = next(
                (
                    value
                    for key, value in observed.items()
                    if key.lower() == "user-agent"
                ),
                None,
            )
            assert observed_agent != "agent-A"


@pytest.mark.parametrize("same_identity", [False, True])
async def test_async_cache_does_not_cross_client_identity(origin, same_identity):
    async with AsyncCloudflareSolver(
        "account-A", api_base=origin.url, on_challenge=False
    ) as a:
        a._linksocks_config = {"url": "ws://local", "connector_token": "local"}
        a._connect = AsyncMock()
        await a.get(origin.url + "/echo")
        async with AsyncCloudflareSolver(
            "account-A" if same_identity else "account-B",
            api_base=origin.url if same_identity else origin.url + "/other",
            solve=False,
        ) as b:
            (await b._get_session()).cookies.set(
                "session", "session-B", domain="127.0.0.1"
            )
            observed = (await b.get(origin.url + "/echo")).json()
            assert observed["Cookie"] == "session=session-B"
            observed_agent = next(
                (
                    value
                    for key, value in observed.items()
                    if key.lower() == "user-agent"
                ),
                None,
            )
            assert observed_agent != "agent-A"


def test_sync_solve_and_cache_only_apply_clearance(origin):
    with CloudflareSolver("local", api_base=origin.url, on_challenge=False) as solver:
        solver._linksocks_config = {"url": "ws://local", "connector_token": "local"}
        solver._connect = lambda: None
        session = solver._get_session()
        session.cookies.set("session", "own-session", domain="127.0.0.1")
        observed = solver.get(origin.url + "/echo").json()
        assert "session=own-session" in observed["Cookie"]
        assert "session-A" not in observed["Cookie"]
        session.cookies.set("session", "updated-session", domain="127.0.0.1")
        solver.solve = False
        observed = solver.get(origin.url + "/echo").json()
        assert "session=updated-session" in observed["Cookie"]
        assert "cf_clearance=clearance-A" in observed["Cookie"]
        assert observed["User-Agent"] == "agent-A"


async def test_async_solve_and_cache_only_apply_clearance(origin):
    async with AsyncCloudflareSolver(
        "local", api_base=origin.url, on_challenge=False
    ) as solver:
        solver._linksocks_config = {"url": "ws://local", "connector_token": "local"}
        solver._connect = AsyncMock()
        session = await solver._get_session()
        session.cookies.set("session", "own-session", domain="127.0.0.1")
        observed = (await solver.get(origin.url + "/echo")).json()
        assert "session=own-session" in observed["Cookie"]
        assert "session-A" not in observed["Cookie"]
        session.cookies.set("session", "updated-session", domain="127.0.0.1")
        solver.solve = False
        observed = (await solver.get(origin.url + "/echo")).json()
        assert "session=updated-session" in observed["Cookie"]
        assert "cf_clearance=clearance-A" in observed["Cookie"]
        assert observed["User-Agent"] == "agent-A"


@pytest.mark.parametrize("async_client", [False, True])
async def test_direct_sdk_keeps_follow_redirects_contract(origin, async_client):
    if async_client:
        async with AsyncCloudflareSolver(
            "local", solve=False, use_cache=False
        ) as solver:
            assert (await solver.get(origin.url + "/redirect")).status_code == 200
            assert (
                await solver.get(origin.url + "/redirect", allow_redirects=False)
            ).status_code == 302
    else:
        with CloudflareSolver("local", solve=False, use_cache=False) as solver:
            assert solver.get(origin.url + "/redirect").status_code == 200
            assert (
                solver.get(origin.url + "/redirect", allow_redirects=False).status_code
                == 302
            )


@pytest.mark.parametrize("mode", ["ready", "timeout", "failure"])
def test_sync_tunnel_owns_task_and_joins_thread(monkeypatch, mode):
    import cfsolver.client as module

    entered, cleaned = threading.Event(), threading.Event()

    class Tunnel:
        def __init__(self, **kwargs):
            self.connected = asyncio.Event()

        async def connect(self):
            entered.set()
            try:
                if mode == "ready":
                    self.connected.set()
                if mode == "failure":
                    raise OSError("local connection failed")
                await asyncio.Event().wait()
            finally:
                cleaned.set()

        async def wait_ready(self, timeout):
            task = asyncio.create_task(self.connect())
            await asyncio.wait_for(self.connected.wait(), timeout)
            return task

    monkeypatch.setattr(module, "WSSocksClient", Tunnel)
    solver = CloudflareSolver("local")
    solver._get_linksocks_config = lambda: {"url": "ws://local", "token": "local"}
    try:
        assert solver.ensure_connected(timeout=0.05) is (mode == "ready")
        assert entered.is_set()
        worker = solver._client_thread
        solver.close()
        solver.close()
        assert cleaned.wait(1)
        assert worker is None or not worker.is_alive()
        assert not solver.is_connected()
        with pytest.raises(RuntimeError, match="closed"):
            solver.get("http://127.0.0.1/unused", solve=False)
        assert not solver.ensure_connected()
    finally:
        solver.close()


async def test_async_tunnel_ready_and_close_are_idempotent(monkeypatch):
    import cfsolver.async_client as module

    cleaned = asyncio.Event()

    class Tunnel:
        def __init__(self, **kwargs):
            self.connected = asyncio.Event()

        async def connect(self):
            self.connected.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

    monkeypatch.setattr(module, "WSSocksClient", Tunnel)
    solver = AsyncCloudflareSolver("local")
    solver._get_linksocks_config = AsyncMock(
        return_value={"url": "ws://local", "token": "local"}
    )
    assert await solver.ensure_connected(timeout=1)
    task = solver._client_task
    await solver.aclose()
    await solver.aclose()
    assert task.done() and cleaned.is_set()
    assert not solver.is_connected()
    assert not await solver.ensure_connected()


def test_sync_session_handle_is_shared_and_closed_after_worker_request(
    origin, monkeypatch
):
    solver = CloudflareSolver("local", solve=False, use_cache=False)
    session = solver._get_session()
    handle = session.curl
    close = Mock(wraps=handle.close)
    monkeypatch.setattr(handle, "close", close)
    observed = []

    def request():
        observed.append(solver.get(origin.url + "/echo").status_code)
        observed.append(solver._get_session().curl is handle)

    worker = threading.Thread(target=request)
    worker.start()
    worker.join(2)
    solver.close()
    assert observed == [200, True]
    close.assert_called_once()


@pytest.mark.parametrize("async_client", [False, True])
@pytest.mark.parametrize(
    "field,value",
    [
        ("user_proxy", "http://other-proxy:8080"),
        ("impersonate", "firefox"),
        ("api_key", "other-account"),
        ("api_base", "http://other-provider"),
    ],
)
async def test_cache_binds_proxy_and_browser_identity(async_client, field, value):
    cls = AsyncCloudflareSolver if async_client else CloudflareSolver
    solver = cls("local", solve=False)
    try:
        if async_client:
            await solver._save_to_cache(
                "https://a.example", {"cf_clearance": "a"}, "agent", None, None
            )
        else:
            solver._save_to_cache(
                "https://a.example", {"cf_clearance": "a"}, "agent", None, None
            )
        setattr(solver, field, value)
        if async_client:
            assert not await solver._load_from_cache("https://a.example")
        else:
            assert not solver._load_from_cache("https://a.example")
    finally:
        if async_client:
            await solver.aclose()
        else:
            solver.close()


@pytest.mark.parametrize("async_client", [False, True])
async def test_clear_cache_class_api_still_invalidates_host(async_client):
    cls = AsyncCloudflareSolver if async_client else CloudflareSolver
    solver = cls("local", solve=False)
    try:
        for host in ("a.example", "b.example"):
            args = (
                "https://" + host,
                {"cf_clearance": host, "session": "private"},
                "agent",
                None,
                None,
            )
            if async_client:
                await solver._save_to_cache(*args)
            else:
                solver._save_to_cache(*args)
        if async_client:
            await cls.clear_cache("A.EXAMPLE")
            assert not await solver._load_from_cache("https://a.example")
            assert await solver._load_from_cache("https://b.example")
            await cls.clear_cache()
            assert not await solver._load_from_cache("https://b.example")
        else:
            cls.clear_cache("A.EXAMPLE")
            assert not solver._load_from_cache("https://a.example")
            assert solver._load_from_cache("https://b.example")
            cls.clear_cache()
            assert not solver._load_from_cache("https://b.example")
    finally:
        if async_client:
            await solver.aclose()
        else:
            solver.close()


async def test_async_close_during_configuration_cannot_create_a_tunnel(monkeypatch):
    import cfsolver.async_client as module

    entered, release = asyncio.Event(), asyncio.Event()

    async def config():
        entered.set()
        await release.wait()
        return {"url": "ws://local", "token": "local"}

    tunnel = Mock()
    monkeypatch.setattr(module, "WSSocksClient", tunnel)
    solver = AsyncCloudflareSolver("local")
    solver._get_linksocks_config = config
    connecting = asyncio.create_task(solver.ensure_connected(timeout=0.05))
    await entered.wait()
    await solver.aclose()
    release.set()
    assert not await connecting
    tunnel.assert_not_called()


@pytest.mark.parametrize("async_client", [False, True])
async def test_cache_restores_exact_user_agent_and_tls_bundle(async_client):
    cls = AsyncCloudflareSolver if async_client else CloudflareSolver
    solver = cls("local", solve=False)
    try:
        args = (
            "https://a.example",
            {"cf_clearance": "clearance"},
            "cached-agent",
            None,
            None,
        )
        if async_client:
            await solver._save_to_cache(*args)
            solver._ja3 = "other-host-fingerprint"
            assert await solver._load_from_cache("https://a.example")
            session = await solver._get_session()
        else:
            solver._save_to_cache(*args)
            solver._ja3 = "other-host-fingerprint"
            assert solver._load_from_cache("https://a.example")
            session = solver._get_session()
        assert solver._ja3 is None and solver._akamai is None
        assert session.headers["User-Agent"] == "cached-agent"
    finally:
        if async_client:
            await solver.aclose()
        else:
            solver.close()


def test_sync_interrupted_tunnel_setup_reaps_worker(monkeypatch):
    import cfsolver.client as module

    entered, cleaned = threading.Event(), threading.Event()

    class Tunnel:
        def __init__(self, **kwargs):
            self.connected = asyncio.Event()

        async def connect(self):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

    monkeypatch.setattr(module, "WSSocksClient", Tunnel)
    solver = CloudflareSolver("local")
    solver._get_linksocks_config = lambda: {"url": "ws://local", "token": "local"}

    def interrupt(timeout):
        assert entered.wait(1)
        raise KeyboardInterrupt()

    monkeypatch.setattr(solver._client_ready, "wait", interrupt)
    with pytest.raises(KeyboardInterrupt):
        solver.ensure_connected()
    assert cleaned.is_set()
    assert solver._client_thread is None
    assert not solver.is_connected()
    solver.close()


def test_sync_session_close_error_still_reaps_tunnel(monkeypatch):
    import cfsolver.client as module

    cleaned = threading.Event()

    class Tunnel:
        def __init__(self, **kwargs):
            self.connected = asyncio.Event()

        async def connect(self):
            self.connected.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

    monkeypatch.setattr(module, "WSSocksClient", Tunnel)
    solver = CloudflareSolver("local")
    solver._get_linksocks_config = lambda: {"url": "ws://local", "token": "local"}
    assert solver.ensure_connected()
    worker = solver._client_thread
    solver._session = SimpleNamespace(close=Mock(side_effect=OSError("close failed")))
    with pytest.raises(OSError, match="close failed"):
        solver.close()
    assert cleaned.is_set() and not worker.is_alive()
    assert not solver.is_connected()
    solver.close()
