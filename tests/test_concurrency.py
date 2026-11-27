"""Offline regressions for request isolation, retries and solve coordination."""

import asyncio
import importlib.util
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from curl_cffi.requests import Cookies

from cfsolver import AsyncCloudflareSolver, CloudflareSolver
from cfsolver.exceptions import CFSolverAPIError, CFSolverTimeoutError


def response(status=200, payload=None, headers=None):
    return SimpleNamespace(
        status_code=status,
        headers=headers or {},
        json=lambda: payload or {"status": "ready", "success": True},
        text="",
    )


@pytest.mark.parametrize(
    "error", [TimeoutError("response lost after send"), OSError("reset")]
)
def test_sync_fingerprint_does_not_replay_post(error):
    solver = CloudflareSolver("test", use_cache=False, solve=False)
    session = SimpleNamespace(request=Mock(side_effect=error), close=Mock())
    solver._session = session
    solver._ja3 = "custom"
    solver._reset_session = Mock()
    with pytest.raises(type(error)):
        solver.post("https://example.com/order", data=b"order=1")
    session.request.assert_called_once()
    solver._reset_session.assert_not_called()
    solver.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [TimeoutError("response lost after send"), OSError("reset")]
)
async def test_async_fingerprint_does_not_replay_post(error):
    async with AsyncCloudflareSolver("test", use_cache=False, solve=False) as solver:
        session = SimpleNamespace(
            request=AsyncMock(side_effect=error), close=AsyncMock()
        )
        solver._session = session
        solver._ja3 = "custom"
        solver._reset_session = AsyncMock()
        with pytest.raises(type(error)):
            await solver.post("https://example.com/order", data=b"order=1")
        session.request.assert_awaited_once()
        solver._reset_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_async_shared_client_keeps_request_fingerprint_and_user_agent_together():
    async with AsyncCloudflareSolver(
        "test", use_cache=False, on_challenge=False
    ) as solver:
        session = SimpleNamespace(cookies=Cookies(), headers={}, close=AsyncMock())
        solver._session = session

        async def solve(url, **kwargs):
            solver._ja3 = url
            session.headers["User-Agent"] = url

        async def send(method, url, **kwargs):
            await asyncio.sleep(0)
            assert solver._ja3 == url
            assert session.headers["User-Agent"] == url
            return response()

        solver._solve_challenge = solve
        session.request = send
        await asyncio.gather(
            solver.get("https://a.example/"), solver.get("https://b.example/")
        )


def test_sync_shared_client_keeps_request_fingerprint_and_user_agent_together():
    import threading
    from concurrent.futures import ThreadPoolExecutor

    first_sent, second_solved = threading.Event(), threading.Event()
    solver = CloudflareSolver("test", use_cache=False, on_challenge=False)
    session = SimpleNamespace(cookies=Cookies(), headers={}, close=Mock())
    solver._session = session

    def solve(url, **kwargs):
        solver._ja3 = url
        session.headers["User-Agent"] = url
        if "b.example" in url:
            second_solved.set()

    def send(method, url, **kwargs):
        if "a.example" in url:
            first_sent.set()
            second_solved.wait(0.1)
        assert solver._ja3 == url
        assert session.headers["User-Agent"] == url
        return response()

    solver._solve_challenge = solve
    session.request = send
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(solver.get, "https://a.example/")
            assert first_sent.wait(1)
            second = executor.submit(solver.get, "https://b.example/")
            first.result(timeout=1)
            second.result(timeout=1)
    finally:
        solver.close()


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay

    async def asleep(self, delay):
        self.sleep(delay)


@pytest.mark.parametrize(
    "domain,host_only,path,secure,expires,url,expected",
    [
        ("a.example", True, "/", False, None, "https://sub.a.example/", None),
        (".a.example", False, "/", False, None, "https://sub.a.example/", "value"),
        (".a.example", False, "/", False, None, "https://bada.example/", None),
        (
            "a.example",
            True,
            "/private",
            False,
            None,
            "https://a.example/private/sub",
            "value",
        ),
        (
            "a.example",
            True,
            "/private",
            False,
            None,
            "https://a.example/private-other",
            None,
        ),
        ("a.example", True, "/", True, None, "http://a.example/", None),
        ("a.example", True, "/", True, None, "https://a.example/", "value"),
        ("a.example", True, "/", False, 1, "https://a.example/", None),
        ("", False, "/", False, None, "https://a.example/", "value"),
    ],
)
def test_cookie_selection_scope_without_proxy_dependency(
    domain, host_only, path, secure, expires, url, expected
):
    from cfsolver.cookie_utils import find_cookie_value

    cookies = Cookies()
    cookies.set("cf_clearance", "value", domain=domain, path=path)
    cookie = next(iter(cookies.jar))
    cookie.domain_specified = not host_only
    cookie.secure = secure
    cookie.expires = expires
    assert find_cookie_value(cookies, "cf_clearance", url) == expected


def test_cookie_selection_prefers_specific_applicable_path():
    from cfsolver.cookie_utils import find_cookie_value

    cookies = Cookies()
    cookies.set("cf_clearance", "root", domain="a.example", path="/")
    cookies.set("cf_clearance", "private", domain="a.example", path="/private")
    assert (
        find_cookie_value(cookies, "cf_clearance", "https://a.example/private/page")
        == "private"
    )


@pytest.mark.parametrize("polling", [False, True])
def test_sync_polling_backs_off_and_respects_budget(monkeypatch, polling):
    import cfsolver.client as module

    clock = Clock()
    monkeypatch.setattr(module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(module.time, "sleep", clock.sleep)
    post = Mock(
        side_effect=[
            response(429, headers={"Retry-After": "3"}),
            response(503),
            response(),
        ]
    )
    session = SimpleNamespace(post=post)
    context = Mock()
    context.__enter__ = Mock(return_value=session)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(module, "Session", Mock(return_value=context))
    solver = CloudflareSolver("test", use_polling=polling, polling_interval=0)
    solver._wait_for_result("task", timeout=10)
    assert clock.sleeps == [3.0, 2.0]
    assert [call.kwargs["timeout"] for call in post.call_args_list] == [10, 7, 5]


def test_sync_polling_stops_at_retry_after_deadline(monkeypatch):
    import cfsolver.client as module

    clock = Clock()
    monkeypatch.setattr(module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(module.time, "sleep", clock.sleep)
    post = Mock(return_value=response(429, headers={"Retry-After": "100"}))
    context = Mock()
    context.__enter__ = Mock(return_value=SimpleNamespace(post=post))
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(module, "Session", Mock(return_value=context))
    with pytest.raises(CFSolverTimeoutError):
        CloudflareSolver("test")._wait_for_result("task", timeout=5)
    assert clock.sleeps == [5]
    post.assert_called_once()


def test_sync_polling_permanent_error_is_not_retried(monkeypatch):
    import cfsolver.client as module

    post = Mock(return_value=response(401))
    context = Mock()
    context.__enter__ = Mock(return_value=SimpleNamespace(post=post))
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(module, "Session", Mock(return_value=context))
    with pytest.raises(CFSolverAPIError):
        CloudflareSolver("test")._wait_for_result("task", timeout=1)
    post.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("polling", [False, True])
async def test_async_polling_backs_off_and_respects_budget(monkeypatch, polling):
    import cfsolver.async_client as module

    clock = Clock()
    monkeypatch.setattr(module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(module.asyncio, "sleep", clock.asleep)
    async with AsyncCloudflareSolver(
        "test", use_polling=polling, polling_interval=0
    ) as solver:
        post = AsyncMock(
            side_effect=[
                response(429, headers={"Retry-After": "3"}),
                response(503),
                response(),
            ]
        )
        solver._api_client.post = post
        await solver._wait_for_result("task", timeout=10)
        assert clock.sleeps == [3.0, 2.0]
        assert [call.kwargs["timeout"] for call in post.call_args_list] == [10, 7, 5]


@pytest.mark.asyncio
async def test_async_polling_stops_at_retry_after_deadline(monkeypatch):
    import cfsolver.async_client as module

    clock = Clock()
    monkeypatch.setattr(module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(module.asyncio, "sleep", clock.asleep)
    async with AsyncCloudflareSolver("test") as solver:
        solver._api_client.post = AsyncMock(
            side_effect=[response(429, headers={"Retry-After": "100"}), response()]
        )
        with pytest.raises(CFSolverTimeoutError):
            await solver._wait_for_result("task", timeout=5)
        assert clock.sleeps == [5]
        solver._api_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_polling_permanent_error_is_not_retried():
    async with AsyncCloudflareSolver("test") as solver:
        solver._api_client.post = AsyncMock(side_effect=[response(401), response()])
        with pytest.raises(CFSolverAPIError):
            await solver._wait_for_result("task", timeout=1)
        solver._api_client.post.assert_awaited_once()


def test_sync_fingerprint_configuration_fallback_rewinds_body(monkeypatch):
    from io import BytesIO
    from curl_cffi.requests.utils import set_ja3_options

    solver = CloudflareSolver("test", use_cache=False, solve=False)
    body = BytesIO(b"order=1")
    attempts = []

    def send(method, url, **kwargs):
        attempts.append((method, kwargs["data"].read()))
        if len(attempts) == 1:
            set_ja3_options(None, "invalid")
        assert "ja3" not in kwargs
        return response()

    session = SimpleNamespace(request=Mock(side_effect=send), close=Mock())
    solver._session = session
    monkeypatch.setattr(solver, "_reset_session", Mock())
    solver.post("https://example.com/order", data=body, ja3="invalid")
    assert attempts == [("POST", b"order=1"), ("POST", b"order=1")]
    solver.close()


@pytest.mark.asyncio
async def test_async_fingerprint_configuration_fallback_rewinds_body(monkeypatch):
    from io import BytesIO
    from curl_cffi.requests.utils import set_ja3_options

    async with AsyncCloudflareSolver("test", use_cache=False, solve=False) as solver:
        body = BytesIO(b"order=1")
        attempts = []

        async def send(method, url, **kwargs):
            attempts.append((method, kwargs["data"].read()))
            if len(attempts) == 1:
                set_ja3_options(None, "invalid")
            assert "ja3" not in kwargs
            return response()

        solver._session = SimpleNamespace(
            request=AsyncMock(side_effect=send), close=AsyncMock()
        )
        monkeypatch.setattr(solver, "_reset_session", AsyncMock())
        await solver.post("https://example.com/order", data=body, ja3="invalid")
        assert attempts == [("POST", b"order=1"), ("POST", b"order=1")]


@pytest.mark.parametrize("value", ["nan", "inf", "not a date", "-1", "0"])
def test_retry_after_invalid_or_zero_still_backs_off(value):
    from cfsolver.polling import retry_delay

    assert retry_delay(response(429, headers={"Retry-After": value}), 1) == 1
    assert retry_delay(response(503), 100) == 30


def test_retry_after_http_date(monkeypatch):
    import cfsolver.polling as module

    monkeypatch.setattr(module.time, "time", lambda: 0)
    assert (
        module.retry_delay(
            response(503, headers={"Retry-After": "Thu, 01 Jan 1970 00:00:05 GMT"}), 1
        )
        == 5
    )


@pytest.mark.asyncio
async def test_async_polling_cancellation_stops_backoff(monkeypatch):
    import cfsolver.async_client as module

    sleeping = asyncio.Event()

    async def sleep(delay):
        sleeping.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(module.asyncio, "sleep", sleep)
    async with AsyncCloudflareSolver("test") as solver:
        solver._api_client.post = AsyncMock(return_value=response(429))
        task = asyncio.create_task(solver._wait_for_result("task"))
        await asyncio.wait_for(sleeping.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        solver._api_client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_async_polling_bounds_inflight_request():
    cancelled = asyncio.Event()

    async def post(*args, **kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async with AsyncCloudflareSolver("test") as solver:
        solver._api_client.post = post
        with pytest.raises(CFSolverTimeoutError):
            await solver._wait_for_result("task", timeout=0.02)
        assert cancelled.is_set()


@pytest.mark.asyncio
async def test_cancelled_tunnel_setup_does_not_leak_child_task(monkeypatch):
    import cfsolver.async_client as module

    entered = asyncio.Event()
    children = []

    class Tunnel:
        def __init__(self, **kwargs):
            self.connected = asyncio.Event()

        async def connect(self):
            children.append(asyncio.current_task())
            entered.set()
            await asyncio.Event().wait()

        async def wait_ready(self, timeout=None):
            task = asyncio.create_task(self.connect())
            await asyncio.wait_for(self.connected.wait(), timeout)
            return task

    monkeypatch.setattr(module, "WSSocksClient", Tunnel)
    solver = AsyncCloudflareSolver("test")
    solver._get_linksocks_config = AsyncMock(
        return_value={"url": "ws://test", "token": "test"}
    )
    task = asyncio.create_task(solver._connect())
    try:
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await solver.aclose()
        assert all(child.done() for child in children)
    finally:
        for child in children:
            child.cancel()
        await asyncio.gather(*children, return_exceptions=True)
        await solver.aclose()


@pytest.mark.skipif(
    importlib.util.find_spec("mitmproxy") is None, reason="optional proxy dependency"
)
class TestProxyConcurrency:
    @staticmethod
    def flow(url="https://example.com/page", skip=False):
        from mitmproxy import http

        headers = {"User-Agent": "client", "Cookie": "session=private"}
        if skip:
            headers["X-CFSolver-Skip"] = "1"
        return SimpleNamespace(
            request=http.Request.make("POST", url, b"order=1", headers),
            response=http.Response.make(
                403, b"challenge", {"cf-mitigated": "challenge"}
            ),
            metadata={},
        )

    def test_long_lived_host_and_user_agent_stores_are_bounded(self):
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon("test", failure_ttl=-1)
        addon._MAX_CACHE_HOSTS = 2
        addon._MAX_USER_AGENTS_PER_HOST = 2
        for i in range(8):
            host = f"{i}.example"
            addon.set_cf_clearance(host, "agent", "cookie")
            addon.record_solve_failure(host)
        assert len(addon.cf_clearance_store) == 2
        assert len(addon.solve_failures) == 2
        assert addon.get_cf_clearance_for_host("0.example") is None
        assert not addon.is_solve_blocked("0.example")
        for i in range(8):
            addon.set_cf_clearance("7.example", f"agent-{i}", "cookie")
        assert len(addon.cf_clearance_store["7.example"]) == 2

    def test_clearance_host_eviction_keeps_recently_used_entries(self):
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon("test")
        addon._MAX_CACHE_HOSTS = 2
        addon.set_cf_clearance("a.example", "agent", "a")
        addon.set_cf_clearance("b.example", "agent", "b")
        assert addon.get_cf_clearance("a.example", "agent") == "a"
        addon.set_cf_clearance("c.example", "agent", "c")
        assert addon.get_cf_clearance_for_host("b.example") is None
        assert addon.get_cf_clearance("a.example", "agent") == "a"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "leader_skip,waiter_skip,ttl",
        [(False, False, -1), (True, False, -1), (False, True, -1), (False, False, 0)],
    )
    async def test_waiters_complete_without_long_term_cache(
        self, leader_skip, waiter_skip, ttl
    ):
        from mitmproxy import http
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon("test", success_ttl=ttl)
        started, release = asyncio.Event(), asyncio.Event()
        calls = []

        async def fetch(flow, url, *, solve, **kwargs):
            calls.append((flow, solve, kwargs))
            if solve:
                started.set()
                await release.wait()
            return http.Response.make(200, b"ok")

        addon._fetch_via_solver = fetch
        addon._try_extract_clearance_from_solver = AsyncMock(
            return_value=("solved-agent", "clearance")
        )
        leader, waiter = self.flow(skip=leader_skip), self.flow(skip=waiter_skip)
        for flow in (leader, waiter):
            addon.request(flow)
        first = asyncio.create_task(addon.response(leader))
        await started.wait()
        second = asyncio.create_task(addon.response(waiter))
        await asyncio.sleep(0)
        release.set()
        await asyncio.wait_for(asyncio.gather(first, second), 1)
        assert [leader.response.status_code, waiter.response.status_code] == [200, 200]
        assert not addon.host_locks
        assert all("X-CFSolver-Skip" not in f.request.headers for f in (leader, waiter))
        if waiter_skip:
            assert "cf_clearance" not in waiter.request.headers["Cookie"]
            assert all(
                not kwargs.get("cf_clearance") for f, _, kwargs in calls if f is waiter
            )
        if ttl == 0 or (leader_skip and waiter_skip):
            assert not addon.cf_clearance_store

    @pytest.mark.parametrize(
        "url",
        ["https://b.example/", "https://a.example/other", "http://a.example/private"],
    )
    def test_cookie_scope_is_respected(self, url):
        from http.cookiejar import Cookie
        from cfsolver.tproxy import _find_cookie_value

        cookies = Cookies()
        cookies.jar.set_cookie(
            Cookie(
                0,
                "cf_clearance",
                "secret",
                None,
                False,
                "a.example",
                False,
                False,
                "/private",
                True,
                True,
                None,
                True,
                None,
                None,
                {},
            )
        )
        assert _find_cookie_value(cookies, "cf_clearance", url) is None

    def test_cookie_hostless_compatibility(self):
        from cfsolver.tproxy import _find_cookie_value

        cookies = Cookies()
        cookies.set("cf_clearance", "hostless")
        assert (
            _find_cookie_value(cookies, "cf_clearance", "https://example.com/")
            == "hostless"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure", ["exception", "cancel", "timeout"])
    async def test_leader_failure_wakes_waiters(self, failure):
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon("test", timeout=0.1 if failure == "timeout" else 1)
        entered, release = asyncio.Event(), asyncio.Event()

        async def fetch(*args, **kwargs):
            entered.set()
            await release.wait()
            raise RuntimeError("solve failed")

        addon._fetch_via_solver = fetch
        leader, waiter = self.flow(), self.flow()
        first = asyncio.create_task(addon.response(leader))
        await entered.wait()
        second = asyncio.create_task(addon.response(waiter))
        await asyncio.sleep(0)
        if failure == "cancel":
            first.cancel()
        elif failure == "exception":
            release.set()
        await asyncio.wait_for(asyncio.gather(first, second, return_exceptions=True), 1)
        assert not addon.host_locks
        assert waiter.response.status_code == 403

    @pytest.mark.asyncio
    async def test_cancelled_waiter_does_not_cancel_leader(self):
        from mitmproxy import http
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon("test")
        entered, release = asyncio.Event(), asyncio.Event()

        async def fetch(*args, **kwargs):
            entered.set()
            await release.wait()
            return http.Response.make(200, b"ok")

        addon._fetch_via_solver = fetch
        addon._try_extract_clearance_from_solver = AsyncMock(
            return_value=("agent", "clearance")
        )
        leader, waiter = self.flow(), self.flow()
        first = asyncio.create_task(addon.response(leader))
        await entered.wait()
        second = asyncio.create_task(addon.response(waiter))
        await asyncio.sleep(0)
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        release.set()
        await asyncio.wait_for(first, 1)
        assert leader.response.status_code == 200
        assert not addon.host_locks

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "no_cache,same_host", [(False, False), (True, False), (True, True)]
    )
    async def test_different_hosts_solve_concurrently_with_isolated_state(
        self, monkeypatch, no_cache, same_host
    ):
        from cfsolver import tproxy

        entered = []
        both_entered = asyncio.Event()
        instances = []

        class Solver(AsyncCloudflareSolver):
            def __init__(self, **kwargs):
                assert kwargs["use_cache"] is False
                super().__init__(**kwargs)
                instances.append(self)
                self._api_client.post = AsyncMock(
                    side_effect=lambda *a, **kw: response(
                        payload={"taskId": kw["json"]["task"]["websiteURL"]}
                    )
                )
                self._session = SimpleNamespace(
                    cookies=Cookies(), headers={}, close=AsyncMock(), request=self.send
                )

            async def _connect(self):
                self._linksocks_config = {"url": "ws://test", "connector_token": "test"}

            async def _wait_for_result(self, task_id):
                entered.append(task_id)
                if len(entered) == 2:
                    both_entered.set()
                await both_entered.wait()
                return {
                    "result": {
                        "cookies": {"cf_clearance": task_id},
                        "userAgent": task_id,
                        "ja3_text": task_id,
                    }
                }

            async def _reset_session(self, ja3=None, akamai=None):
                self._ja3, self._akamai = ja3, akamai

            async def send(self, method, url, **kwargs):
                cleared = any(c.value == url for c in self._session.cookies.jar)
                if cleared:
                    assert self._ja3 == url
                    assert self._session.headers["User-Agent"] == url
                    assert method == "POST" and kwargs["data"] == b"order=1"
                    assert kwargs["headers"]["User-Agent"] == url
                    assert f"cf_clearance={url}" in kwargs["headers"]["Cookie"]
                    assert "X-CFSolver-Skip" not in kwargs["headers"]
                return SimpleNamespace(
                    status_code=200 if cleared else 403,
                    content=b"ok",
                    text="challenge",
                    headers={} if cleared else {"cf-mitigated": "challenge"},
                )

        monkeypatch.setattr(tproxy, "AsyncCloudflareSolver", Solver)
        addon = tproxy.CloudAPIProxyAddon("test", no_cache=no_cache)
        flows = [
            self.flow("https://a.example/page"),
            self.flow(
                "https://a.example/page" if same_host else "https://b.example/page"
            ),
        ]
        for flow in flows:
            addon.request(flow)
        try:
            await asyncio.wait_for(
                asyncio.gather(*(addon.response(f) for f in flows)), 1
            )
            assert [f.response.status_code for f in flows] == [200, 200]
            assert len(instances) == 2
            assert all(s._session is None for s in instances)
        finally:
            for solver in instances:
                await solver.aclose()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("skip", [False, True])
    async def test_solver_fetch_post_timeout_does_not_replay(self, monkeypatch, skip):
        from cfsolver import tproxy

        instances, requests = [], []

        class Solver(AsyncCloudflareSolver):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                instances.append(self)
                self._session = SimpleNamespace(
                    cookies=Cookies(), headers={}, close=AsyncMock(), request=self.send
                )

            async def _solve_challenge(self, url, **kwargs):
                self._ja3 = "custom"

            async def send(self, method, url, **kwargs):
                requests.append((method, kwargs["data"]))
                raise TimeoutError("response lost after send")

        monkeypatch.setattr(tproxy, "AsyncCloudflareSolver", Solver)
        addon = tproxy.CloudAPIProxyAddon("test")
        flow = self.flow(skip=skip)
        addon.request(flow)
        await addon.response(flow)
        assert requests == [("POST", b"order=1")]
        assert not addon.host_locks
        assert all(s._closed for s in instances)

    @pytest.mark.asyncio
    async def test_skip_isolates_cached_cookies_and_does_not_write_any_cache(
        self, monkeypatch
    ):
        from cfsolver import tproxy

        instances = []
        sent = []

        class Solver(AsyncCloudflareSolver):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                instances.append(self)
                self._clearance_cache.set(
                    self._get_cache_key("https://example.com/page"),
                    {
                        "cookies": {"cf_clearance": "sdk-cached"},
                        "user_agent": "cached-agent",
                    },
                )
                self._session = SimpleNamespace(
                    cookies=Cookies(), headers={}, close=AsyncMock(), request=self.send
                )

            async def _solve_challenge(self, url, use_cache=None):
                assert use_cache is False
                assert not list(self._session.cookies.jar)
                self._session.cookies.set(
                    "cf_clearance", "own-solve", domain="example.com"
                )
                self._session.headers["User-Agent"] = "own-agent"

            async def send(self, method, url, **kwargs):
                sent.append(kwargs["headers"])
                return SimpleNamespace(status_code=200, content=b"ok", headers={})

        monkeypatch.setattr(tproxy, "AsyncCloudflareSolver", Solver)
        addon = tproxy.CloudAPIProxyAddon("test")
        addon.set_cf_clearance("example.com", "client", "proxy-cached")
        flow = self.flow(skip=True)
        addon.request(flow)
        await addon.response(flow)
        assert flow.response.status_code == 200
        assert flow.request.headers["Cookie"] == "session=private"
        assert sent[0]["Cookie"] == "session=private; cf_clearance=own-solve"
        assert sent[0]["User-Agent"] == "own-agent"
        assert addon.get_cf_clearance_for_host("example.com") == (
            "client",
            "proxy-cached",
        )
        assert all(instance._closed for instance in instances)
        assert all(
            instance._clearance_cache.get(
                instance._get_cache_key("https://example.com/page")
            )
            is None
            for instance in instances
        )
