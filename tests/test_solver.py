"""
Unit tests for CFSolver.

These tests do NOT require an API key and test basic functionality,
initialization, and challenge detection logic.

Run with: pytest tests/test_solver.py -v
"""

import importlib.util

import pytest

from cfsolver import AsyncCloudflareSolver, CloudflareSolver


class TestSolverInitialization:
    """Test solver initialization and configuration."""

    def test_init_with_api_key(self, mock_solver_kwargs):
        """Test solver initialization with API key."""
        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)
        assert solver.api_base == mock_solver_kwargs["api_base"]
        assert solver.impersonate == "chrome"
        solver.close()

    def test_init_with_custom_impersonate(self, mock_solver_kwargs):
        """Test solver initialization with custom impersonate."""
        solver = CloudflareSolver(
            **mock_solver_kwargs, solve=False, impersonate="firefox"
        )
        assert solver.impersonate == "firefox"
        solver.close()

    def test_init_with_solve_disabled(self, mock_solver_kwargs):
        """Test solver initialization with solve disabled."""
        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)
        assert solver.solve is False
        solver.close()

    def test_init_with_solve_enabled(self, mock_solver_kwargs):
        """Test solver initialization with solve enabled."""
        solver = CloudflareSolver(**mock_solver_kwargs, solve=True)
        assert solver.solve is True
        solver.close()

    def test_context_manager(self, mock_solver_kwargs):
        """Test solver as context manager."""
        with CloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            assert solver is not None
            assert solver.api_base == mock_solver_kwargs["api_base"]

    @pytest.mark.asyncio
    async def test_async_context_manager(self, mock_solver_kwargs):
        """Test async solver as context manager."""
        async with AsyncCloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            assert solver is not None
            assert solver.api_base == mock_solver_kwargs["api_base"]


class TestChallengeDetection:
    """Test challenge detection logic."""

    def test_detect_challenge_normal_response(self, mock_solver_kwargs):
        """Test that normal responses are not detected as challenges."""
        from unittest.mock import MagicMock

        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.text = "<html><body>Normal page content</body></html>"

        assert solver._detect_challenge(mock_resp) is False
        solver.close()

    def test_detect_challenge_cloudflare_403(self, mock_solver_kwargs):
        """Test detection of Cloudflare 403 challenge."""
        from unittest.mock import MagicMock

        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.headers = {"Server": "cloudflare"}
        mock_resp.text = "Just a moment..."

        assert solver._detect_challenge(mock_resp) is True
        solver.close()

    def test_detect_challenge_cloudflare_503(self, mock_solver_kwargs):
        """Test detection of Cloudflare 503 challenge."""
        from unittest.mock import MagicMock

        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.headers = {"Server": "cloudflare"}
        mock_resp.text = "Just a moment..."

        assert solver._detect_challenge(mock_resp) is True
        solver.close()

    def test_detect_challenge_non_cloudflare_403(self, mock_solver_kwargs):
        """Test that non-Cloudflare 403 is not detected as challenge."""
        from unittest.mock import MagicMock

        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.text = "Access denied"

        assert solver._detect_challenge(mock_resp) is False
        solver.close()

    def _detect(
        self, mock_solver_kwargs, status_code, body, headers=None, markers=None
    ):
        from unittest.mock import MagicMock

        solver = CloudflareSolver(
            **mock_solver_kwargs, solve=False, challenge_markers=markers
        )
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.headers = headers or {"Server": "cloudflare"}
        mock_resp.content = body.encode("utf-8")
        mock_resp.text = body
        try:
            return solver._detect_challenge(mock_resp)
        finally:
            solver.close()

    def test_detect_challenge_200_managed_challenge(self, mock_solver_kwargs):
        """A managed challenge served with 200 must be detected."""
        body = (
            "<html><head><title>Are you a robot?</title></head><body>"
            "<script>window._cf_chl_opt = {cvId: '3'};</script>"
            "</body></html>"
        )
        assert self._detect(mock_solver_kwargs, 200, body) is True

    def test_detect_challenge_200_embeds_turnstile_widget(self, mock_solver_kwargs):
        """A normal page that embeds Turnstile is not a challenge page."""
        body = (
            "<html><body>"
            '<div class="cf-turnstile" data-sitekey="x"></div>'
            '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
            "</body></html>"
        )
        assert self._detect(mock_solver_kwargs, 200, body) is False

    def test_detect_challenge_200_bot_management_script(self, mock_solver_kwargs):
        """The jsd script Cloudflare injects into normal pages is not a challenge."""
        body = (
            "<html><body>real content"
            '<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>'
            "</body></html>"
        )
        assert self._detect(mock_solver_kwargs, 200, body) is False

    def test_detect_challenge_403_orchestrate_page(self, mock_solver_kwargs):
        """Challenge pages referencing the challenge orchestrator are detected."""
        body = (
            "<html><body>"
            '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>'
            "</body></html>"
        )
        assert self._detect(mock_solver_kwargs, 403, body) is True

    def test_detect_challenge_200_large_non_html(self, mock_solver_kwargs):
        """Large non-HTML payloads are not scanned as challenge pages."""
        body = "x" * (300 * 1024)
        headers = {"Server": "cloudflare", "Content-Type": "application/javascript"}
        assert self._detect(mock_solver_kwargs, 200, body, headers) is False

    def test_detect_challenge_mitigated_header(self, mock_solver_kwargs):
        """cf-mitigated marks a challenge without any page marker."""
        body = "<html><body>opaque interstitial</body></html>"
        headers = {"Server": "cloudflare", "cf-mitigated": "challenge"}
        assert self._detect(mock_solver_kwargs, 200, body, headers) is True

    def test_detect_challenge_custom_marker(self, mock_solver_kwargs):
        """User markers force detection on pages Cloudflare did not serve."""
        body = "<html><body><h1>Are you a robot?</h1></body></html>"
        headers = {"Server": "nginx"}
        assert self._detect(mock_solver_kwargs, 200, body, headers) is False
        assert (
            self._detect(
                mock_solver_kwargs,
                200,
                body,
                headers,
                markers=["Are you a robot?"],
            )
            is True
        )


class TestDetectionRules:
    """Test the shared rule table and its structured verdict."""

    @staticmethod
    def _response(status, body, headers=None):
        from unittest.mock import MagicMock

        resp = MagicMock()
        resp.status_code = status
        resp.headers = headers if headers is not None else {}
        resp.content = body.encode("utf-8")
        resp.text = body
        return resp

    def test_mitigated_header_wins(self):
        from cfsolver.detection import CHALLENGE, detect

        resp = self._response(200, "<html>opaque</html>", {"cf-mitigated": "challenge"})
        result = detect(resp)
        assert result.kind == CHALLENGE
        assert result.strong is True
        assert result.reason == "header:cf-mitigated"

    def test_hard_block_is_not_a_challenge(self):
        from cfsolver.detection import BLOCK, detect

        body = "<html><title>Access denied</title>error code: 1020</html>"
        result = detect(self._response(403, body, {"Server": "cloudflare"}))
        assert result.kind == BLOCK
        assert bool(result) is False
        assert result.reason == "error:1020"

    def test_single_weak_marker_without_corroboration_is_suspicious(self):
        from cfsolver.detection import SUSPICIOUS, detect

        result = detect(self._response(403, "Just a moment...", {"Server": "nginx"}))
        assert result.kind == SUSPICIOUS
        assert bool(result) is False

    def test_single_weak_marker_with_cloudflare_server_is_challenge(self):
        from cfsolver.detection import CHALLENGE, detect

        result = detect(
            self._response(403, "Just a moment...", {"Server": "cloudflare"})
        )
        assert result.kind == CHALLENGE
        assert result.strong is False

    def test_two_weak_markers_are_enough(self):
        from cfsolver.detection import CHALLENGE, detect

        body = (
            "Just a moment... <noscript>Please enable JavaScript and cookies</noscript>"
        )
        result = detect(self._response(503, body, {"Server": "nginx"}))
        assert result.kind == CHALLENGE

    def test_override_matches_any_status_code(self):
        from cfsolver.detection import CHALLENGE, detect

        resp = self._response(200, '{"error": "Are you a robot?"}', {})
        assert detect(resp).kind != CHALLENGE
        assert detect(resp, overrides=["are you a robot?"]).kind == CHALLENGE

    def test_weak_markers_ignored_on_success_status(self):
        from cfsolver.detection import NONE, detect

        result = detect(
            self._response(200, "Just a moment...", {"Server": "cloudflare"})
        )
        assert result.kind == NONE


class TestClearanceCache:
    """Empty solves must not enter the solver clearance cache."""

    def test_empty_solution_is_not_saved(self, mock_solver_kwargs):
        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)
        CloudflareSolver.clear_cache()
        solver._save_to_cache("https://example.com", {}, None, None, None)
        assert solver._load_from_cache("https://example.com") is False
        solver.close()

    @pytest.mark.asyncio
    async def test_empty_solution_is_not_saved_in_async_solver(
        self, mock_solver_kwargs
    ):
        async with AsyncCloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            await AsyncCloudflareSolver.clear_cache()
            await solver._save_to_cache("https://example.com", {}, None, None, None)
            assert await solver._load_from_cache("https://example.com") is False


@pytest.mark.skipif(
    importlib.util.find_spec("mitmproxy") is None,
    reason="mitmproxy is only installed with cfsolver[proxy]",
)
class TestProxyClearanceCache:
    """Only a cleared page may seed the proxy clearance store."""

    @staticmethod
    def _flow(url="https://example.com/protected"):
        from types import SimpleNamespace
        from mitmproxy import http

        return SimpleNamespace(
            request=http.Request.make("GET", url, headers={"User-Agent": "test-agent"}),
            response=http.Response.make(
                403, b"Just a moment...", {"Server": "cloudflare"}
            ),
        )

    @pytest.mark.asyncio
    async def test_error_response_does_not_store_clearance(self):
        from unittest.mock import AsyncMock
        from mitmproxy import http
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon(api_key="test-key")
        flow = self._flow()
        addon._fetch_via_solver = AsyncMock(
            return_value=http.Response.make(
                403, b"Just a moment...", {"Server": "cloudflare"}
            )
        )
        addon._try_extract_clearance_from_solver = AsyncMock(
            return_value=("test-agent", "stale-clearance")
        )

        await addon.response(flow)

        assert flow.response.status_code == 403
        assert addon.get_cf_clearance("example.com", "test-agent") is None

    @pytest.mark.asyncio
    async def test_cleared_response_stores_clearance(self):
        from unittest.mock import AsyncMock
        from mitmproxy import http
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon(api_key="test-key")
        flow = self._flow()
        addon._fetch_via_solver = AsyncMock(
            return_value=http.Response.make(
                200, b"<html>article</html>", {"Content-Type": "text/html"}
            )
        )
        addon._try_extract_clearance_from_solver = AsyncMock(
            return_value=("test-agent", "fresh-clearance")
        )

        await addon.response(flow)

        assert addon.get_cf_clearance("example.com", "test-agent") == "fresh-clearance"

    @pytest.mark.asyncio
    async def test_page_still_challenging_does_not_store_clearance(self):
        from unittest.mock import AsyncMock
        from mitmproxy import http
        from cfsolver.tproxy import CloudAPIProxyAddon

        addon = CloudAPIProxyAddon(api_key="test-key")
        flow = self._flow()
        still_challenge = b"<html><script>window._cf_chl_opt = {};</script></html>"
        addon._fetch_via_solver = AsyncMock(
            return_value=http.Response.make(
                200, still_challenge, {"Content-Type": "text/html"}
            )
        )
        addon._try_extract_clearance_from_solver = AsyncMock(
            return_value=("test-agent", "unused-clearance")
        )

        await addon.response(flow)

        assert addon.get_cf_clearance("example.com", "test-agent") is None


class TestBasicRequests:
    """Test basic HTTP requests without challenge solving."""

    def test_simple_get_request(self, mock_solver_kwargs):
        """Test simple GET request without solving."""
        with CloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            resp = solver.get("https://httpbin.org/get")
            assert resp.status_code == 200

    def test_simple_post_request(self, mock_solver_kwargs):
        """Test simple POST request without solving."""
        with CloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            resp = solver.post("https://httpbin.org/post", json={"test": "data"})
            assert resp.status_code == 200
            assert "test" in resp.json().get("json", {})

    def test_request_with_headers(self, mock_solver_kwargs):
        """Test request with custom headers."""
        with CloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            resp = solver.get(
                "https://httpbin.org/headers", headers={"X-Custom-Header": "test-value"}
            )
            assert resp.status_code == 200
            headers = resp.json().get("headers", {})
            assert headers.get("X-Custom-Header") == "test-value"

    @pytest.mark.asyncio
    async def test_async_simple_get_request(self, mock_solver_kwargs):
        """Test async GET request without solving."""
        async with AsyncCloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            resp = await solver.get("https://httpbin.org/get")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_simple_post_request(self, mock_solver_kwargs):
        """Test async POST request without solving."""
        async with AsyncCloudflareSolver(**mock_solver_kwargs, solve=False) as solver:
            resp = await solver.post("https://httpbin.org/post", json={"test": "data"})
            assert resp.status_code == 200


class TestSolvingModes:
    """Test different solving modes."""

    def test_mode_auto_detect(self, mock_solver_kwargs):
        """Test auto-detect mode (solve=True, on_challenge=True)."""
        solver = CloudflareSolver(**mock_solver_kwargs, solve=True, on_challenge=True)
        assert solver.solve is True
        assert solver.on_challenge is True
        solver.close()

    def test_mode_always_solve(self, mock_solver_kwargs):
        """Test always-solve mode (solve=True, on_challenge=False)."""
        solver = CloudflareSolver(**mock_solver_kwargs, solve=True, on_challenge=False)
        assert solver.solve is True
        assert solver.on_challenge is False
        solver.close()

    def test_mode_disabled(self, mock_solver_kwargs):
        """Test disabled mode (solve=False)."""
        solver = CloudflareSolver(**mock_solver_kwargs, solve=False)
        assert solver.solve is False
        solver.close()


class TestProxyConfiguration:
    """Test proxy configuration."""

    def test_init_with_proxy(self, mock_solver_kwargs):
        """Test solver initialization with proxy."""
        solver = CloudflareSolver(
            **mock_solver_kwargs, solve=False, proxy="http://proxy.example.com:8080"
        )
        assert solver.user_proxy == "http://proxy.example.com:8080"
        solver.close()

    def test_init_with_api_proxy(self, mock_solver_kwargs):
        """Test solver initialization with separate API proxy."""
        solver = CloudflareSolver(
            **mock_solver_kwargs,
            solve=False,
            proxy="http://fast-proxy:8080",
            api_proxy="http://stable-proxy:8081",
        )
        assert solver.user_proxy == "http://fast-proxy:8080"
        assert solver.api_proxy == "http://stable-proxy:8081"
        solver.close()
