"""
Unit tests for CFSolver.

These tests do NOT require an API key and test basic functionality,
initialization, and challenge detection logic.

Run with: pytest tests/test_solver.py -v
"""

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
        solver = CloudflareSolver(**mock_solver_kwargs, solve=False, impersonate="firefox")
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
                "https://httpbin.org/headers",
                headers={"X-Custom-Header": "test-value"}
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
            **mock_solver_kwargs,
            solve=False,
            proxy="http://proxy.example.com:8080"
        )
        assert solver.user_proxy == "http://proxy.example.com:8080"
        solver.close()

    def test_init_with_api_proxy(self, mock_solver_kwargs):
        """Test solver initialization with separate API proxy."""
        solver = CloudflareSolver(
            **mock_solver_kwargs,
            solve=False,
            proxy="http://fast-proxy:8080",
            api_proxy="http://stable-proxy:8081"
        )
        assert solver.user_proxy == "http://fast-proxy:8080"
        assert solver.api_proxy == "http://stable-proxy:8081"
        solver.close()
