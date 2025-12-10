import pytest

from cfsolver import CloudflareSolver, AsyncCloudflareSolver


TEST_TARGETS = {
    "cloudflare": {
        "url": "https://2captcha.com/demo/cloudflare-turnstile-challenge",
        "type": "CloudflareChallenge",
    },
    "turnstile": {
        "url": "https://www.coronausa.com",
        "siteKey": "0x4AAAAAAAH4-VmiV_O_wBN-",
        "type": "Turnstile",
    },
}


class TestCloudflareChallenge:
    """Test solving Cloudflare Challenge (2captcha demo)."""

    @pytest.mark.timeout(180)
    def test_solve_cloudflare_challenge(self, solver_kwargs, api_key):
        """Test solving Cloudflare Challenge on 2captcha demo page."""
        if not api_key:
            pytest.skip("API key required")
        
        url = TEST_TARGETS["cloudflare"]["url"]
        
        with CloudflareSolver(**solver_kwargs) as solver:
            resp = solver.get(url)
            
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
            assert "cf-turnstile" not in resp.text.lower() or "challenge" not in resp.text.lower(), \
                "Challenge page still present after solving"
            
            print(f"[CloudflareChallenge] Success! Status: {resp.status_code}")
            print(f"[CloudflareChallenge] Cookies: {dict(solver._session.cookies)}")

    @pytest.mark.timeout(180)
    @pytest.mark.asyncio
    async def test_solve_cloudflare_challenge_async(self, solver_kwargs, api_key):
        """Test solving Cloudflare Challenge asynchronously."""
        if not api_key:
            pytest.skip("API key required")
        
        url = TEST_TARGETS["cloudflare"]["url"]
        
        async with AsyncCloudflareSolver(**solver_kwargs) as solver:
            resp = await solver.get(url)
            
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
            
            print(f"[AsyncCloudflareChallenge] Success! Status: {resp.status_code}")


class TestTurnstile:
    """Test solving Turnstile challenge."""

    @pytest.mark.timeout(180)
    def test_solve_turnstile(self, solver_kwargs, api_key):
        """Test solving Turnstile and getting token."""
        if not api_key:
            pytest.skip("API key required")
        
        url = TEST_TARGETS["turnstile"]["url"]
        sitekey = TEST_TARGETS["turnstile"]["siteKey"]
        
        with CloudflareSolver(**solver_kwargs) as solver:
            token = solver.solve_turnstile(url, sitekey)
            
            assert token, "Expected a token to be returned"
            assert len(token) > 50, f"Token seems too short: {token}"
            
            print(f"[Turnstile] Success! Token: {token[:50]}...")

    @pytest.mark.timeout(180)
    @pytest.mark.asyncio
    async def test_solve_turnstile_async(self, solver_kwargs, api_key):
        """Test solving Turnstile asynchronously."""
        if not api_key:
            pytest.skip("API key required")
        
        url = TEST_TARGETS["turnstile"]["url"]
        sitekey = TEST_TARGETS["turnstile"]["siteKey"]
        
        async with AsyncCloudflareSolver(**solver_kwargs) as solver:
            token = await solver.solve_turnstile(url, sitekey)
            
            assert token, "Expected a token to be returned"
            assert len(token) > 50, f"Token seems too short: {token}"
            
            print(f"[AsyncTurnstile] Success! Token: {token[:50]}...")


class TestBasicFunctionality:
    """Basic functionality tests (no API required)."""

    def test_init(self, solver_kwargs):
        """Test solver initialization."""
        solver = CloudflareSolver(**solver_kwargs, solve=False)
        assert solver.api_base == solver_kwargs["api_base"]
        assert solver.impersonate == "chrome"
        solver.close()

    def test_simple_request_no_solve(self, solver_kwargs):
        """Test HTTP request without solving."""
        with CloudflareSolver(**solver_kwargs, solve=False) as solver:
            resp = solver.get("https://httpbin.org/get")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_async_simple_request_no_solve(self, solver_kwargs):
        """Test async HTTP request without solving."""
        async with AsyncCloudflareSolver(**solver_kwargs, solve=False) as solver:
            resp = await solver.get("https://httpbin.org/get")
            assert resp.status_code == 200

    def test_detect_challenge(self, solver_kwargs):
        """Test challenge detection logic."""
        from unittest.mock import MagicMock
        
        solver = CloudflareSolver(**solver_kwargs, solve=False)
        
        # Normal response - not a challenge
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "nginx"}
        mock_resp.text = "<html>Normal</html>"
        assert solver._detect_challenge(mock_resp) is False
        
        # Cloudflare challenge
        mock_resp.status_code = 403
        mock_resp.headers = {"Server": "cloudflare"}
        mock_resp.text = "Just a moment..."
        assert solver._detect_challenge(mock_resp) is True
        
        solver.close()
