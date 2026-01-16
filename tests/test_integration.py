"""
Integration tests for CFSolver.

These tests require a valid API key and make real API calls.
They are skipped automatically if CLOUDFLYER_API_KEY is not set.

Run with: pytest tests/test_integration.py -v --timeout=300
"""

import os

import pytest

from cfsolver import AsyncCloudflareSolver, CloudflareSolver


pytestmark = pytest.mark.integration


def requires_api_key(func):
    """Decorator to skip tests if API key is not available."""
    return pytest.mark.skipif(
        not os.environ.get("CLOUDFLYER_API_KEY"),
        reason="CLOUDFLYER_API_KEY not set"
    )(func)


TEST_TARGETS = {
    "cloudflare": {
        "url": "https://cloudflyer.zetx.site/demo/challenge",
        "type": "CloudflareChallenge",
    },
    "turnstile": {
        "url": "https://cloudflyer.zetx.site/demo/turnstile",
        "siteKey": "0x4AAAAAACJkAlPHW8xr1T2J",
        "type": "Turnstile",
    },
}


class TestIntegrationCloudflareChallenge:
    """Integration tests for Cloudflare Challenge solving."""

    @requires_api_key
    @pytest.mark.timeout(180)
    def test_integration_solve_cloudflare_challenge(self, solver_kwargs):
        """Test solving Cloudflare Challenge on demo page."""
        url = TEST_TARGETS["cloudflare"]["url"]

        with CloudflareSolver(**solver_kwargs) as solver:
            resp = solver.get(url)

            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
            assert "cf-turnstile" not in resp.text.lower() or "challenge" not in resp.text.lower(), \
                "Challenge page still present after solving"

            print(f"[Integration][CloudflareChallenge] Success! Status: {resp.status_code}")
            print(f"[Integration][CloudflareChallenge] Cookies: {dict(solver._session.cookies)}")

    @requires_api_key
    @pytest.mark.timeout(180)
    @pytest.mark.asyncio
    async def test_integration_solve_cloudflare_challenge_async(self, solver_kwargs):
        """Test solving Cloudflare Challenge asynchronously."""
        url = TEST_TARGETS["cloudflare"]["url"]

        async with AsyncCloudflareSolver(**solver_kwargs) as solver:
            resp = await solver.get(url)

            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

            print(f"[Integration][AsyncCloudflareChallenge] Success! Status: {resp.status_code}")


class TestIntegrationTurnstile:
    """Integration tests for Turnstile challenge solving."""

    @requires_api_key
    @pytest.mark.timeout(180)
    def test_integration_solve_turnstile(self, solver_kwargs):
        """Test solving Turnstile and getting token."""
        url = TEST_TARGETS["turnstile"]["url"]
        sitekey = TEST_TARGETS["turnstile"]["siteKey"]

        with CloudflareSolver(**solver_kwargs) as solver:
            token = solver.solve_turnstile(url, sitekey)

            assert token, "Expected a token to be returned"
            assert len(token) > 50, f"Token seems too short: {token}"

            print(f"[Integration][Turnstile] Success! Token: {token[:50]}...")

    @requires_api_key
    @pytest.mark.timeout(180)
    @pytest.mark.asyncio
    async def test_integration_solve_turnstile_async(self, solver_kwargs):
        """Test solving Turnstile asynchronously."""
        url = TEST_TARGETS["turnstile"]["url"]
        sitekey = TEST_TARGETS["turnstile"]["siteKey"]

        async with AsyncCloudflareSolver(**solver_kwargs) as solver:
            token = await solver.solve_turnstile(url, sitekey)

            assert token, "Expected a token to be returned"
            assert len(token) > 50, f"Token seems too short: {token}"

            print(f"[Integration][AsyncTurnstile] Success! Token: {token[:50]}...")


class TestIntegrationBalance:
    """Integration tests for balance checking."""

    @requires_api_key
    @pytest.mark.timeout(30)
    def test_integration_check_balance(self, solver_kwargs):
        """Test checking account balance."""
        with CloudflareSolver(**solver_kwargs) as solver:
            balance = solver.get_balance()

            assert balance is not None, "Expected balance to be returned"
            assert isinstance(balance, (int, float)), f"Expected numeric balance, got {type(balance)}"

            print(f"[Integration][Balance] Current balance: {balance}")
