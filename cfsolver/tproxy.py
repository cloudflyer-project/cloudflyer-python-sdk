"""
Transparent proxy with Cloudflare challenge detection using cloud API.

This module provides a MITM proxy that automatically detects and solves
Cloudflare challenges using the CloudFlyer cloud API, without requiring
a local browser instance.
"""

import asyncio
import logging
import socket
import threading
import time
import signal
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse

import httpx
from mitmproxy import http, options, ctx
from mitmproxy.tools.dump import DumpMaster

from .client import CloudflareSolver
from .exceptions import CFSolverProxyError

logger = logging.getLogger(__name__)

# Default challenge page title patterns (multi-language support)
DEFAULT_TITLE_INDICATORS = [
    "<title>Just a moment...</title>",
    "<title>请稀候…</title>",
    "<title>请稍候...</title>",
    "<title>Un instant...</title>",
    "<title>Einen Moment...</title>",
    "<title>Un momento...</title>",
    "<title>Bir dakika...</title>",
    "<title>Um momento...</title>",
    "<title>Een moment...</title>",
    "<title>ちょっと待ってください...</title>",
    "<title>Подождите...</title>",
]

# Default Cloudflare-specific indicators (high confidence)
DEFAULT_CF_INDICATORS = [
    "cf-challenge-running",
    "cloudflare-challenge",
    "cf_challenge_response",
    "cf-under-attack",
    "cf-checking-browser",
    "/cdn-cgi/challenge-platform",
]


class CloudflareDetector:
    """Cloudflare challenge detection logic."""

    def __init__(
        self,
        extra_title_indicators: Optional[list] = None,
        extra_cf_indicators: Optional[list] = None,
    ):
        """
        Initialize detector with optional extra indicators.

        Args:
            extra_title_indicators: Additional title patterns to detect challenge pages
            extra_cf_indicators: Additional Cloudflare-specific indicators
        """
        self.title_indicators = list(DEFAULT_TITLE_INDICATORS)
        self.cf_indicators = list(DEFAULT_CF_INDICATORS)

        if extra_title_indicators:
            self.title_indicators.extend(extra_title_indicators)
        if extra_cf_indicators:
            self.cf_indicators.extend(extra_cf_indicators)

    def is_cloudflare_challenge(self, response: http.Response) -> bool:
        """Check if response contains Cloudflare challenge."""
        if not response or not response.content:
            return False

        # Cloudflare challenge pages typically return 403, 503, or 429
        # Normal pages with status 200 should not be treated as challenges
        if response.status_code == 200:
            return False

        try:
            content = response.content.decode("utf-8", errors="ignore")
        except:
            return False

        content_lower = content.lower()

        # Check title indicators with additional validation
        for indicator in self.title_indicators:
            if indicator.lower() in content_lower:
                if any(cf.lower() in content_lower for cf in self.cf_indicators):
                    logger.debug(f"Detected Cloudflare challenge: title={indicator}")
                    return True
                if (
                    'id="challenge' in content_lower
                    or 'class="no-js">' in content_lower
                ):
                    logger.debug(f"Detected challenge page with title: {indicator}")
                    return True
                if response.status_code in [403, 503, 429]:
                    logger.debug(
                        f"Detected challenge by title and status code: {indicator}"
                    )
                    return True

        # Direct CF indicator matches - only for non-200 responses
        if response.status_code in [403, 503, 429]:
            for indicator in self.cf_indicators:
                if indicator.lower() in content_lower:
                    logger.debug(
                        f"Detected Cloudflare challenge indicator: {indicator}"
                    )
                    return True

        return False


class CloudAPIProxyAddon:
    """MITM addon for transparent proxy with cloud-based challenge solving."""

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://solver.zetx.site",
        user_proxy: Optional[str] = None,
        api_proxy: Optional[str] = None,
        impersonate: str = "chrome",
        enable_detection: bool = True,
        no_cache: bool = False,
        timeout: int = 120,
        extra_title_indicators: Optional[list] = None,
        extra_cf_indicators: Optional[list] = None,
    ):
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.user_proxy = user_proxy
        self.api_proxy = api_proxy
        self.impersonate = impersonate
        self.enable_detection = enable_detection
        self.no_cache = no_cache
        self.timeout = timeout

        self.detector = (
            CloudflareDetector(
                extra_title_indicators=extra_title_indicators,
                extra_cf_indicators=extra_cf_indicators,
            )
            if enable_detection
            else None
        )

        # Host-level locks for serializing challenge solving
        self.host_locks: Dict[str, threading.Event] = {}
        self.host_lock = threading.Lock()

        # Store cf_clearance cookies keyed by host and User-Agent
        # Structure: {host: {user_agent: cf_clearance}}
        self.cf_clearance_store: Dict[str, Dict[str, str]] = {}
        self._store_lock = threading.Lock()

        # Pre-start CloudflareSolver with pywssocks provider
        # This establishes the linksocks tunnel for server to access user's network
        self._solver: Optional[CloudflareSolver] = None
        if enable_detection:
            try:
                self._solver = CloudflareSolver(
                    api_key=api_key,
                    api_base=api_base,
                    proxy=user_proxy,
                    api_proxy=api_proxy,
                    impersonate=impersonate,
                    solve=True,
                    on_challenge=False,
                )
                # Pre-connect to establish linksocks tunnel
                self._solver._connect()
                logger.info("CloudflareSolver initialized with linksocks tunnel")
            except Exception as e:
                logger.warning(f"Failed to initialize CloudflareSolver: {e}")
                self._solver = None

    @staticmethod
    def inject_cookie(flow: http.HTTPFlow, cookie_name: str, cookie_value: str) -> None:
        """Safely inject or update a cookie in the request headers."""
        if not cookie_name or not cookie_value:
            return

        try:
            original_cookie = flow.request.headers.get("Cookie", "")
            cookies = []
            cookie_name_lower = cookie_name.lower()
            target_updated = False

            if original_cookie:
                for part in original_cookie.split(";"):
                    part = part.strip()
                    if not part:
                        continue

                    if "=" in part:
                        current_name = part.split("=", 1)[0].strip()
                    else:
                        current_name = part

                    if current_name.lower() == cookie_name_lower:
                        if not target_updated:
                            cookies.append(f"{cookie_name}={cookie_value}")
                            target_updated = True
                        continue

                    cookies.append(part)

            if not target_updated:
                cookies.append(f"{cookie_name}={cookie_value}")

            flow.request.headers["Cookie"] = "; ".join(cookies)

        except Exception as e:
            logger.debug(f"Failed to inject cookie {cookie_name}: {e}")
            try:
                existing = flow.request.headers.get("Cookie", "")
                if existing:
                    flow.request.headers["Cookie"] = (
                        f"{existing}; {cookie_name}={cookie_value}"
                    )
                else:
                    flow.request.headers["Cookie"] = f"{cookie_name}={cookie_value}"
            except Exception:
                pass

    def request(self, flow: http.HTTPFlow):
        """Handle incoming request - inject cached cf_clearance if available."""
        if self.no_cache:
            return

        # Inject stored cf_clearance for first request if available (keyed by host and UA)
        try:
            ua = flow.request.headers.get("User-Agent")
            host = flow.request.host
            if ua and host:
                cf_val = self.get_cf_clearance(host, ua)
                if cf_val:
                    self.inject_cookie(flow, "cf_clearance", cf_val)
                    logger.debug(f"[Cache HIT] Injected cf_clearance for {host}")
                else:
                    # Fallback: reuse any stored cf_clearance for this host and align UA
                    stored = self.get_cf_clearance_for_host(host)
                    if stored:
                        stored_ua, stored_cf = stored
                        if stored_ua:
                            flow.request.headers["User-Agent"] = stored_ua
                        self.inject_cookie(flow, "cf_clearance", stored_cf)
                        logger.debug(
                            f"[Cache HIT fallback] Injected cf_clearance for {host}"
                        )
                    else:
                        logger.debug(f"[Cache MISS] No cf_clearance for {host}")
        except Exception:
            # Do not block on injection errors
            pass

    async def response(self, flow: http.HTTPFlow):
        """Handle response - detect challenge and solve via cloud API."""
        if not self.enable_detection or not flow.response:
            return

        # Skip CF internal API requests
        request_path = flow.request.path
        if (
            "/cdn-cgi/challenge-platform" in request_path
            or flow.request.host == "challenges.cloudflare.com"
        ):
            return

        # Check if this is a Cloudflare challenge
        if self.detector and self.detector.is_cloudflare_challenge(flow.response):
            host = flow.request.host
            is_solver = False

            # In no_cache mode, every request solves independently (no host-level serialization)
            if self.no_cache:
                is_solver = True
            else:
                with self.host_lock:
                    if host not in self.host_locks:
                        self.host_locks[host] = threading.Event()
                        is_solver = True

            url = flow.request.pretty_url
            try:
                loop = asyncio.get_running_loop()

                if not is_solver:
                    event = self.host_locks.get(host)
                    if event:
                        await loop.run_in_executor(None, event.wait, 120.0)

                    # After waiting, get stored cf_clearance and re-fetch
                    stored = self.get_cf_clearance_for_host(host)
                    if stored:
                        stored_ua, stored_cf = stored
                        # Re-fetch the URL with the solved cookies
                        refetch_result = await loop.run_in_executor(
                            None,
                            self._refetch_with_cookies,
                            url,
                            stored_cf,
                            stored_ua,
                            flow,
                        )
                        if refetch_result:
                            flow.response = refetch_result
                            logger.debug(
                                f"Waiter re-fetched {url} with stored cf_clearance"
                            )
                    return

                # This is the solver thread
                logger.info(
                    f"Detected Cloudflare challenge for {url}, solving via cloud API..."
                )

                # Solve challenge using cloud API
                result = await loop.run_in_executor(None, self._solve_challenge, url)

                if result and result.get("success"):
                    solution = result.get("solution", {})
                    cookies = solution.get("cookies", {})
                    headers = solution.get("headers", {})
                    user_agent = headers.get("User-Agent")
                    cf_clearance = cookies.get("cf_clearance")

                    # Persist cf_clearance for future first-send usage when available
                    if not self.no_cache and user_agent and cf_clearance:
                        self.set_cf_clearance(host, user_agent, cf_clearance)
                        logger.info(f"[Cache STORE] Stored cf_clearance for {host}")
                    else:
                        logger.warning(
                            f"[Cache SKIP] user_agent={bool(user_agent)}, cf_clearance={bool(cf_clearance)}"
                        )

                    # Check if we have response content - if so, return it directly
                    response_data = solution.get("response")
                    if response_data and isinstance(response_data, dict):
                        resp_headers = response_data.get("headers", {})
                        resp_status = response_data.get("status_code", 200)
                        resp_content = response_data.get("content", "")

                        # Directly replace the response, no replay needed
                        flow.response = http.Response.make(
                            resp_status,
                            (
                                resp_content.encode("utf-8")
                                if isinstance(resp_content, str)
                                else resp_content
                            ),
                            resp_headers,
                        )
                        logger.info(f"Challenge solved, returning response directly")
                        return

                    # No response content from solver, re-fetch with cookies/UA
                    if cf_clearance:
                        refetch_result = await loop.run_in_executor(
                            None,
                            self._refetch_with_cookies,
                            url,
                            cf_clearance,
                            user_agent,
                            flow,
                        )
                        if refetch_result:
                            flow.response = refetch_result
                            logger.info(
                                f"Challenge solved, re-fetched content successfully"
                            )
                            return

                    logger.warning(
                        f"Challenge solved but no cf_clearance cookie received"
                    )
                else:
                    error = (
                        result.get("error", "Unknown error")
                        if result
                        else "No response"
                    )
                    logger.error(f"Challenge solve failed: {error}")

            except Exception as e:
                logger.error(f"Error resolving challenge for {url}: {e}")
            finally:
                # Only release lock if we acquired one (i.e., not in no_cache mode)
                # Ensure lock is always released even if exceptions occur before try block
                if not self.no_cache and is_solver:
                    with self.host_lock:
                        if host in self.host_locks:
                            self.host_locks[host].set()
                            del self.host_locks[host]

    def _refetch_with_cookies(
        self,
        url: str,
        cf_clearance: str,
        user_agent: Optional[str],
        flow: http.HTTPFlow,
    ) -> Optional[http.Response]:
        """Re-fetch URL with cf_clearance cookie and return mitmproxy Response."""
        try:
            # Build headers from original request
            headers = dict(flow.request.headers)
            if user_agent:
                headers["User-Agent"] = user_agent

            # Build cookies
            original_cookie = headers.get("Cookie", "")
            cookie_parts = [
                p.strip()
                for p in original_cookie.split(";")
                if p.strip() and not p.strip().lower().startswith("cf_clearance=")
            ]
            cookie_parts.append(f"cf_clearance={cf_clearance}")
            headers["Cookie"] = "; ".join(cookie_parts)

            # Remove hop-by-hop headers that shouldn't be forwarded
            for h in [
                "Host",
                "Connection",
                "Proxy-Connection",
                "Keep-Alive",
                "Transfer-Encoding",
                "TE",
                "Trailer",
                "Upgrade",
            ]:
                headers.pop(h, None)

            # Determine proxy for httpx
            proxies = None
            if self.user_proxy:
                proxies = {"http://": self.user_proxy, "https://": self.user_proxy}

            # Make the request
            with httpx.Client(
                proxies=proxies, verify=False, timeout=30.0, follow_redirects=True
            ) as client:
                method = flow.request.method
                content = flow.request.content

                resp = client.request(method, url, headers=headers, content=content)

                # Convert to mitmproxy Response
                resp_headers = dict(resp.headers)
                return http.Response.make(resp.status_code, resp.content, resp_headers)
        except Exception as e:
            logger.error(f"Failed to re-fetch {url}: {e}")
            return None

    def _solve_challenge(self, url: str) -> Dict[str, Any]:
        """Solve Cloudflare challenge and return response content directly."""
        if not self._solver:
            # Fallback: try to create solver on demand
            try:
                self._solver = CloudflareSolver(
                    api_key=self.api_key,
                    api_base=self.api_base,
                    proxy=self.user_proxy,
                    api_proxy=self.api_proxy,
                    impersonate=self.impersonate,
                    solve=True,
                    on_challenge=False,
                )
                self._solver._connect()
            except Exception as e:
                return {"success": False, "error": f"Failed to initialize solver: {e}"}

        try:
            # Ensure linksocks tunnel is connected
            self._solver._connect()

            if not self._solver._linksocks_config:
                return {
                    "success": False,
                    "error": "CloudFlyer service unavailable: connection failed",
                }

            # Call API directly with response=True to get page content
            with httpx.Client(
                verify=False, proxy=self.api_proxy, timeout=30.0
            ) as api_client:
                resp = api_client.post(
                    f"{self.api_base}/api/createTask",
                    json={
                        "apiKey": self.api_key,
                        "task": {
                            "type": "CloudflareTask",
                            "websiteURL": url,
                            "response": True,  # Request response content
                            "linksocks": {
                                "url": self._solver._linksocks_config["url"],
                                "token": self._solver._linksocks_config[
                                    "connector_token"
                                ],
                            },
                        },
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            if data.get("errorId"):
                return {
                    "success": False,
                    "error": data.get("errorDescription", "Unknown error"),
                }

            task_id = data["taskId"]
            logger.debug(f"Task created: {task_id}")

            # Wait for result
            result = self._wait_for_task_result(task_id)
            if not result:
                return {"success": False, "error": "Task timed out"}

            # Extract solution from worker result
            worker_result = result.get("result") or {}
            if isinstance(worker_result.get("result"), dict):
                solution = worker_result["result"]
            else:
                solution = worker_result

            if not isinstance(solution, dict):
                return {"success": False, "error": "Invalid response from server"}

            cookies = solution.get("cookies", {})
            user_agent = solution.get("userAgent")
            headers = solution.get("headers", {})
            if not user_agent and isinstance(headers, dict):
                user_agent = headers.get("User-Agent")

            # Build response data if available
            response_data = None
            if solution.get("response"):
                resp_info = solution["response"]
                response_data = {
                    "status_code": resp_info.get(
                        "status_code", resp_info.get("statusCode", 200)
                    ),
                    "headers": resp_info.get("headers", {}),
                    "content": resp_info.get("content", resp_info.get("text", "")),
                }

            result_solution = {
                "cookies": cookies,
                "headers": {"User-Agent": user_agent} if user_agent else {},
            }
            if response_data:
                result_solution["response"] = response_data

            logger.info("Challenge solved successfully via CloudflareSolver")
            return {"success": True, "solution": result_solution}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _wait_for_task_result(
        self, task_id: str, timeout: int = 120
    ) -> Optional[Dict[str, Any]]:
        """Wait for task result using long-polling."""
        start = time.time()

        with httpx.Client(verify=False, proxy=self.api_proxy, timeout=130.0) as client:
            while time.time() - start < timeout:
                try:
                    res = client.post(
                        f"{self.api_base}/api/waitTaskResult",
                        json={"apiKey": self.api_key, "taskId": task_id},
                    )

                    if res.status_code != 200:
                        time.sleep(2)
                        continue

                    result = res.json()
                    status = result.get("status")

                    if status == "processing" or status == "timeout":
                        continue

                    success = result.get("success")
                    if isinstance(success, bool) and success:
                        return result
                    if status in ("completed", "ready") and not result.get("error"):
                        return result

                    # Task failed
                    logger.error(f"Task failed: {result.get('error', 'Unknown error')}")
                    return None

                except Exception as e:
                    logger.debug(f"Poll error: {e}")
                    time.sleep(2)

        return None

    # --- cf_clearance store helpers ---
    def set_cf_clearance(self, host: str, user_agent: str, cf_clearance: str) -> None:
        """Store cf_clearance for host and User-Agent."""
        if not host or not user_agent or not cf_clearance:
            return
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if inner is None:
                inner = {}
                self.cf_clearance_store[key_host] = inner
            inner[user_agent] = cf_clearance

    def get_cf_clearance(self, host: str, user_agent: str) -> Optional[str]:
        """Retrieve cf_clearance for host and User-Agent if present."""
        if not host or not user_agent:
            return None
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if not inner:
                return None
            return inner.get(user_agent)

    def get_cf_clearance_for_host(self, host: str) -> Optional[tuple]:
        """Get any stored cf_clearance for a host. Returns (user_agent, cf_clearance) tuple."""
        if not host:
            return None
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if not inner:
                return None
            for ua, cf in inner.items():
                if ua and cf:
                    return ua, cf
            return None

    def clear_cf_clearance(
        self, host: Optional[str] = None, user_agent: Optional[str] = None
    ) -> None:
        """Clear stored cf_clearance entries."""
        with self._store_lock:
            if host is None and user_agent is None:
                self.cf_clearance_store.clear()
                return
            if host is not None:
                key_host = host.lower()
                if key_host in self.cf_clearance_store:
                    if user_agent is None:
                        self.cf_clearance_store.pop(key_host, None)
                    else:
                        inner = self.cf_clearance_store.get(key_host, {})
                        inner.pop(user_agent, None)
                        if not inner:
                            self.cf_clearance_store.pop(key_host, None)


class CloudAPITransparentProxy:
    """Transparent proxy server using cloud API for challenge solving."""

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://solver.zetx.site",
        host: str = "127.0.0.1",
        port: int = 8080,
        user_proxy: Optional[str] = None,
        api_proxy: Optional[str] = None,
        impersonate: str = "chrome",
        enable_detection: bool = True,
        no_cache: bool = False,
        timeout: int = 120,
        extra_title_indicators: Optional[list] = None,
        extra_cf_indicators: Optional[list] = None,
    ):
        self.api_key = api_key
        self.api_base = api_base
        self.host = host
        self.port = port
        self.user_proxy = user_proxy
        self.api_proxy = api_proxy
        self.impersonate = impersonate
        self.enable_detection = enable_detection
        self.no_cache = no_cache
        self.timeout = timeout

        # pproxy bridge for SOCKS proxy support
        self._pproxy_server = None
        self._pproxy_thread = None
        self._pproxy_port = None
        self._effective_upstream = None  # The actual upstream proxy for mitmproxy

        self.addon = CloudAPIProxyAddon(
            api_key=api_key,
            api_base=api_base,
            user_proxy=user_proxy,
            api_proxy=api_proxy,
            impersonate=impersonate,
            enable_detection=enable_detection,
            no_cache=no_cache,
            timeout=timeout,
            extra_title_indicators=extra_title_indicators,
            extra_cf_indicators=extra_cf_indicators,
        )

        self._master = None
        self._thread = None
        self._running = False
        self._loop = None
        self._started_event = threading.Event()

    def _find_free_port(self) -> int:
        """Find a free port for pproxy."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _parse_proxy_url(
        self, proxy_url: str
    ) -> Tuple[str, Optional[str], Optional[str]]:
        """Parse proxy URL and return (scheme, host:port, auth)."""
        parsed = urlparse(proxy_url)
        scheme = parsed.scheme.lower()

        host_port = parsed.hostname
        if parsed.port:
            host_port = f"{parsed.hostname}:{parsed.port}"

        auth = None
        if parsed.username:
            if parsed.password:
                auth = f"{parsed.username}:{parsed.password}"
            else:
                auth = parsed.username

        return scheme, host_port, auth

    def _start_pproxy_bridge(self, socks_proxy: str) -> str:
        """Start pproxy as HTTP-to-SOCKS bridge and return local HTTP proxy URL."""
        try:
            import pproxy
        except ImportError:
            raise CFSolverProxyError(
                "pproxy is required for SOCKS proxy support. Install it with: pip install pproxy"
            )

        scheme, host_port, auth = self._parse_proxy_url(socks_proxy)

        # Build pproxy remote URI
        if auth:
            remote_uri = f"{scheme}://{host_port}#{auth}"
        else:
            remote_uri = f"{scheme}://{host_port}"

        self._pproxy_port = self._find_free_port()
        local_uri = f"http://127.0.0.1:{self._pproxy_port}"

        logger.info(
            f"Starting pproxy bridge on port {self._pproxy_port} -> {scheme}://{host_port}"
        )

        def run_pproxy():
            pproxy_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(pproxy_loop)

            try:
                server = pproxy.Server(local_uri)
                remote = pproxy.Connection(remote_uri)
                args = dict(
                    rserver=[remote], verbose=lambda x: logger.debug(f"pproxy: {x}")
                )

                handler = pproxy_loop.run_until_complete(server.start_server(args))
                self._pproxy_server = handler

                pproxy_loop.run_forever()
            except Exception as e:
                logger.error(f"pproxy error: {e}")
            finally:
                if self._pproxy_server:
                    self._pproxy_server.close()
                pproxy_loop.close()

        self._pproxy_thread = threading.Thread(target=run_pproxy, daemon=True)
        self._pproxy_thread.start()

        # Wait for pproxy to start
        time.sleep(0.5)

        return f"http://127.0.0.1:{self._pproxy_port}"

    def _stop_pproxy_bridge(self):
        """Stop the pproxy bridge."""
        if self._pproxy_server:
            try:
                self._pproxy_server.close()
            except Exception:
                pass
            self._pproxy_server = None
        self._pproxy_thread = None
        self._pproxy_port = None

    def start(self):
        """Start the transparent proxy server."""
        if self._running:
            raise CFSolverProxyError("Proxy is already running")

        # Determine effective upstream proxy for mitmproxy
        # mitmproxy doesn't support SOCKS5 upstream directly, so we use pproxy as bridge
        if self.user_proxy:
            parsed = urlparse(self.user_proxy)
            if parsed.scheme.lower() in ("socks5", "socks4", "socks"):
                # Start pproxy bridge for SOCKS proxy
                self._effective_upstream = self._start_pproxy_bridge(self.user_proxy)
                logger.info(
                    f"Using pproxy bridge for SOCKS proxy: {self._effective_upstream}"
                )
            else:
                # HTTP proxy can be used directly
                self._effective_upstream = self.user_proxy
        else:
            self._effective_upstream = None

        def run_proxy():
            if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            def _ignore_winerror_64(loop, context):
                exc = context.get("exception")
                if isinstance(exc, OSError) and getattr(exc, "winerror", None) == 64:
                    logger.debug("Ignored WinError 64")
                    return
                loop.default_exception_handler(context)

            self._loop = asyncio.new_event_loop()
            self._loop.set_exception_handler(_ignore_winerror_64)
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run_proxy())

        self._thread = threading.Thread(target=run_proxy, daemon=True)
        self._thread.start()

        self._started_event.clear()
        started = self._started_event.wait(timeout=15)

        if not started or not self._running:
            try:
                self.stop()
            except Exception:
                pass
            raise CFSolverProxyError("Failed to start transparent proxy")

        logger.info(f"Transparent proxy started on {self.host}:{self.port}")

    async def _run_proxy(self):
        """Run the MITM proxy."""
        try:
            # Configure proxy options
            mode = []
            if self._effective_upstream:
                mode.append(f"upstream:{self._effective_upstream}")
            else:
                mode.append("regular")

            opts = options.Options(
                listen_host=self.host,
                listen_port=self.port,
                ssl_insecure=True,
                mode=mode,
            )

            self._master = DumpMaster(opts)
            self._master.addons.add(self.addon)

            ctx.options.flow_detail = 0
            ctx.options.termlog_verbosity = "error"
            ctx.options.connection_strategy = "lazy"

            self._running = True
            self._started_event.set()

            await self._master.run()

        except Exception as e:
            logger.error(f"Error running transparent proxy: {e}")
            self._running = False
            try:
                if self._master:
                    self._master.shutdown()
            except Exception:
                pass
            self._started_event.set()
            raise

    def stop(self):
        """Stop the transparent proxy server."""
        logger.info("Stopping transparent proxy")

        self._running = False

        try:
            if self._master:
                self._master.shutdown()
        except Exception:
            pass

        # Stop the event loop to unblock the thread
        if self._loop and self._loop.is_running():
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

            # Force cleanup if thread didn't exit gracefully
            if self._thread.is_alive():
                logger.warning("Proxy thread did not exit gracefully, forcing cleanup")
                try:
                    if self._loop and not self._loop.is_closed():
                        self._loop.call_soon_threadsafe(self._loop.stop)
                except Exception:
                    pass

        # Close the loop if it's still open
        if self._loop and not self._loop.is_closed():
            try:
                self._loop.close()
            except Exception:
                pass

        # Stop pproxy bridge if running
        self._stop_pproxy_bridge()

        self._loop = None
        self._master = None
        self._effective_upstream = None
        logger.info("Transparent proxy stopped")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    # Public API for cf_clearance management
    def set_cf_clearance(self, host: str, user_agent: str, cf_clearance: str) -> None:
        """Store cf_clearance for a host."""
        self.addon.set_cf_clearance(host, user_agent, cf_clearance)

    def get_cf_clearance(self, host: str, user_agent: str) -> Optional[str]:
        """Get stored cf_clearance for a host."""
        return self.addon.get_cf_clearance(host, user_agent)

    def clear_cf_clearance(
        self, host: Optional[str] = None, user_agent: Optional[str] = None
    ) -> None:
        """Clear stored cf_clearance entries."""
        self.addon.clear_cf_clearance(host, user_agent)


def start_transparent_proxy(
    api_key: str,
    api_base: str = "https://solver.zetx.site",
    host: str = "127.0.0.1",
    port: int = 8080,
    user_proxy: Optional[str] = None,
    api_proxy: Optional[str] = None,
    impersonate: str = "chrome",
    enable_detection: bool = True,
    no_cache: bool = False,
    timeout: int = 120,
    extra_title_indicators: Optional[list] = None,
    extra_cf_indicators: Optional[list] = None,
):
    """Start transparent proxy server with configuration.

    Args:
        api_key: CloudFlyer API key
        api_base: CloudFlyer API base URL
        host: Listen address (default: 127.0.0.1)
        port: Listen port (default: 8080)
        user_proxy: Proxy for all requests (mitmproxy upstream + linksocks tunnel)
        api_proxy: Proxy for API calls to CloudFlyer
        impersonate: Browser to impersonate (default: chrome)
        enable_detection: Enable Cloudflare challenge detection
        no_cache: Disable cf_clearance caching
        timeout: Challenge solve timeout in seconds
        extra_title_indicators: Additional title patterns to detect challenge pages
        extra_cf_indicators: Additional Cloudflare-specific indicators
    """
    proxy = CloudAPITransparentProxy(
        api_key=api_key,
        api_base=api_base,
        host=host,
        port=port,
        user_proxy=user_proxy,
        api_proxy=api_proxy,
        impersonate=impersonate,
        enable_detection=enable_detection,
        no_cache=no_cache,
        timeout=timeout,
        extra_title_indicators=extra_title_indicators,
        extra_cf_indicators=extra_cf_indicators,
    )

    shutdown_event = threading.Event()

    def signal_handler(signum, frame):
        logger.info("Received interrupt signal, shutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    try:
        proxy.start()

        logger.info(f"Proxy ready at http://{host}:{port}")
        logger.info(
            "Configure your application to use this proxy for automatic Cloudflare bypass"
        )
        logger.info("Press Ctrl+C to stop")

        while proxy._running and not shutdown_event.is_set():
            shutdown_event.wait(timeout=1)

    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
        proxy.stop()
