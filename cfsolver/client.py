"""
CFSolver - Synchronous HTTP client with automatic Cloudflare challenge bypass.

This module provides a drop-in replacement for requests/httpx that automatically
detects and solves Cloudflare challenges using the CloudFlyer cloud API.

Features:
    - Automatic challenge detection and solving
    - Browser TLS fingerprint impersonation via curl-impersonate
    - LinkSocks tunnel support for challenge solving
    - Configurable polling strategy (long-polling vs interval polling)

Example:
    >>> from cfsolver import CloudflareSolver
    >>> with CloudflareSolver("your-api-key") as solver:
    ...     response = solver.get("https://protected-site.com")
    ...     print(response.text)

Copyright (c) 2024 CloudFlyer Team. MIT License.
"""

import logging
import os
import time
import threading
import asyncio
from typing import Optional, Dict, Any, Tuple, Iterable
from urllib.parse import urlparse, unquote

from curl_cffi.requests import Session, Response
from pywssocks import WSSocksClient

from .detection import is_challenge_response
from .tls_utils import (
    is_fingerprint_configuration_error,
    is_fingerprint_incompatibility_error,
    request_body_rewinder,
    sanitize_ja3,
)
from .polling import retry_delay
from .clearance_cache import ClearanceCache, clearance_cookies

from .exceptions import (
    CFSolverError,
    CFSolverAPIError,
    CFSolverChallengeError,
    CFSolverTimeoutError,
    CFSolverConnectionError,
)

logger = logging.getLogger(__name__)


def _parse_proxy(
    proxy_url: str,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Parse a proxy URL and return address, username, password, and type.

    Args:
        proxy_url: URL string in format scheme://[user:pass@]host[:port]
                   Supported schemes: socks5, http, https

    Returns:
        Tuple of (address, username, password, proxy_type), all None if invalid
    """
    if not proxy_url:
        return None, None, None, None

    try:
        u = urlparse(proxy_url)
    except Exception:
        return None, None, None, None

    if u.scheme not in ("socks5", "http", "https"):
        return None, None, None, None

    username = unquote(u.username) if u.username else None
    password = unquote(u.password) if u.password else None

    host = u.hostname
    if u.scheme == "socks5":
        port = u.port or 1080
        proxy_type = "socks5"
    else:
        port = u.port or 8080
        proxy_type = "http"
    address = f"{host}:{port}"

    return address, username, password, proxy_type


def _raise_for_status(resp):
    """Raise exception with detailed error message from API response."""
    if resp.status_code >= 400:
        error_detail = f"HTTP {resp.status_code}"
        try:
            data = resp.json()
            if isinstance(data, dict):
                error_detail = (
                    data.get("error")
                    or data.get("detail")
                    or data.get("message")
                    or error_detail
                )
        except:
            if resp.text:
                error_detail = resp.text[:200]
        raise CFSolverAPIError(f"API request failed: {error_detail}")


class CloudflareSolver:
    """
    HTTP client that automatically bypasses Cloudflare challenges.

    Provides a curl_cffi-based interface with automatic challenge detection and solving.
    Uses curl-impersonate to mimic browser TLS fingerprints for better anti-detection.

    Args:
        api_key: Your API key
        api_base: CloudFlyer service URL (default: $CLOUDFLYER_API_BASE or https://solver.zetx.site)
        solve: Enable automatic challenge solving (default: True)
        on_challenge: Solve only when challenge detected (default: True)
        proxy: HTTP proxy for your requests (optional)
        api_proxy: Proxy for service API calls (optional)
        impersonate: Browser to impersonate (default: "chrome")
        use_polling: Use interval polling instead of long-polling (default: False).
            When False, uses /waitTaskResult for efficient long-polling.
            When True, uses /getTaskResult with configurable intervals.
        use_cache: Cache clearance data per host within this client (default: True).
            Only cf_clearance, its user agent, and TLS fingerprints are retained.
        polling_interval: Interval in seconds between polling attempts when use_polling=True (default: 2.0)

    Examples:
        >>> solver = CloudflareSolver("your_api_key")
        >>> response = solver.get("https://protected-site.com")
        >>> print(response.text)

        >>> with CloudflareSolver("your_api_key") as solver:
        ...     response = solver.post("https://example.com", json={"data": "value"})
    """

    def __init__(
        self,
        api_key: str,
        api_base: Optional[str] = None,
        solve: bool = True,
        on_challenge: bool = True,
        proxy: Optional[str] = None,
        api_proxy: Optional[str] = None,
        impersonate: str = "chrome",
        use_polling: bool = False,
        use_cache: bool = True,
        polling_interval: float = 2.0,
        challenge_markers: Optional[Iterable[str]] = None,
    ):
        self.api_key = api_key
        self.api_base = (
            api_base
            or os.environ.get("CLOUDFLYER_API_BASE")
            or "https://solver.zetx.site"
        ).rstrip("/")
        self.solve = solve
        self.on_challenge = on_challenge
        self.user_proxy = proxy
        self.api_proxy = api_proxy
        self.impersonate = impersonate
        self.use_polling = use_polling
        self.use_cache = use_cache
        self.polling_interval = polling_interval
        self.challenge_markers = tuple(challenge_markers or ())

        self._client: Optional[WSSocksClient] = None
        self._client_thread: Optional[threading.Thread] = None
        self._linksocks_config: Optional[Dict[str, Any]] = None
        self._client_ready = threading.Event()
        self._client_loop = None
        self._client_task = None
        self._client_failed = threading.Event()
        self._client_stop = threading.Event()
        self._connect_lock = threading.RLock()
        self._closed = False
        self._clearance_cache = ClearanceCache()

        # Session state
        self._session: Optional[Session] = None
        self._ja3: Optional[str] = None
        self._akamai: Optional[str] = None

        # Thread lock for session operations
        self._lock = threading.Lock()
        self._request_lock = threading.RLock()

    def _get_session(self) -> Session:
        """Get or create the HTTP session with current fingerprint settings."""
        if self._closed:
            raise RuntimeError("Session is closed")
        if self._session is None:
            if self._ja3 or self._akamai:
                self._session = Session(
                    verify=False,
                    use_thread_local_curl=False,
                    proxy=self.user_proxy,
                    ja3=self._ja3,
                    akamai=self._akamai,
                )
            else:
                self._session = Session(
                    verify=False,
                    use_thread_local_curl=False,
                    proxy=self.user_proxy,
                    impersonate=self.impersonate,
                )
        return self._session

    def _reset_session(self, ja3: Optional[str] = None, akamai: Optional[str] = None):
        """Reset session with new TLS fingerprints, preserving cookies and headers.

        Only rebuilds if fingerprints actually changed.
        """
        if self._ja3 == ja3 and self._akamai == akamai:
            return

        old_cookies = []
        old_headers = {}

        if self._session:
            # Copy cookie objects as-is so domain, path and secure flags
            # survive. A name->value dict would raise CookieConflict for
            # same-named cookies on unrelated domains and drop the domain.
            old_cookies = list(self._session.cookies.jar)
            old_headers = dict(self._session.headers)
            self._session.close()
            self._session = None

        self._ja3 = ja3
        self._akamai = akamai

        try:
            session = self._get_session()
        except Exception as e:
            if not is_fingerprint_configuration_error(e):
                raise
            logger.info(
                "Failed to apply TLS fingerprints (%s); falling back to impersonate=%s",
                str(e),
                self.impersonate,
            )
            self._ja3 = None
            self._akamai = None
            session = self._get_session()
        for cookie in old_cookies:
            session.cookies.jar.set_cookie(cookie)
        for k, v in old_headers.items():
            session.headers[k] = v

    @staticmethod
    def _normalize_ws_url(url: str) -> str:
        """Convert http(s) URL to ws(s) URL if needed."""
        if url.startswith("https://"):
            return "wss://" + url[8:]
        elif url.startswith("http://"):
            return "ws://" + url[7:]
        return url

    def _get_linksocks_config(self) -> Dict[str, Any]:
        url = f"{self.api_base}/getLinkSocks"
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        with Session(verify=False, proxy=self.api_proxy) as s:
            resp = s.post(url, headers=headers)
            if resp.status_code != 200:
                error_detail = f"HTTP {resp.status_code}"
                try:
                    error_data = resp.json()
                    if isinstance(error_data, dict) and "detail" in error_data:
                        error_detail = error_data["detail"]
                except:
                    error_detail = resp.text or error_detail
                raise CFSolverConnectionError(
                    f"Failed to get linksocks config: {error_detail}"
                )
            try:
                config = resp.json()
            except Exception as e:
                preview = resp.text[:200] if resp.text else "(empty)"
                raise CFSolverConnectionError(
                    f"Failed to parse linksocks config from {url}: {e}, response preview: {preview}"
                )
            if "url" in config:
                config["url"] = self._normalize_ws_url(config["url"])
            return config

    def _connect(self, timeout: float = 10.0):
        """Connect while retaining ownership of setup, connection and worker tasks."""
        with self._connect_lock:
            if self._closed:
                raise RuntimeError("Session is closed")
            if self.is_connected():
                return
            self._stop_client()
            self._client_ready.clear()
            self._client_failed.clear()
            self._client_stop.clear()
            try:
                self._linksocks_config = self._get_linksocks_config()
                config = self._linksocks_config
                upstream_host, upstream_username, upstream_password, upstream_type = (
                    _parse_proxy(self.user_proxy)
                )

                async def start_client():
                    self._client_loop = asyncio.get_running_loop()
                    self._client_task = asyncio.current_task()
                    if self._client_stop.is_set():
                        return
                    self._client = WSSocksClient(
                        ws_url=config["url"],
                        token=config["token"],
                        reverse=True,
                        upstream_proxy=upstream_host,
                        upstream_username=upstream_username,
                        upstream_password=upstream_password,
                        upstream_proxy_type=upstream_type,
                    )
                    connection = asyncio.create_task(self._client.connect())
                    ready = asyncio.create_task(self._client.connected.wait())
                    try:
                        done, _ = await asyncio.wait(
                            (connection, ready),
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if connection in done:
                            await connection
                            raise CFSolverConnectionError(
                                "LinkSocks client stopped before readiness"
                            )
                        self._client_ready.set()
                        await connection
                    finally:
                        connection.cancel()
                        ready.cancel()
                        await asyncio.gather(connection, ready, return_exceptions=True)

                def run_client():
                    try:
                        asyncio.run(start_client())
                    except asyncio.CancelledError:
                        pass
                    except Exception as e:
                        self._last_connect_error = str(e)
                        logger.error("LinkSocks client error: %s", e)
                    finally:
                        self._client_failed.set()
                        self._client_ready.set()

                self._client_thread = threading.Thread(target=run_client, daemon=True)
                self._client_thread.start()
                if not self._client_ready.wait(timeout=timeout):
                    raise TimeoutError("LinkSocks connection timed out")
                if not self.is_connected():
                    raise CFSolverConnectionError(
                        getattr(
                            self, "_last_connect_error", "LinkSocks connection failed"
                        )
                    )
                logger.info("LinkSocks provider established")
            except BaseException as e:
                self._stop_client()
                if not isinstance(e, Exception):
                    raise
                logger.error("Connection setup failed: %s", e)
                self._last_connect_error = str(e)
                if self.solve and not self.on_challenge:
                    raise CFSolverConnectionError(
                        f"Failed to connect to CloudFlyer service: {e}"
                    ) from e

    def _stop_client(self):
        """Cancel on the owning loop and wait for all tunnel cleanup to finish."""
        self._client_stop.set()
        loop, task, worker = self._client_loop, self._client_task, self._client_thread
        if loop and task and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass
        if worker and worker.is_alive():
            worker.join(timeout=10)
            if worker.is_alive():
                raise CFSolverConnectionError("LinkSocks client did not stop")
        self._client = None
        self._client_task = None
        self._client_loop = None
        self._client_thread = None
        self._linksocks_config = None
        self._client_ready.clear()

    def is_connected(self) -> bool:
        """Check if LinkSocks client is currently connected.

        Returns:
            True if connected, False otherwise
        """
        return (
            not self._closed
            and self._client_thread is not None
            and self._client_thread.is_alive()
            and self._client_ready.is_set()
            and not self._client_failed.is_set()
        )

    def ensure_connected(self, timeout: float = 10.0) -> bool:
        """Ensure LinkSocks connection is established before solving challenges.

        This method can be called manually before the first solve to establish
        the connection in advance, reducing latency on the first challenge.

        Args:
            timeout: Maximum time to wait for connection (default: 10 seconds)

        Returns:
            True if connected successfully, False otherwise

        Example:
            >>> solver = CloudflareSolver("your_api_key")
            >>> if solver.ensure_connected():
            ...     response = solver.get("https://protected-site.com")
        """
        try:
            self._connect(timeout=timeout)
            return self.is_connected()
        except Exception as e:
            logger.error(f"Failed to ensure connection: {e}")
            return False

    def _detect_challenge(self, resp: Response) -> bool:
        return is_challenge_response(resp, overrides=self.challenge_markers)

    def _get_cache_key(self, url: str) -> tuple:
        """Bind clearance to its host, egress and client configuration."""
        host = urlparse(url).hostname or ""
        return (host, self.user_proxy, self.impersonate, self.api_base, self.api_key)

    def _load_from_cache(self, url: str) -> bool:
        """Load clearance data from cache if available. Returns True if loaded."""
        if not self.use_cache:
            return False

        cache_key = self._get_cache_key(url)
        cached = self._clearance_cache.get(cache_key)
        if not cached or not cached.get("cookies"):
            return False

        ja3 = sanitize_ja3(cached.get("ja3"))
        akamai = cached.get("akamai")
        self._reset_session(ja3=ja3, akamai=akamai)

        session = self._get_session()
        domain = urlparse(url).hostname
        for k, v in cached["cookies"].items():
            session.cookies.set(k, v, domain=domain)
        if cached.get("user_agent"):
            session.headers["User-Agent"] = cached["user_agent"]
        return True

    def _save_to_cache(
        self,
        url: str,
        cookies: Dict[str, str],
        user_agent: Optional[str],
        ja3: Optional[str],
        akamai: Optional[str],
    ):
        """Save clearance data to cache."""
        if not self.use_cache:
            return

        cache_key = self._get_cache_key(url)
        cookies = clearance_cookies(cookies)
        if not cookies:
            # A solve without cookies carries no clearance; caching it would
            # make later requests believe they were already cleared.
            return
        self._clearance_cache.set(
            cache_key,
            {
                "cookies": cookies,
                "user_agent": user_agent,
                "ja3": ja3,
                "akamai": akamai,
            },
        )

    @staticmethod
    def clear_cache(host: Optional[str] = None):
        """Clear clearance cache.

        Args:
            host: If provided, only clear cache for this host. Otherwise clear all.
        """
        ClearanceCache.clear_all(host)

    def _solve_challenge(
        self, url: str, html: Optional[str] = None, use_cache: Optional[bool] = None
    ):
        _use_cache = self.use_cache if use_cache is None else use_cache
        with self._lock:
            # Lazy connect: only connect to linksocks when actually solving a challenge
            self._connect()

            if not self._linksocks_config:
                error_detail = getattr(self, "_last_connect_error", "connection failed")
                raise CFSolverConnectionError(
                    f"CloudFlyer service unavailable: {error_detail}"
                )

            logger.info(f"Starting challenge solve: {url}")

            with Session(verify=False, proxy=self.api_proxy) as api_session:
                resp = api_session.post(
                    f"{self.api_base}/api/createTask",
                    json={
                        "apiKey": self.api_key,
                        "task": {
                            "type": "CloudflareTask",
                            "websiteURL": url,
                            "linksocks": {
                                "url": self._linksocks_config["url"],
                                "token": self._linksocks_config["connector_token"],
                            },
                        },
                    },
                )
                _raise_for_status(resp)
                data = resp.json()

            if data.get("errorId"):
                raise CFSolverChallengeError(
                    f"Challenge solve failed: {data.get('errorDescription')}"
                )

            task_id = data["taskId"]
            logger.debug(f"Task created: {task_id}")

            result = self._wait_for_result(task_id)

            # Extract normalized solution from worker result structure
            worker_result = result.get("result") or {}
            logger.debug(f"Retrieved task result:\n{worker_result}")
            if isinstance(worker_result.get("result"), dict):
                solution = worker_result["result"]
            else:
                solution = worker_result

            if not isinstance(solution, dict):
                raise CFSolverChallengeError(
                    "Challenge solve failed: invalid response from server"
                )

            cookies = clearance_cookies(solution.get("cookies", {}))
            user_agent = solution.get("userAgent")
            headers = solution.get("headers")
            if not user_agent and isinstance(headers, dict):
                user_agent = headers.get("User-Agent")

            # Apply TLS fingerprints if provided
            ja3_text = sanitize_ja3(solution.get("ja3_text"))
            akamai_text = solution.get("akamai_text")
            if ja3_text or akamai_text:
                logger.debug(
                    f"Applying TLS fingerprints - JA3: {ja3_text[:50] if ja3_text else 'N/A'}..."
                )
                self._reset_session(ja3=ja3_text, akamai=akamai_text)

            # Apply cookies and user agent
            session = self._get_session()
            domain = urlparse(url).hostname
            for k, v in cookies.items():
                session.cookies.set(k, v, domain=domain)

            if user_agent:
                session.headers["User-Agent"] = user_agent

            # Save to cache
            if _use_cache:
                self._save_to_cache(url, cookies, user_agent, ja3_text, akamai_text)

            logger.info("Challenge solved successfully")

    def _wait_for_result(self, task_id: str, timeout: int = 120) -> Dict[str, Any]:
        """
        Wait for task result using either long-polling or interval polling.

        Args:
            task_id: The task ID to wait for
            timeout: Maximum time to wait in seconds

        Returns:
            The task result dictionary

        Raises:
            CFSolverChallengeError: If task fails
            CFSolverTimeoutError: If timeout is reached
        """
        deadline = time.monotonic() + timeout
        failures = 0

        with Session(verify=False, proxy=self.api_proxy) as poll_session:
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                # Choose endpoint based on polling strategy
                if self.use_polling:
                    endpoint = f"{self.api_base}/api/getTaskResult"
                    request_timeout = min(remaining, 30)
                else:
                    endpoint = f"{self.api_base}/api/waitTaskResult"
                    request_timeout = min(remaining, 310)

                try:
                    res = poll_session.post(
                        endpoint,
                        json={"apiKey": self.api_key, "taskId": task_id},
                        timeout=request_timeout,
                    )
                except Exception as e:
                    if time.monotonic() >= deadline:
                        raise CFSolverTimeoutError("Task timed out") from e
                    raise

                if time.monotonic() >= deadline:
                    break

                if res.status_code != 200:
                    if res.status_code == 429 or 500 <= res.status_code < 600:
                        failures += 1
                        time.sleep(
                            min(
                                retry_delay(res, failures),
                                max(0, deadline - time.monotonic()),
                            )
                        )
                    else:
                        _raise_for_status(res)
                        raise CFSolverAPIError(
                            f"Unexpected API status: HTTP {res.status_code}"
                        )
                    continue

                failures = 0
                result = res.json()
                status = result.get("status")

                # Still processing - wait and retry
                if status in ("processing", "timeout"):
                    delay = max(0.1, self.polling_interval) if self.use_polling else 0.1
                    time.sleep(min(delay, max(0, deadline - time.monotonic())))
                    continue

                # Determine success
                success_field = result.get("success")
                if isinstance(success_field, bool):
                    success = success_field
                else:
                    success = (status in ("completed", "ready")) and (
                        result.get("error") in (None, "")
                    )

                if not success:
                    worker_result = result.get("result") or {}
                    error = (
                        result.get("error")
                        or worker_result.get("error")
                        or f"Unknown error (full response: {result})"
                    )
                    raise CFSolverChallengeError(f"Task failed: {error}")

                return result

        raise CFSolverTimeoutError("Task timed out")

    def get_balance(self) -> float:
        """
        Get the current account balance.

        Returns:
            The account balance as a float

        Raises:
            CFSolverAPIError: If the API request fails
        """
        with Session(verify=False, proxy=self.api_proxy) as api_session:
            resp = api_session.post(
                f"{self.api_base}/api/getBalance",
                json={"clientKey": self.api_key},
            )
            _raise_for_status(resp)
            data = resp.json()

        if data.get("errorId"):
            raise CFSolverAPIError(
                f"Failed to get balance: {data.get('errorDescription', 'Unknown error')}"
            )

        return float(data.get("balance", 0))

    def solve_turnstile(self, url: str, sitekey: str) -> str:
        """
        Solve a Turnstile challenge and return the token.

        Args:
            url: The website URL containing the Turnstile widget
            sitekey: The Turnstile sitekey (found in the page's cf-turnstile element)

        Returns:
            The solved Turnstile token to submit with your form

        Raises:
            CFSolverChallengeError: If task creation or solving fails
            CFSolverTimeoutError: If solving takes too long
        """
        logger.info(f"Starting Turnstile solve: {url}")

        with Session(verify=False, proxy=self.api_proxy) as api_session:
            resp = api_session.post(
                f"{self.api_base}/api/createTask",
                json={
                    "apiKey": self.api_key,
                    "task": {
                        "type": "TurnstileTask",
                        "websiteURL": url,
                        "websiteKey": sitekey,
                    },
                },
            )
            _raise_for_status(resp)
            data = resp.json()

        if data.get("errorId"):
            raise CFSolverChallengeError(
                f"Turnstile solve failed: {data.get('errorDescription')}"
            )

        task_id = data["taskId"]
        logger.debug(f"Turnstile task created: {task_id}")

        try:
            result = self._wait_for_result(task_id)
        except CFSolverChallengeError as e:
            raise CFSolverChallengeError(f"Turnstile solve failed: {e}")
        except CFSolverTimeoutError:
            raise CFSolverTimeoutError("Turnstile solve timed out")

        worker_result = result.get("result") or {}
        if isinstance(worker_result.get("result"), dict):
            solution = worker_result["result"]
        else:
            solution = worker_result

        token = solution.get("token")
        if not token:
            raise CFSolverChallengeError("Turnstile solve failed: no token returned")

        logger.info("Turnstile solved successfully")
        return token

    def request(
        self,
        method: str,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        """Send a request with stable session state throughout solving and sending.

        A solver owns one mutable TLS/UA/cookie context. Concurrent callers on
        the same instance are serialized; independent instances run in parallel.
        """
        with self._request_lock:
            return self._request(
                method,
                url,
                solve=solve,
                on_challenge=on_challenge,
                use_cache=use_cache,
                **kwargs,
            )

    def _request(
        self,
        method: str,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        """
        Send an HTTP request with optional Cloudflare challenge bypass.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            solve: Override instance-level solve setting for this request
            on_challenge: Override instance-level on_challenge setting for this request
            use_cache: Override instance-level use_cache setting for this request
            **kwargs: Additional arguments passed to curl_cffi session.request()

        Returns:
            Response object
        """
        # Use per-request overrides or fall back to instance defaults
        _solve = self.solve if solve is None else solve
        _on_challenge = self.on_challenge if on_challenge is None else on_challenge
        _use_cache = self.use_cache if use_cache is None else use_cache

        # Try to load from cache first
        if _use_cache:
            self._load_from_cache(url)

        def _request_with_fallback() -> Response:
            session = self._get_session()
            rewind_body = request_body_rewinder(kwargs.get("data"))
            try:
                return session.request(method, url, **kwargs)
            except Exception as e:
                fingerprints = (
                    self._ja3
                    or self._akamai
                    or kwargs.get("ja3")
                    or kwargs.get("akamai")
                )
                if (
                    not fingerprints
                    or not is_fingerprint_configuration_error(e)
                    or rewind_body is None
                ):
                    raise
                try:
                    rewind_body()
                except (OSError, ValueError):
                    raise e

                logger.info(
                    "Request failed with TLS fingerprints (%s); retrying with impersonate=%s",
                    str(e),
                    self.impersonate,
                )
                self._reset_session(ja3=None, akamai=None)
                session = self._get_session()
                fallback_kwargs = {
                    key: value
                    for key, value in kwargs.items()
                    if key not in ("ja3", "akamai")
                }
                return session.request(method, url, **fallback_kwargs)

        if not _solve:
            return _request_with_fallback()

        if not _on_challenge:
            # Always pre-solve
            try:
                self._solve_challenge(url, use_cache=_use_cache)
            except Exception as e:
                logger.warning(f"Pre-solve failed: {e}")

        resp = _request_with_fallback()

        if _on_challenge and self._detect_challenge(resp):
            logger.info("Cloudflare challenge detected")
            self._solve_challenge(url, resp.text, use_cache=_use_cache)
            resp = _request_with_fallback()

        return resp

    def get(
        self,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        return self.request(
            "GET",
            url,
            solve=solve,
            on_challenge=on_challenge,
            use_cache=use_cache,
            **kwargs,
        )

    def post(
        self,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        return self.request(
            "POST",
            url,
            solve=solve,
            on_challenge=on_challenge,
            use_cache=use_cache,
            **kwargs,
        )

    def put(
        self,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        return self.request(
            "PUT",
            url,
            solve=solve,
            on_challenge=on_challenge,
            use_cache=use_cache,
            **kwargs,
        )

    def delete(
        self,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        return self.request(
            "DELETE",
            url,
            solve=solve,
            on_challenge=on_challenge,
            use_cache=use_cache,
            **kwargs,
        )

    def head(
        self,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        return self.request(
            "HEAD",
            url,
            solve=solve,
            on_challenge=on_challenge,
            use_cache=use_cache,
            **kwargs,
        )

    def options(
        self,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        return self.request(
            "OPTIONS",
            url,
            solve=solve,
            on_challenge=on_challenge,
            use_cache=use_cache,
            **kwargs,
        )

    def patch(
        self,
        url: str,
        *,
        solve: Optional[bool] = None,
        on_challenge: Optional[bool] = None,
        use_cache: Optional[bool] = None,
        **kwargs,
    ) -> Response:
        return self.request(
            "PATCH",
            url,
            solve=solve,
            on_challenge=on_challenge,
            use_cache=use_cache,
            **kwargs,
        )

    def close(self):
        with self._request_lock, self._connect_lock:
            self._closed = True
            try:
                if self._session:
                    try:
                        self._session.close()
                    except Exception as e:
                        if is_fingerprint_incompatibility_error(e):
                            logger.info("Ignoring close() error: %s", str(e))
                        else:
                            raise
                    finally:
                        self._session = None
            finally:
                self._stop_client()
                self._clearance_cache.clear()
        logger.info("Session closed")

    def __enter__(self):
        # Don't connect to linksocks eagerly - it will be connected lazily
        # when _solve_challenge is called (for CloudflareTask only)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
