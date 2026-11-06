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

from mitmproxy import http, options, ctx
from mitmproxy.tools.dump import DumpMaster

from .async_client import AsyncCloudflareSolver
from .detection import Detection, detect as detect_challenge
from .exceptions import CFSolverProxyError

logger = logging.getLogger(__name__)


def _is_cleared_response(response: http.Response) -> bool:
    """A solved response may only seed the cache when the challenge is gone."""
    if not 200 <= response.status_code < 400:
        return False
    return not detect_challenge(response)


def _find_cookie_value(cookies, name: str, url: str) -> Optional[str]:
    """Read a cookie for the URL's host without domain ambiguity.

    Same-named cookies can live on unrelated domains with different values,
    which makes an unqualified read raise CookieConflict. Prefer an exact
    host match, then a parent-domain match, and only fall back to a lone
    candidate when nothing matches the host.
    """
    host = (urlparse(url).hostname or "").lower()
    jar = getattr(cookies, "jar", cookies)

    exact = None
    parent = None
    others = []
    for cookie in jar:
        if cookie.name != name or not cookie.value:
            continue
        domain = (cookie.domain or "").lstrip(".").lower()
        if domain and host and domain == host:
            exact = exact or cookie.value
        elif domain and host and host.endswith("." + domain):
            parent = parent or cookie.value
        else:
            others.append(cookie.value)

    if exact:
        return exact
    if parent:
        return parent
    if len(others) == 1:
        return others[0]
    return None


# Header used to exclude a single request from cf_clearance injection and
# caching. It never reaches the upstream server.
DEFAULT_SKIP_HEADER = "X-CFSolver-Skip"


class BypassRule:
    """A direct pass-through rule for the transparent proxy.

    Matching requests skip challenge detection, solving and caching entirely.

    Supported specs (one per rule string):
        host:example.com       exact host
        host:*.example.com     a host and all of its subdomains
        suffix:.jpg            URL path suffix (query string is ignored)

    An explicit ``=direct`` action suffix is accepted; ``direct`` is the only
    supported action.
    """

    def __init__(self, spec: str):
        raw = (spec or "").strip()
        if not raw:
            raise ValueError("empty rule")

        pattern, _, action = raw.partition("=")
        action = action.strip().lower()
        if action and action != "direct":
            raise ValueError(
                f"unsupported rule action {action!r} in {raw!r}; "
                "only 'direct' is supported"
            )

        kind, sep, value = pattern.strip().partition(":")
        kind = kind.strip().lower()
        value = value.strip().lower()
        if not sep or kind not in ("host", "suffix") or not value:
            raise ValueError(
                f"invalid rule {raw!r}; expected 'host:PATTERN', "
                "'host:*.example.com' or 'suffix:.jpg'"
            )

        self.spec = raw
        self.kind = kind
        self.value = value
        self.host_suffix = False
        if kind == "host":
            if self.value.startswith("*.") or self.value.startswith("."):
                self.host_suffix = True
                self.value = self.value.lstrip("*.")
                if not self.value:
                    raise ValueError(f"invalid rule {raw!r}: empty host pattern")

    def matches(self, host: str, url: str) -> bool:
        """Check whether a request host and URL match this rule."""
        host = (host or "").lower()
        if self.kind == "host":
            if self.host_suffix:
                return host == self.value or host.endswith("." + self.value)
            return host == self.value
        return urlparse(url).path.lower().endswith(self.value)


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
        self.user_markers = list(extra_title_indicators or []) + list(
            extra_cf_indicators or []
        )

    def detect(self, response: http.Response, url: str = "") -> Detection:
        """Classify a response, reporting blocks and near misses."""
        result = detect_challenge(response, overrides=self.user_markers)
        if result.is_block:
            logger.warning(
                f"Cloudflare block ({result.reason}) for {url}: "
                "not a challenge, leaving the response untouched"
            )
        elif result.is_suspicious:
            logger.debug(
                f"Challenge not confirmed for {url} "
                f"(weak markers only: {', '.join(result.markers)})"
            )
        return result

    def is_cloudflare_challenge(self, response: http.Response) -> bool:
        """Check if response contains Cloudflare challenge."""
        if not response or not response.content:
            return False
        return bool(self.detect(response))


class CloudAPIProxyAddon:
    """MITM addon for transparent proxy with cloud-based challenge solving."""

    # Flow metadata key marking a request that carries the skip header
    _SKIP_CACHE_META = "cfsolver_skip_cache"

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
        polling_interval: float = 2.0,
        extra_title_indicators: Optional[list] = None,
        extra_cf_indicators: Optional[list] = None,
        rules: Optional[list] = None,
        success_ttl: float = -1,
        failure_ttl: float = 0,
        skip_header: Optional[str] = DEFAULT_SKIP_HEADER,
    ):
        if success_ttl < -1 or failure_ttl < -1:
            raise ValueError(
                "success_ttl and failure_ttl must be -1 (forever), 0 or "
                "a positive number of seconds"
            )
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.user_proxy = user_proxy
        self.api_proxy = api_proxy
        self.impersonate = impersonate
        self.enable_detection = enable_detection
        self.no_cache = no_cache
        self.timeout = timeout
        self.polling_interval = polling_interval
        self.success_ttl = success_ttl
        self.failure_ttl = failure_ttl
        self.rules = [BypassRule(spec) for spec in (rules or [])]
        self.skip_header = (skip_header or "").strip() or None

        self.detector = (
            CloudflareDetector(
                extra_title_indicators=extra_title_indicators,
                extra_cf_indicators=extra_cf_indicators,
            )
            if enable_detection
            else None
        )

        # Host-level locks for serializing challenge solving
        self.host_locks: Dict[str, asyncio.Event] = {}
        self.host_lock = asyncio.Lock()

        # Store cf_clearance cookies keyed by host and User-Agent
        # Structure: {host: {user_agent: (cf_clearance, stored_at)}}
        self.cf_clearance_store: Dict[str, Dict[str, Tuple[str, float]]] = {}
        # Failed-solve cooldown: {host: monotonic deadline}
        self.solve_failures: Dict[str, float] = {}
        self._store_lock = threading.Lock()

        # Lazy async solver (created on first use inside async response handler)
        self._solver: Optional[AsyncCloudflareSolver] = None

    def _get_or_create_solver(self) -> AsyncCloudflareSolver:
        if self._solver is None:
            self._solver = AsyncCloudflareSolver(
                api_key=self.api_key,
                api_base=self.api_base,
                proxy=self.user_proxy,
                api_proxy=self.api_proxy,
                impersonate=self.impersonate,
                solve=True,
                on_challenge=True,
                use_cache=not self.no_cache,
                polling_interval=self.polling_interval,
            )
        return self._solver

    @staticmethod
    def _remove_hop_by_hop_headers(headers: Dict[str, str]) -> None:
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

    async def _fetch_via_solver(
        self,
        flow: http.HTTPFlow,
        url: str,
        *,
        solve: bool,
        user_agent: Optional[str] = None,
        cf_clearance: Optional[str] = None,
    ) -> Optional[http.Response]:
        """Fetch URL using AsyncCloudflareSolver and return mitmproxy Response."""
        try:
            solver = self._get_or_create_solver()

            headers = dict(flow.request.headers)
            if user_agent:
                headers["User-Agent"] = user_agent

            if cf_clearance:
                # Ensure cf_clearance is present for this fetch
                cookie_val = headers.get("Cookie", "")
                cookie_parts = [
                    p.strip()
                    for p in cookie_val.split(";")
                    if p.strip() and not p.strip().lower().startswith("cf_clearance=")
                ]
                cookie_parts.append(f"cf_clearance={cf_clearance}")
                headers["Cookie"] = "; ".join(cookie_parts)

            self._remove_hop_by_hop_headers(headers)

            resp = await solver.request(
                flow.request.method,
                url,
                headers=headers,
                data=flow.request.content or None,
                solve=solve,
                on_challenge=True,
                use_cache=not self.no_cache,
            )

            return http.Response.make(
                resp.status_code, resp.content, dict(resp.headers)
            )
        except Exception as e:
            logger.error(f"Failed to fetch {url} via solver: {e}")
            return None

    async def _try_extract_clearance_from_solver(
        self, url: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """Best-effort extract (user_agent, cf_clearance) from solver session state."""
        solver = self._solver
        if solver is None:
            return None, None

        user_agent: Optional[str] = None
        cf_clearance: Optional[str] = None

        try:
            session = await solver._get_session()  # internal but stable in this SDK
            try:
                user_agent = session.headers.get("User-Agent")
            except Exception:
                user_agent = None

            try:
                cf_clearance = _find_cookie_value(session.cookies, "cf_clearance", url)
            except Exception:
                cf_clearance = None
        except Exception:
            return None, None

        return user_agent, cf_clearance

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

    def _is_direct(self, flow: http.HTTPFlow) -> bool:
        """Check whether the request matches a direct pass-through rule."""
        if not self.rules:
            return False
        host = flow.request.host
        url = flow.request.pretty_url
        return any(rule.matches(host, url) for rule in self.rules)

    def request(self, flow: http.HTTPFlow):
        """Handle incoming request - inject cached cf_clearance if available."""
        # The skip header is a control header: it is stripped before forwarding
        # and excludes this request from injection and cache writes.
        skip_cache = False
        if self.skip_header and self.skip_header in flow.request.headers:
            skip_cache = True
            flow.request.headers.pop(self.skip_header, None)
            flow.metadata[self._SKIP_CACHE_META] = True
            logger.debug(
                f"[Skip header] {self.skip_header} set for {flow.request.pretty_url}"
            )

        if self.no_cache:
            return

        if self._is_direct(flow):
            return

        if skip_cache:
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

        # Direct rules leave the flow untouched (no injection, solving or caching)
        if self._is_direct(flow):
            return

        # Skip CF internal API requests
        request_path = flow.request.path
        if (
            "/cdn-cgi/challenge-platform" in request_path
            or flow.request.host == "challenges.cloudflare.com"
        ):
            return

        # Check if this is a Cloudflare challenge
        detection = (
            self.detector.detect(flow.response, flow.request.pretty_url)
            if self.detector
            else None
        )
        if detection:
            host = flow.request.host
            skip_cache = bool(flow.metadata.get(self._SKIP_CACHE_META, False))
            is_solver = False

            # A host whose solve failed recently is passed through untouched
            if self.is_solve_blocked(host):
                logger.debug(f"[Failure hold] Not solving {flow.request.pretty_url}")
                return

            # In no_cache mode, every request solves independently (no host-level serialization)
            if self.no_cache:
                is_solver = True
            else:
                async with self.host_lock:
                    if host not in self.host_locks:
                        self.host_locks[host] = asyncio.Event()
                        is_solver = True

            url = flow.request.pretty_url
            try:
                if not is_solver:
                    event = self.host_locks.get(host)
                    if event:
                        try:
                            await asyncio.wait_for(
                                event.wait(), timeout=float(self.timeout)
                            )
                        except asyncio.TimeoutError:
                            return

                    # After waiting, get stored cf_clearance and re-fetch
                    if not skip_cache:
                        stored = self.get_cf_clearance_for_host(host)
                        if stored:
                            stored_ua, stored_cf = stored
                            refetch_result = await self._fetch_via_solver(
                                flow,
                                url,
                                solve=False,
                                user_agent=stored_ua,
                                cf_clearance=stored_cf,
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

                solved_response = await self._fetch_via_solver(flow, url, solve=True)
                if not solved_response:
                    logger.error(
                        "Challenge solve failed: solver fetch returned no response"
                    )
                    if not skip_cache:
                        self.record_solve_failure(host)
                    return

                flow.response = solved_response

                # Persist cf_clearance for future first-send usage when available.
                # An unusable solve (error status or a page that is still a
                # challenge) must not seed the cache, or every later request
                # gets a clearance that was never accepted.
                if self.no_cache or skip_cache:
                    if skip_cache:
                        logger.debug(f"[Cache SKIP] {self.skip_header} set for {url}")
                    return
                if not _is_cleared_response(solved_response):
                    logger.warning(
                        f"[Cache SKIP] Solve did not clear {host}: "
                        f"HTTP {solved_response.status_code}"
                    )
                    self.record_solve_failure(host)
                    return
                ua, cf = await self._try_extract_clearance_from_solver(url)
                if ua and cf:
                    self.set_cf_clearance(host, ua, cf)
                    self.clear_solve_failure(host)
                    logger.info(f"[Cache STORE] Stored cf_clearance for {host}")
                else:
                    logger.warning(
                        f"[Cache SKIP] user_agent={bool(ua)}, cf_clearance={bool(cf)}"
                    )
                return

            except Exception as e:
                logger.error(f"Error resolving challenge for {url}: {e}")
                if is_solver and not skip_cache:
                    self.record_solve_failure(host)
            finally:
                # Only release lock if we acquired one (i.e., not in no_cache mode)
                # Ensure lock is always released even if exceptions occur before try block
                if not self.no_cache and is_solver:
                    async with self.host_lock:
                        if host in self.host_locks:
                            self.host_locks[host].set()
                            del self.host_locks[host]

    # --- cf_clearance store helpers ---
    def set_cf_clearance(self, host: str, user_agent: str, cf_clearance: str) -> None:
        """Store cf_clearance for host and User-Agent."""
        if not host or not user_agent or not cf_clearance:
            return
        if self.success_ttl == 0:
            return
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if inner is None:
                inner = {}
                self.cf_clearance_store[key_host] = inner
            inner[user_agent] = (cf_clearance, time.monotonic())

    def _clearance_expired(self, stored_at: float) -> bool:
        if self.success_ttl < 0:
            return False
        return time.monotonic() - stored_at > self.success_ttl

    def get_cf_clearance(self, host: str, user_agent: str) -> Optional[str]:
        """Retrieve cf_clearance for host and User-Agent if present."""
        if not host or not user_agent:
            return None
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if not inner:
                return None
            entry = inner.get(user_agent)
            if entry is None:
                return None
            cf_clearance, stored_at = entry
            if self._clearance_expired(stored_at):
                inner.pop(user_agent, None)
                if not inner:
                    self.cf_clearance_store.pop(key_host, None)
                return None
            return cf_clearance

    def get_cf_clearance_for_host(self, host: str) -> Optional[tuple]:
        """Get any stored cf_clearance for a host. Returns (user_agent, cf_clearance) tuple."""
        if not host:
            return None
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if not inner:
                return None
            found = None
            expired = []
            for ua, (cf, stored_at) in inner.items():
                if self._clearance_expired(stored_at):
                    expired.append(ua)
                    continue
                if ua and cf and found is None:
                    found = (ua, cf)
            for ua in expired:
                inner.pop(ua, None)
            if not inner:
                self.cf_clearance_store.pop(key_host, None)
            return found

    # --- failed-solve cooldown helpers ---
    def record_solve_failure(self, host: str) -> None:
        """Hold off solving a host for a while after a failed solve."""
        if not host or self.no_cache or self.failure_ttl == 0:
            return
        deadline = (
            float("inf")
            if self.failure_ttl < 0
            else time.monotonic() + self.failure_ttl
        )
        with self._store_lock:
            self.solve_failures[host.lower()] = deadline
        if self.failure_ttl < 0:
            logger.warning(f"[Solve FAIL] {host}: not solving again this session")
        else:
            logger.warning(
                f"[Solve FAIL] {host}: not solving again for {self.failure_ttl}s"
            )

    def is_solve_blocked(self, host: str) -> bool:
        """Check whether a recent failed solve puts the host in a cooldown."""
        if not host or self.no_cache or self.failure_ttl == 0:
            return False
        key_host = host.lower()
        with self._store_lock:
            deadline = self.solve_failures.get(key_host)
            if deadline is None:
                return False
            if time.monotonic() >= deadline:
                self.solve_failures.pop(key_host, None)
                return False
            return True

    def clear_solve_failure(self, host: str) -> None:
        """Drop the failed-solve cooldown for a host."""
        if not host:
            return
        with self._store_lock:
            self.solve_failures.pop(host.lower(), None)

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
        rules: Optional[list] = None,
        success_ttl: float = -1,
        failure_ttl: float = 0,
        skip_header: Optional[str] = DEFAULT_SKIP_HEADER,
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
            rules=rules,
            success_ttl=success_ttl,
            failure_ttl=failure_ttl,
            skip_header=skip_header,
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
    rules: Optional[list] = None,
    success_ttl: float = -1,
    failure_ttl: float = 0,
    skip_header: Optional[str] = DEFAULT_SKIP_HEADER,
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
        rules: Direct pass-through rules, e.g. ["suffix:.jpg", "host:*.example.com"]
        success_ttl: Seconds a solved cf_clearance stays cached
            (-1 = forever, 0 = do not cache)
        failure_ttl: Seconds to skip re-solving a host after a failed solve
            (0 = retry every time, -1 = for the rest of the session)
        skip_header: Request header that excludes a request from injection and
            caching; it is stripped before forwarding (None or "" disables)
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
        rules=rules,
        success_ttl=success_ttl,
        failure_ttl=failure_ttl,
        skip_header=skip_header,
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
