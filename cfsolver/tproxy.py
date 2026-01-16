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
                if 'id="challenge' in content_lower or 'class="no-js">' in content_lower:
                    logger.debug(f"Detected challenge page with title: {indicator}")
                    return True
                if response.status_code in [403, 503, 429]:
                    logger.debug(f"Detected challenge by title and status code: {indicator}")
                    return True

        # Direct CF indicator matches - only for non-200 responses
        if response.status_code in [403, 503, 429]:
            for indicator in self.cf_indicators:
                if indicator.lower() in content_lower:
                    logger.debug(f"Detected Cloudflare challenge indicator: {indicator}")
                    return True

        return False


class CloudAPIProxyAddon:
    """MITM addon for transparent proxy with cloud-based challenge solving."""

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://solver.zetx.site",
        api_proxy: Optional[str] = None,
        impersonate: str = "chrome",
        enable_detection: bool = True,
        no_cache: bool = False,
        timeout: int = 120,
    ):
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.api_proxy = api_proxy
        self.impersonate = impersonate
        self.enable_detection = enable_detection
        self.no_cache = no_cache
        self.timeout = timeout
        
        self.detector = CloudflareDetector() if enable_detection else None
        
        # Host-level locks for serializing challenge solving
        self.host_locks: Dict[str, threading.Event] = {}
        self.host_lock = threading.Lock()
        
        # Store cf_clearance cookies keyed by host and User-Agent
        self.cf_clearance_store: Dict[str, Dict[str, Dict[str, str]]] = {}
        self._store_lock = threading.Lock()

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
                    flow.request.headers["Cookie"] = f"{existing}; {cookie_name}={cookie_value}"
                else:
                    flow.request.headers["Cookie"] = f"{cookie_name}={cookie_value}"
            except Exception:
                pass

    def request(self, flow: http.HTTPFlow):
        """Handle incoming request - inject cached cf_clearance if available."""
        if self.no_cache:
            return

        try:
            ua = flow.request.headers.get("User-Agent")
            host = flow.request.host
            if ua and host:
                cached = self.get_cf_clearance(host, ua)
                if cached:
                    self.inject_cookie(flow, "cf_clearance", cached["cf_clearance"])
                    if cached.get("user_agent"):
                        flow.request.headers["User-Agent"] = cached["user_agent"]
                else:
                    # Fallback: reuse any stored cf_clearance for this host
                    stored = self.get_cf_clearance_for_host(host)
                    if stored:
                        if stored.get("user_agent"):
                            flow.request.headers["User-Agent"] = stored["user_agent"]
                        self.inject_cookie(flow, "cf_clearance", stored["cf_clearance"])
        except Exception:
            pass

    async def response(self, flow: http.HTTPFlow):
        """Handle response - detect challenge and solve via cloud API."""
        if not self.enable_detection or not flow.response:
            return

        # Skip CF internal API requests
        request_path = flow.request.path
        if "/cdn-cgi/challenge-platform" in request_path or flow.request.host == "challenges.cloudflare.com":
            return

        # Check if this is a Cloudflare challenge
        if self.detector and self.detector.is_cloudflare_challenge(flow.response):
            host = flow.request.host
            is_solver = False

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
                    
                    if flow.request.headers.get("X-Refetched-By-Waiter") == "1":
                        return
                    flow.request.headers["X-Refetched-By-Waiter"] = "1"
                    ctx.master.commands.call("replay.client", [flow])
                    return

                logger.info(f"Detected Cloudflare challenge for {url}, solving via cloud API...")

                # Solve challenge using cloud API
                result = await loop.run_in_executor(None, self._solve_challenge, url)

                if result and result.get("success"):
                    solution = result.get("solution", {})
                    cookies = solution.get("cookies", {})
                    user_agent = solution.get("userAgent") or solution.get("user_agent")
                    
                    # Cache the solution
                    if not self.no_cache and cookies.get("cf_clearance"):
                        self.set_cf_clearance(host, user_agent or "", cookies["cf_clearance"])
                    
                    # Update request with solved cookies/UA and replay
                    if user_agent:
                        flow.request.headers["User-Agent"] = user_agent
                    if cookies.get("cf_clearance"):
                        self.inject_cookie(flow, "cf_clearance", cookies["cf_clearance"])
                    
                    if flow.request.headers.get("X-Refetched") == "1":
                        return
                    flow.request.headers["X-Refetched"] = "1"
                    
                    ctx.master.commands.call("replay.client", [flow])
                else:
                    error = result.get("error", "Unknown error") if result else "No response"
                    logger.error(f"Challenge solve failed: {error}")

            except Exception as e:
                logger.error(f"Error resolving challenge for {url}: {e}")
            finally:
                if not self.no_cache and is_solver:
                    with self.host_lock:
                        if host in self.host_locks:
                            self.host_locks[host].set()
                            del self.host_locks[host]

    def _solve_challenge(self, url: str) -> Dict[str, Any]:
        """Solve Cloudflare challenge using cloud API."""
        try:
            with Session(verify=False, proxy=self.api_proxy) as session:
                # Create task
                resp = session.post(
                    f"{self.api_base}/api/createTask",
                    json={
                        "apiKey": self.api_key,
                        "task": {
                            "type": "CloudflareTask",
                            "websiteURL": url,
                        },
                    },
                )
                
                if resp.status_code != 200:
                    return {"success": False, "error": f"HTTP {resp.status_code}"}
                
                data = resp.json()
                if data.get("errorId"):
                    return {"success": False, "error": data.get("errorDescription", "Unknown error")}
                
                task_id = data.get("taskId")
                if not task_id:
                    return {"success": False, "error": "No task ID returned"}
                
                logger.debug(f"Task created: {task_id}")
                
                # Poll for result
                start = time.time()
                while time.time() - start < self.timeout:
                    res = session.post(
                        f"{self.api_base}/api/getTaskResult",
                        json={"apiKey": self.api_key, "taskId": task_id},
                    )
                    
                    if res.status_code != 200:
                        time.sleep(2)
                        continue
                    
                    result = res.json()
                    status = result.get("status")
                    
                    if status == "processing":
                        time.sleep(2)
                        continue
                    
                    success_field = result.get("success")
                    if isinstance(success_field, bool):
                        success = success_field
                    else:
                        success = (status in ("completed", "ready")) and (result.get("error") in (None, ""))
                    
                    if not success:
                        worker_result = result.get("result") or {}
                        error = (
                            result.get("error")
                            or worker_result.get("error")
                            or "Unknown error"
                        )
                        return {"success": False, "error": error}
                    
                    # Extract solution
                    worker_result = result.get("result") or {}
                    if isinstance(worker_result.get("result"), dict):
                        solution = worker_result["result"]
                    else:
                        solution = worker_result
                    
                    logger.info("Challenge solved successfully via cloud API")
                    return {"success": True, "solution": solution}
                
                return {"success": False, "error": "Timeout waiting for solution"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}

    # --- cf_clearance store helpers ---
    def set_cf_clearance(self, host: str, user_agent: str, cf_clearance: str) -> None:
        """Store cf_clearance for host and User-Agent."""
        if not host or not cf_clearance:
            return
        key_host = host.lower()
        with self._store_lock:
            if key_host not in self.cf_clearance_store:
                self.cf_clearance_store[key_host] = {}
            self.cf_clearance_store[key_host][user_agent or ""] = {
                "cf_clearance": cf_clearance,
                "user_agent": user_agent,
            }

    def get_cf_clearance(self, host: str, user_agent: str) -> Optional[Dict[str, str]]:
        """Retrieve cf_clearance for host and User-Agent if present."""
        if not host:
            return None
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if not inner:
                return None
            return inner.get(user_agent or "")

    def get_cf_clearance_for_host(self, host: str) -> Optional[Dict[str, str]]:
        """Get any stored cf_clearance for a host."""
        if not host:
            return None
        key_host = host.lower()
        with self._store_lock:
            inner = self.cf_clearance_store.get(key_host)
            if not inner:
                return None
            for data in inner.values():
                if data and data.get("cf_clearance"):
                    return data
            return None

    def clear_cf_clearance(self, host: Optional[str] = None) -> None:
        """Clear stored cf_clearance entries."""
        with self._store_lock:
            if host is None:
                self.cf_clearance_store.clear()
            else:
                self.cf_clearance_store.pop(host.lower(), None)


class CloudAPITransparentProxy:
    """Transparent proxy server using cloud API for challenge solving."""

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://solver.zetx.site",
        host: str = "127.0.0.1",
        port: int = 8080,
        upstream_proxy: Optional[str] = None,
        api_proxy: Optional[str] = None,
        impersonate: str = "chrome",
        enable_detection: bool = True,
        no_cache: bool = False,
        timeout: int = 120,
    ):
        self.api_key = api_key
        self.api_base = api_base
        self.host = host
        self.port = port
        self.upstream_proxy = upstream_proxy
        self.api_proxy = api_proxy
        self.impersonate = impersonate
        self.enable_detection = enable_detection
        self.no_cache = no_cache
        self.timeout = timeout

        self.addon = CloudAPIProxyAddon(
            api_key=api_key,
            api_base=api_base,
            api_proxy=api_proxy,
            impersonate=impersonate,
            enable_detection=enable_detection,
            no_cache=no_cache,
            timeout=timeout,
        )
        
        self._master = None
        self._thread = None
        self._running = False
        self._loop = None
        self._started_event = threading.Event()

    def start(self):
        """Start the transparent proxy server."""
        if self._running:
            raise RuntimeError("Proxy is already running")

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
            raise RuntimeError("Failed to start transparent proxy")

        logger.info(f"Transparent proxy started on {self.host}:{self.port}")

    async def _run_proxy(self):
        """Run the MITM proxy."""
        try:
            # Configure proxy options
            mode = []
            if self.upstream_proxy:
                mode.append(f"upstream:{self.upstream_proxy}")
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

        try:
            if self._master:
                self._master.shutdown()
        except Exception:
            pass

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

        self._running = False
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

    def get_cf_clearance(self, host: str, user_agent: str) -> Optional[Dict[str, str]]:
        """Get stored cf_clearance for a host."""
        return self.addon.get_cf_clearance(host, user_agent)

    def clear_cf_clearance(self, host: Optional[str] = None) -> None:
        """Clear stored cf_clearance entries."""
        self.addon.clear_cf_clearance(host)


def start_transparent_proxy(
    api_key: str,
    api_base: str = "https://solver.zetx.site",
    host: str = "127.0.0.1",
    port: int = 8080,
    upstream_proxy: Optional[str] = None,
    api_proxy: Optional[str] = None,
    impersonate: str = "chrome",
    enable_detection: bool = True,
    no_cache: bool = False,
    timeout: int = 120,
):
    """Start transparent proxy server with configuration.
    
    Args:
        api_key: CloudFlyer API key
        api_base: CloudFlyer API base URL
        host: Listen address (default: 127.0.0.1)
        port: Listen port (default: 8080)
        upstream_proxy: Upstream proxy for forwarding requests
        api_proxy: Proxy for API calls to CloudFlyer
        impersonate: Browser to impersonate (default: chrome)
        enable_detection: Enable Cloudflare challenge detection
        no_cache: Disable cf_clearance caching
        timeout: Challenge solve timeout in seconds
    """
    proxy = CloudAPITransparentProxy(
        api_key=api_key,
        api_base=api_base,
        host=host,
        port=port,
        upstream_proxy=upstream_proxy,
        api_proxy=api_proxy,
        impersonate=impersonate,
        enable_detection=enable_detection,
        no_cache=no_cache,
        timeout=timeout,
    )

    shutdown_event = threading.Event()

    def signal_handler(signum, frame):
        logger.info("Received interrupt signal, shutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    try:
        proxy.start()
        
        logger.info(f"Proxy ready at http://{host}:{port}")
        logger.info("Configure your application to use this proxy for automatic Cloudflare bypass")
        logger.info("Press Ctrl+C to stop")

        while proxy._running and not shutdown_event.is_set():
            shutdown_event.wait(timeout=1)

    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
        proxy.stop()
