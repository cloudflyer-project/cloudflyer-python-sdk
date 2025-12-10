import logging
import time
import secrets
import threading
import asyncio
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from curl_cffi.requests import Session, Response
from pywssocks import WSSocksClient


logger = logging.getLogger(__name__)


class CloudflareSolver:
    """
    HTTP client that automatically bypasses Cloudflare challenges.
    
    Provides a curl_cffi-based interface with automatic challenge detection and solving.
    Uses curl-impersonate to mimic browser TLS fingerprints for better anti-detection.
    
    Args:
        api_key: Your API key
        api_base: CloudFlyer service URL (default: https://cloudflyer.zetx.tech)
        solve: Enable automatic challenge solving (default: True)
        on_challenge: Solve only when challenge detected (default: True)
        proxy: HTTP proxy for your requests (optional)
        api_proxy: Proxy for service API calls (optional)
        impersonate: Browser to impersonate (default: "chrome")
    
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
        api_base: str = "https://cloudflyer.zetx.tech",
        solve: bool = True,
        on_challenge: bool = True,
        proxy: Optional[str] = None,
        api_proxy: Optional[str] = None,
        impersonate: str = "chrome",
    ):
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.solve = solve
        self.on_challenge = on_challenge
        self.user_proxy = proxy
        self.api_proxy = api_proxy
        self.impersonate = impersonate
        
        # Connector token: auto-generated, not exposed to user
        self.connector_token = secrets.token_urlsafe(16)
        
        self._client: Optional[WSSocksClient] = None
        self._client_thread: Optional[threading.Thread] = None
        self._session = Session(
            verify=False,
            proxy=self.user_proxy,
            impersonate=self.impersonate,
        )
        self._linksocks_config: Optional[Dict[str, Any]] = None
    
    def _get_linksocks_config(self) -> Dict[str, Any]:
        url = f"{self.api_base}/api/linksocks/getLinkSocks"
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        with Session(verify=False, proxy=self.api_proxy, impersonate=self.impersonate) as s:
            resp = s.post(url, headers=headers)
            if resp.status_code != 200:
                error_detail = f"HTTP {resp.status_code}"
                try:
                    error_data = resp.json()
                    if isinstance(error_data, dict) and "detail" in error_data:
                        error_detail = error_data["detail"]
                except:
                    error_detail = resp.text or error_detail
                raise RuntimeError(f"Failed to get linksocks config: {error_detail}")
            return resp.json()
    
    def _connect(self):
        if self._client_thread and self._client_thread.is_alive():
            return
            
        try:
            self._linksocks_config = self._get_linksocks_config()
            
            def run_client():
                async def _start():
                    self._client = WSSocksClient(
                        ws_url=self._linksocks_config["url"],
                        token=self.connector_token,
                        reverse=True
                    )
                    await self._client.start()
                
                try:
                    asyncio.run(_start())
                except Exception as e:
                    logger.error(f"LinkSocks client error: {e}")

            self._client_thread = threading.Thread(target=run_client, daemon=True)
            self._client_thread.start()
            
            time.sleep(1) # Wait for connection
            logger.info("LinkSocks Provider established (background thread)")
            
        except Exception as e:
            logger.error(f"Connection setup failed: {e}")
            self._last_connect_error = str(e)
            if self.solve and not self.on_challenge:
                raise RuntimeError(f"Failed to connect to CloudFlyer service: {e}")
    
    def _detect_challenge(self, resp: Response) -> bool:
        if resp.status_code not in (403, 503):
            return False
        if "cloudflare" not in resp.headers.get("Server", "").lower():
            return False
        text = resp.text
        return any(k in text for k in ["cf-turnstile", "cf-challenge", "Just a moment"])
    
    def _solve_challenge(self, url: str, html: Optional[str] = None):
        if not self._client_thread or not self._client_thread.is_alive():
            self._connect()
        
        if not self._linksocks_config:
            error_detail = getattr(self, '_last_connect_error', 'connection failed')
            raise RuntimeError(f"CloudFlyer service unavailable: {error_detail}")
        
        logger.info(f"Starting challenge solve: {url}")
        
        with Session(verify=False, proxy=self.api_proxy, impersonate=self.impersonate) as api_session:
            resp = api_session.post(
                f"{self.api_base}/api/createTask",
                json={
                    "apiKey": self.api_key,
                    "task": {
                        "type": "CloudflareTask",
                        "websiteURL": url,
                        "linksocks": {
                            "url": self._linksocks_config["url"],
                            "token": self.connector_token,
                        },
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()
        
        if data.get("errorId"):
            raise RuntimeError(f"Challenge solve failed: {data.get('errorDescription')}")
        
        task_id = data["taskId"]
        logger.debug(f"Task created: {task_id}")
        
        start = time.time()
        with Session(verify=False, proxy=self.api_proxy, impersonate=self.impersonate) as poll_session:
            while time.time() - start < 120:
                res = poll_session.post(
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
                    error = result.get("error") or "Unknown error"
                    raise RuntimeError(f"Challenge solve failed: {error}")

                worker_result = result.get("result") or {}
                if isinstance(worker_result.get("result"), dict):
                    solution = worker_result["result"]
                else:
                    solution = worker_result

                if not isinstance(solution, dict):
                    raise RuntimeError("Challenge solve failed: invalid response from server")

                cookies = solution.get("cookies", {})
                user_agent = solution.get("userAgent")
                headers = solution.get("headers")
                if not user_agent and isinstance(headers, dict):
                    user_agent = headers.get("User-Agent")

                domain = urlparse(url).hostname
                for k, v in cookies.items():
                    self._session.cookies.set(k, v, domain=domain)

                if user_agent:
                    self._session.headers["User-Agent"] = user_agent

                logger.info("Challenge solved successfully")
                return
        raise TimeoutError("Challenge solve timed out")
    
    def solve_turnstile(self, url: str, sitekey: str) -> str:
        """
        Solve a Turnstile challenge and return the token.
        
        Args:
            url: The website URL containing the Turnstile widget
            sitekey: The Turnstile sitekey (found in the page's cf-turnstile element)
        
        Returns:
            The solved Turnstile token to submit with your form
        
        Raises:
            RuntimeError: If task creation or solving fails
            TimeoutError: If solving takes too long
        """
        if not self._client_thread or not self._client_thread.is_alive():
            self._connect()
        
        if not self._linksocks_config:
            error_detail = getattr(self, '_last_connect_error', 'connection failed')
            raise RuntimeError(f"CloudFlyer service unavailable: {error_detail}")
        
        logger.info(f"Starting Turnstile solve: {url}")
        
        with Session(verify=False, proxy=self.api_proxy, impersonate=self.impersonate) as api_session:
            resp = api_session.post(
                f"{self.api_base}/api/createTask",
                json={
                    "apiKey": self.api_key,
                    "task": {
                        "type": "TurnstileTask",
                        "websiteURL": url,
                        "websiteKey": sitekey,
                        "linksocks": {
                            "url": self._linksocks_config["url"],
                            "token": self.connector_token,
                        },
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()
        
        if data.get("errorId"):
            raise RuntimeError(f"Turnstile solve failed: {data.get('errorDescription')}")
        
        task_id = data["taskId"]
        logger.debug(f"Turnstile task created: {task_id}")
        
        start = time.time()
        with Session(verify=False, proxy=self.api_proxy, impersonate=self.impersonate) as poll_session:
            while time.time() - start < 120:
                res = poll_session.post(
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
                    error = result.get("error") or "Unknown error"
                    raise RuntimeError(f"Turnstile solve failed: {error}")
                
                worker_result = result.get("result") or {}
                if isinstance(worker_result.get("result"), dict):
                    solution = worker_result["result"]
                else:
                    solution = worker_result
                
                token = solution.get("token")
                if not token:
                    raise RuntimeError("Turnstile solve failed: no token returned")
                
                logger.info("Turnstile solved successfully")
                return token
        
        raise TimeoutError("Turnstile solve timed out")
    
    def request(self, method: str, url: str, **kwargs) -> Response:
        if not self.solve:
            return self._session.request(method, url, **kwargs)
        
        if not self.on_challenge:
            # Always pre-solve
            try:
                self._solve_challenge(url)
            except Exception as e:
                logger.warning(f"Pre-solve failed: {e}")
        
        resp = self._session.request(method, url, **kwargs)
        
        if self.on_challenge and self._detect_challenge(resp):
            logger.info("Cloudflare challenge detected")
            self._solve_challenge(url, resp.text)
            resp = self._session.request(method, url, **kwargs)
        
        return resp
    
    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Response:
        return self.request("PUT", url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Response:
        return self.request("HEAD", url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Response:
        return self.request("OPTIONS", url, **kwargs)
    
    def patch(self, url: str, **kwargs) -> Response:
        return self.request("PATCH", url, **kwargs)
    
    def close(self):
        if self._session:
            self._session.close()
        logger.info("Session closed")
    
    def __enter__(self):
        if self.solve:
            self._connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

