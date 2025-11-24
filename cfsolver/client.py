import logging
import time
import secrets
import threading
import asyncio
from typing import Optional, Dict, Any
import requests
from pywssocks import WSSocksClient


logger = logging.getLogger(__name__)


class CloudflareSolver:
    """
    HTTP client that automatically bypasses Cloudflare challenges.
    
    Provides a requests-compatible interface with automatic challenge detection and solving.
    
    Args:
        api_key: Your API key
        api_base: CloudFlyer service URL (default: https://cloudflyer.zetx.tech)
        solve: Enable automatic challenge solving (default: True)
        on_challenge: Solve only when challenge detected (default: True)
        proxy: HTTP proxy for your requests (optional)
        api_proxy: Proxy for service API calls (optional)
    
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
    ):
        self.api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.solve = solve
        self.on_challenge = on_challenge
        self.user_proxy = proxy
        self.api_proxy = api_proxy
        
        # Connector token: auto-generated, not exposed to user
        self.connector_token = secrets.token_urlsafe(16)
        
        self._client: Optional[WSSocksClient] = None
        self._client_thread: Optional[threading.Thread] = None
        self._session = requests.Session()
        self._linksocks_config: Optional[Dict[str, Any]] = None
        
        if self.user_proxy:
            self._session.proxies = {"http": self.user_proxy, "https": self.user_proxy}
    
    def _get_linksocks_config(self) -> Dict[str, Any]:
        url = f"{self.api_base}/api/linksocks/getLinksSocks"
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        proxies = {"http": self.api_proxy, "https": self.api_proxy} if self.api_proxy else {}
        resp = requests.post(url, headers=headers, proxies=proxies)
        resp.raise_for_status()
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
            logger.error(f"LinkSocks connection failed: {e}")
            if self.solve and not self.on_challenge:
                raise
    
    def _detect_challenge(self, resp: requests.Response) -> bool:
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
            raise RuntimeError("LinkSocks config not initialized")
        
        logger.info(f"Starting challenge solve: {url}")
        
        proxies = {"http": self.api_proxy, "https": self.api_proxy} if self.api_proxy else {}
        resp = requests.post(
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
            proxies=proxies,
        )
        resp.raise_for_status()
        data = resp.json()
        
        if data.get("errorId"):
            raise RuntimeError(f"Task creation failed: {data.get('errorDescription')}")
        
        task_id = data["taskId"]
        logger.info(f"Task created: {task_id}")
        
        start = time.time()
        while time.time() - start < 120:
            res = requests.post(
                f"{self.api_base}/api/getTaskResult",
                json={"apiKey": self.api_key, "taskId": task_id},
                proxies=proxies,
            )
            if res.status_code != 200:
                time.sleep(2)
                continue
            
            result = res.json()
            status = result.get("status")
            # API layer still processing
            if status == "processing":
                time.sleep(2)
                continue

            # Determine success based on worker result
            success_field = result.get("success")
            if isinstance(success_field, bool):
                success = success_field
            else:
                success = (status in ("completed", "ready")) and (result.get("error") in (None, ""))

            if not success:
                error = result.get("error") or "Task failed"
                raise RuntimeError(f"Task failed: {error}")

            # Extract normalized solution from worker result structure
            worker_result = result.get("result") or {}
            if isinstance(worker_result.get("result"), dict):
                solution = worker_result["result"]
            else:
                solution = worker_result

            if not isinstance(solution, dict):
                raise RuntimeError("Unexpected task result format")

            cookies = solution.get("cookies", {})
            user_agent = solution.get("userAgent")
            headers = solution.get("headers")
            if not user_agent and isinstance(headers, dict):
                user_agent = headers.get("User-Agent")

            for k, v in cookies.items():
                self._session.cookies.set(k, v, domain=requests.utils.urlparse(url).hostname)

            if user_agent:
                self._session.headers["User-Agent"] = user_agent

            logger.info("Challenge solved successfully")
            return
            time.sleep(2)
        raise TimeoutError("Task timeout")
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
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
            try:
                self._solve_challenge(url, resp.text)
                resp = self._session.request(method, url, **kwargs)
            except Exception as e:
                logger.error(f"Challenge solve failed: {e}")
        
        return resp
    
    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)
    
    def put(self, url: str, **kwargs) -> requests.Response:
        return self.request("PUT", url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        return self.request("DELETE", url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)
    
    def patch(self, url: str, **kwargs) -> requests.Response:
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

