# CFSolver

[![PyPI version](https://badge.fury.io/py/cfsolver.svg)](https://badge.fury.io/py/cfsolver)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python HTTP client that automatically bypasses Cloudflare challenges using the [CloudFlyer](https://cloudflyer.zetx.site) API.

## Features

- **Drop-in replacement** for `requests` and `httpx` - minimal code changes required
- **Automatic challenge detection** - detects Cloudflare protection and solves transparently
- **Multiple solving modes** - auto-detect, always pre-solve, or disable
- **Turnstile support** - solve Cloudflare Turnstile CAPTCHA and get tokens
- **Transparent proxy mode** - automatic bypass for any HTTP client without code changes
- **Proxy support** - HTTP/HTTPS/SOCKS5 proxies for both requests and API calls
- **Browser impersonation** - TLS fingerprint mimicking via curl-impersonate
- **Async support** - full async/await API for high-performance applications
- **Command-line interface** - quick operations without writing code

## Installation

```bash
# Basic installation
pip install cfsolver

# With transparent proxy support (requires mitmproxy)
pip install cfsolver[proxy]

# All features
pip install cfsolver[all]
```

## Quick Start

### Python API

Works just like `requests`, but automatically handles Cloudflare challenges:

```python
from cfsolver import CloudflareSolver

solver = CloudflareSolver("your-api-key")
response = solver.get("https://protected-site.com")
print(response.text)
```

### Command Line

```bash
# Set API key
export CLOUDFLYER_API_KEY="your-api-key"

# Make a request with automatic bypass
cfsolver request https://protected-site.com

# Start transparent proxy
cfsolver proxy -P 8080
```

---

## Table of Contents

- [Python API](#python-api)
  - [CloudflareSolver](#cloudfaresolver)
  - [AsyncCloudflareSolver](#asynccloudflaresolver)
  - [Solving Modes](#solving-modes)
  - [Turnstile Support](#turnstile-support)
  - [Proxy Configuration](#proxy-configuration)
- [Transparent Proxy](#transparent-proxy)
  - [Command Line Usage](#command-line-usage)
  - [Programmatic Usage](#programmatic-usage)
  - [Proxy Options](#proxy-options)
- [Command Line Interface](#command-line-interface)
  - [solve cloudflare](#solve-cloudflare)
  - [solve turnstile](#solve-turnstile)
  - [request](#request)
  - [proxy](#proxy)
  - [balance](#balance)
- [Configuration](#configuration)
  - [Parameters](#parameters)
  - [Environment Variables](#environment-variables)
- [Exceptions](#exceptions)
- [Examples](#examples)

---

## Python API

### CloudflareSolver

The main synchronous client for bypassing Cloudflare challenges.

```python
from cfsolver import CloudflareSolver

# Basic usage with context manager (recommended)
with CloudflareSolver("your-api-key") as solver:
    response = solver.get("https://protected-site.com")
    print(response.status_code)
    print(response.text)

# Without context manager
solver = CloudflareSolver("your-api-key")
response = solver.get("https://protected-site.com")
solver.close()
```

#### Supported HTTP Methods

```python
solver.get(url, **kwargs)
solver.post(url, **kwargs)
solver.put(url, **kwargs)
solver.delete(url, **kwargs)
solver.head(url, **kwargs)
solver.options(url, **kwargs)
solver.patch(url, **kwargs)
solver.request(method, url, **kwargs)
```

All methods accept the same keyword arguments as `curl_cffi.requests`:

```python
response = solver.post(
    "https://api.example.com/data",
    json={"key": "value"},
    headers={"Authorization": "Bearer token"},
    timeout=30,
)
```

### AsyncCloudflareSolver

Async version for use with `asyncio`:

```python
import asyncio
from cfsolver import AsyncCloudflareSolver

async def main():
    async with AsyncCloudflareSolver("your-api-key") as solver:
        response = await solver.get("https://protected-site.com")
        print(response.text)

asyncio.run(main())
```

#### Concurrent Requests

```python
import asyncio
from cfsolver import AsyncCloudflareSolver

async def fetch_all():
    urls = [
        "https://site1.com",
        "https://site2.com",
        "https://site3.com",
    ]
    
    async with AsyncCloudflareSolver("your-api-key") as solver:
        tasks = [solver.get(url) for url in urls]
        responses = await asyncio.gather(*tasks)
        
        for url, resp in zip(urls, responses):
            print(f"{url}: {resp.status_code}")

asyncio.run(fetch_all())
```

### Solving Modes

CFSolver supports three solving modes to balance speed and reliability:

#### Mode 1: Auto-detect (Default, Recommended)

Solves only when a Cloudflare challenge is detected. Best for most use cases.

```python
solver = CloudflareSolver("your-api-key")
# or explicitly:
solver = CloudflareSolver("your-api-key", solve=True, on_challenge=True)
```

#### Mode 2: Always Pre-solve

Always solves before each request. Slower but most reliable for heavily protected sites.

```python
solver = CloudflareSolver("your-api-key", solve=True, on_challenge=False)
```

#### Mode 3: Disabled

Direct requests only, no challenge solving. Useful for testing or unprotected endpoints.

```python
solver = CloudflareSolver("your-api-key", solve=False)
```

### Turnstile Support

Solve Cloudflare Turnstile CAPTCHA and get the token for form submission:

```python
from cfsolver import CloudflareSolver

with CloudflareSolver("your-api-key") as solver:
    # Get the Turnstile token
    token = solver.solve_turnstile(
        url="https://example.com/login",
        sitekey="0x4AAAAAAA..."  # From cf-turnstile element
    )
    
    # Use the token in your form submission
    response = solver.post(
        "https://example.com/login",
        data={
            "username": "user",
            "password": "pass",
            "cf-turnstile-response": token,
        }
    )
```

#### Finding the Sitekey

The sitekey is found in the page's HTML within the `cf-turnstile` element:

```html
<div class="cf-turnstile" data-sitekey="0x4AAAAAAA..."></div>
```

### Proxy Configuration

#### Single Proxy for All Requests

```python
solver = CloudflareSolver(
    "your-api-key",
    proxy="http://proxy.example.com:8080"
)
```

#### Separate Proxies for HTTP and API

Use different proxies for your HTTP requests and CloudFlyer API calls:

```python
solver = CloudflareSolver(
    "your-api-key",
    proxy="http://fast-proxy:8080",      # For your HTTP requests
    api_proxy="http://stable-proxy:8081"  # For CloudFlyer API calls
)
```

#### Supported Proxy Formats

```python
# HTTP proxy
proxy="http://host:port"
proxy="http://user:pass@host:port"

# HTTPS proxy
proxy="https://host:port"

# SOCKS5 proxy
proxy="socks5://host:port"
proxy="socks5://user:pass@host:port"
```

---

## Transparent Proxy

The transparent proxy automatically detects and solves Cloudflare challenges for **any application** that supports HTTP proxies, without requiring code changes.

### How It Works

1. Start the CFSolver proxy server
2. Configure your application to use the proxy
3. All requests are automatically monitored for Cloudflare challenges
4. When a challenge is detected, it's solved transparently
5. The `cf_clearance` cookie is cached and reused for subsequent requests

### Command Line Usage

```bash
# Start proxy on default port 8080
cfsolver proxy

# Custom host and port
cfsolver proxy -H 0.0.0.0 -P 8888

# With upstream proxy (for requests going through another proxy)
cfsolver proxy -X http://upstream:8080
cfsolver proxy -X socks5://upstream:1080

# Disable challenge detection (pure proxy mode)
cfsolver proxy -D

# Disable cookie caching (solve every challenge)
cfsolver proxy -S
```

Then use the proxy with any HTTP client:

> **Note:** Since the transparent proxy performs HTTPS interception (MITM), you must disable SSL certificate verification.

```bash
# curl (use -k to skip certificate verification)
curl -k -x http://127.0.0.1:8080 https://protected-site.com

# wget (use --no-check-certificate to skip certificate verification)
wget --no-check-certificate -e https_proxy=http://127.0.0.1:8080 https://protected-site.com

# Environment variables
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
curl -k https://protected-site.com
```

### Programmatic Usage

```python
from cfsolver import CloudAPITransparentProxy
import requests

# Using context manager
with CloudAPITransparentProxy(api_key="your-api-key", port=8080) as proxy:
    response = requests.get(
        "https://protected-site.com",
        proxies={
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080"
        },
        verify=False,  # Required for HTTPS interception
    )
    print(response.text)

# Manual start/stop
proxy = CloudAPITransparentProxy(api_key="your-api-key", port=8080)
proxy.start()

# ... make requests ...

proxy.stop()
```

#### Managing cf_clearance Cache

```python
with CloudAPITransparentProxy(api_key="your-api-key", port=8080) as proxy:
    # Pre-set cf_clearance for a host
    proxy.set_cf_clearance("example.com", "Mozilla/5.0...", "cf_clearance_value")
    
    # Get stored cf_clearance
    cf_value = proxy.get_cf_clearance("example.com", "Mozilla/5.0...")
    
    # Clear cache for specific host
    proxy.clear_cf_clearance("example.com")
    
    # Clear all cache
    proxy.clear_cf_clearance()
```

### Proxy Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | str | required | CloudFlyer API key |
| `api_base` | str | `https://solver.zetx.site` | CloudFlyer API base URL |
| `host` | str | `127.0.0.1` | Listen address |
| `port` | int | `8080` | Listen port |
| `user_proxy` | str | None | Upstream proxy for forwarding requests |
| `api_proxy` | str | None | Proxy for CloudFlyer API calls |
| `impersonate` | str | `chrome` | Browser to impersonate |
| `enable_detection` | bool | `True` | Enable challenge detection |
| `no_cache` | bool | `False` | Disable cf_clearance caching |
| `timeout` | int | `120` | Challenge solve timeout (seconds) |
| `extra_title_indicators` | list | None | Additional title patterns for detection |
| `extra_cf_indicators` | list | None | Additional CF-specific indicators |

---

## Command Line Interface

CFSolver provides a comprehensive CLI for common operations.

### Global Options

```
cfsolver --help                    Show help
cfsolver --version                 Show version
cfsolver -v <command>              Enable verbose output
```

### Common Options

These options are available for most commands:

```
-K, --api-key       API key (or set CLOUDFLYER_API_KEY env var)
-B, --api-base      API base URL (default: https://solver.zetx.site)
-X, --proxy         Proxy for HTTP requests (scheme://host:port)
--api-proxy         Proxy for API calls (scheme://host:port)
-I, --impersonate   Browser to impersonate (default: chrome)
```

### solve cloudflare

Solve a Cloudflare challenge and get cookies/user-agent:

```bash
# Basic usage
cfsolver solve cloudflare https://protected-site.com

# With options
cfsolver solve cloudflare -K your-api-key https://protected-site.com

# Output as JSON
cfsolver solve cloudflare --json https://protected-site.com

# With proxy
cfsolver solve cloudflare -X http://proxy:8080 https://protected-site.com

# With timeout
cfsolver solve cloudflare -T 180 https://protected-site.com
```

**Output (normal):**
```
[+] Challenge solved successfully!
    Status: 200
    Cookies: {'cf_clearance': '...'}
    User-Agent: Mozilla/5.0...
```

**Output (JSON):**
```json
{
  "success": true,
  "url": "https://protected-site.com",
  "status_code": 200,
  "cookies": {"cf_clearance": "..."},
  "user_agent": "Mozilla/5.0..."
}
```

### solve turnstile

Solve a Turnstile challenge and get the token:

```bash
# Basic usage
cfsolver solve turnstile https://example.com 0x4AAAAAAA...

# Output as JSON
cfsolver solve turnstile --json https://example.com 0x4AAAAAAA...

# With timeout
cfsolver solve turnstile -T 180 https://example.com 0x4AAAAAAA...
```

**Arguments:**
- `URL`: Website URL containing the Turnstile widget
- `SITEKEY`: Turnstile site key (from `data-sitekey` attribute)

**Output:**
```
[+] Turnstile solved successfully!
    Token: 0.xxx...
    Token length: 2048
```

### request

Make HTTP requests with automatic challenge bypass:

```bash
# Simple GET request
cfsolver request https://protected-site.com

# POST request with JSON data
cfsolver request -m POST -d '{"key":"value"}' https://api.example.com

# With custom headers
cfsolver request -H "Authorization: Bearer token" https://api.example.com
cfsolver request -H "Content-Type: application/json" -H "X-Custom: value" https://api.example.com

# Save response to file
cfsolver request -o output.html https://protected-site.com

# Output response info as JSON
cfsolver request --json https://protected-site.com
```

**Options:**
```
-m, --method    HTTP method (default: GET)
-d, --data      Request body data
-H, --header    Request header (can be used multiple times)
-o, --output    Output file path
--json          Output response info as JSON
```

### proxy

Start the transparent proxy server:

```bash
# Default settings (127.0.0.1:8080)
cfsolver proxy

# Custom host and port
cfsolver proxy -H 0.0.0.0 -P 8888

# With upstream proxy
cfsolver proxy -X http://upstream:8080
cfsolver proxy -X socks5://127.0.0.1:1080

# Disable challenge detection (pure proxy mode)
cfsolver proxy -D

# Disable cf_clearance caching
cfsolver proxy -S

# Custom timeout
cfsolver proxy -T 180
```

**Options:**
```
-H, --host              Listen address (default: 127.0.0.1)
-P, --port              Listen port (default: 8080)
-X, --proxy             Upstream proxy for all requests
--api-proxy             Proxy for API calls
-I, --impersonate       Browser to impersonate (default: chrome)
-D, --disable-detection Disable challenge detection
-S, --no-cache          Disable cf_clearance caching
-T, --timeout           Challenge solve timeout (default: 120)
```

### balance

Check your CloudFlyer account balance:

```bash
cfsolver balance
```

**Output:**
```
[+] Balance: 100.00
```

---

## Configuration

### Parameters

#### CloudflareSolver / AsyncCloudflareSolver

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | str | required | Your CloudFlyer API key |
| `api_base` | str | `https://solver.zetx.site` | CloudFlyer service URL |
| `solve` | bool | `True` | Enable challenge solving |
| `on_challenge` | bool | `True` | Solve only on challenge detection |
| `proxy` | str | None | Proxy for HTTP requests |
| `api_proxy` | str | None | Proxy for API calls |
| `impersonate` | str | `chrome` | Browser to impersonate |
| `use_polling` | bool | `False` | Use interval polling instead of long-polling |

#### Impersonation Options

The `impersonate` parameter accepts browser identifiers supported by `curl_cffi`:

- `chrome` (default)
- `chrome110`, `chrome116`, `chrome120`, etc.
- `firefox`
- `safari`
- `edge`

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CLOUDFLYER_API_KEY` | Default API key for all operations |
| `CLOUDFLYER_API_BASE` | Default API base URL |

```bash
# Set environment variables
export CLOUDFLYER_API_KEY="your-api-key"
export CLOUDFLYER_API_BASE="https://solver.zetx.site"

# Now you can use cfsolver without -K option
cfsolver request https://protected-site.com
```

---

## Exceptions

CFSolver defines specific exceptions for different error scenarios:

```python
from cfsolver import (
    CFSolverError,           # Base exception
    CFSolverAPIError,        # API request failed
    CFSolverChallengeError,  # Challenge solving failed
    CFSolverTimeoutError,    # Operation timed out
    CFSolverConnectionError, # Connection to service failed
    CFSolverProxyError,      # Transparent proxy error
)
```

### Exception Handling

```python
from cfsolver import CloudflareSolver, CFSolverChallengeError, CFSolverTimeoutError

try:
    with CloudflareSolver("your-api-key") as solver:
        response = solver.get("https://protected-site.com")
except CFSolverChallengeError as e:
    print(f"Failed to solve challenge: {e}")
except CFSolverTimeoutError as e:
    print(f"Operation timed out: {e}")
except CFSolverConnectionError as e:
    print(f"Connection failed: {e}")
```

---

## Examples

### Run Example Scripts

```bash
set CLOUDFLYER_API_KEY=your_api_key
set CLOUDFLYER_API_BASE=https://solver.zetx.site

python examples/sdk_challenge.py
python examples/sdk_turnstile.py

python examples/sdk_challenge.py --proxy http://user:pass@host:port
python examples/sdk_turnstile.py --proxy http://user:pass@host:port
```

### Basic Challenge Bypass

```python
import os
from cfsolver import CloudflareSolver

api_key = os.environ.get("CLOUDFLYER_API_KEY")

with CloudflareSolver(api_key) as solver:
    response = solver.get("https://protected-site.com")
    
    if response.status_code == 200:
        print("Success!")
        print(f"Cookies: {dict(solver._session.cookies)}")
```

### Turnstile Token for Login

```python
from cfsolver import CloudflareSolver

with CloudflareSolver("your-api-key") as solver:
    # Solve Turnstile
    token = solver.solve_turnstile(
        "https://example.com/login",
        "0x4AAAAAAA..."
    )
    
    # Submit login form with token
    response = solver.post(
        "https://example.com/login",
        data={
            "email": "user@example.com",
            "password": "password",
            "cf-turnstile-response": token,
        }
    )
```

### Async Scraping

```python
import asyncio
from cfsolver import AsyncCloudflareSolver

async def scrape_pages():
    urls = [
        "https://site.com/page1",
        "https://site.com/page2",
        "https://site.com/page3",
    ]
    
    async with AsyncCloudflareSolver("your-api-key") as solver:
        for url in urls:
            response = await solver.get(url)
            print(f"{url}: {len(response.text)} bytes")

asyncio.run(scrape_pages())
```

### Transparent Proxy with requests

```python
from cfsolver import CloudAPITransparentProxy
import requests

with CloudAPITransparentProxy(api_key="your-api-key", port=8080) as proxy:
    session = requests.Session()
    session.proxies = {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }
    session.verify = False
    
    # All requests through this session will auto-bypass Cloudflare
    response = session.get("https://protected-site.com")
    print(response.text)
```

### Using with Scrapy

```python
# In your Scrapy settings.py
DOWNLOADER_MIDDLEWARES = {
    'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware': 1,
}

HTTP_PROXY = 'http://127.0.0.1:8080'
HTTPS_PROXY = 'http://127.0.0.1:8080'

# Disable SSL certificate verification (required for transparent proxy)
DOWNLOAD_HANDLERS = {
    "https": "scrapy.core.downloader.handlers.http2.H2DownloadHandler",
}
DOWNLOADER_CLIENT_TLS_VERIFY_MODE = "CERT_NONE"

# Start cfsolver proxy before running Scrapy:
# cfsolver proxy -P 8080
```

### Using with httpx

```python
import httpx

# Disable SSL verification when using transparent proxy
with httpx.Client(
    proxy="http://127.0.0.1:8080",
    verify=False,  # Required for HTTPS interception
) as client:
    response = client.get("https://protected-site.com")
    print(response.text)

# Async version
async with httpx.AsyncClient(
    proxy="http://127.0.0.1:8080",
    verify=False,
) as client:
    response = await client.get("https://protected-site.com")
    print(response.text)
```

### Using with aiohttp

```python
import aiohttp
import ssl

# Create SSL context that doesn't verify certificates
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

async with aiohttp.ClientSession() as session:
    async with session.get(
        "https://protected-site.com",
        proxy="http://127.0.0.1:8080",
        ssl=ssl_context,  # Required for HTTPS interception
    ) as response:
        print(await response.text())
```

---

## Requirements

- Python 3.8+
- `curl_cffi>=0.7.0` - HTTP client with browser impersonation
- `pywssocks>=1.5.0` - WebSocket SOCKS tunnel for challenge solving
- `click>=8.0.0` - CLI framework

### Optional Dependencies

- `mitmproxy>=10.0.0` - Required for transparent proxy mode (`pip install cfsolver[proxy]`)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Links

- [CloudFlyer Website](https://cloudflyer.zetx.site)
- [API Documentation](https://cloudflyer.zetx.site/docs)
- [GitHub Repository](https://github.com/cloudflyer-project/cloudflyer-python-sdk)
- [PyPI Package](https://pypi.org/project/cfsolver)
