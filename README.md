# CFSolver

Python HTTP client that automatically bypasses Cloudflare challenges.

## Installation

```bash
pip install cfsolver

# With transparent proxy support
pip install cfsolver[proxy]

# All features
pip install cfsolver[all]
```

## Features

- **Drop-in replacement** for `requests` and `httpx`
- **Automatic challenge detection and solving**
- **Flexible solving modes**: auto-detect, always solve, or disable
- **Proxy support** for both HTTP requests and API calls
- **Command-line interface** for quick operations
- **Transparent proxy mode** for automatic bypass without code changes
- Compatible with synchronous and asynchronous code

## Quick Start

Works just like `requests`, but automatically handles Cloudflare challenges:

```python
from cfsolver import CloudflareSolver

solver = CloudflareSolver("your-api-key")
response = solver.get("https://protected-site.com")
print(response.text)
```

## Command Line Interface

CFSolver provides a powerful CLI for common operations:

### Solve Cloudflare Challenge

```bash
# Using environment variable
export CLOUDFLYER_API_KEY="your-api-key"
cfsolver solve cloudflare https://protected-site.com

# Using command line option
cfsolver solve cloudflare -K your-api-key https://protected-site.com

# Output as JSON
cfsolver solve cloudflare --json https://protected-site.com
```

### Solve Turnstile

```bash
cfsolver solve turnstile https://example.com 0x4AAAAAAA...

# Output as JSON
cfsolver solve turnstile --json https://example.com 0x4AAAAAAA...
```

### Make HTTP Request

```bash
# Simple GET request
cfsolver request https://protected-site.com

# POST request with data
cfsolver request -m POST -d '{"key":"value"}' https://api.example.com

# With custom headers
cfsolver request -H "Authorization: Bearer token" https://api.example.com

# Save response to file
cfsolver request -o output.html https://protected-site.com
```

### Check Balance

```bash
cfsolver balance
```

### Start Transparent Proxy

```bash
# Start proxy on default port 8080
cfsolver proxy

# Custom host and port
cfsolver proxy -H 0.0.0.0 -P 8888

# With upstream proxy
cfsolver proxy -X http://upstream-proxy:8080

# Disable challenge detection (pure proxy mode)
cfsolver proxy -D
```

### CLI Options

```
cfsolver --help                    # Show help
cfsolver --version                 # Show version
cfsolver -v <command>              # Verbose output

# Common options for most commands:
-K, --api-key       API key (or set CLOUDFLYER_API_KEY env var)
-B, --api-base      API base URL (default: https://solver.zetx.site)
-X, --proxy         Proxy for HTTP requests
--api-proxy         Proxy for API calls
-I, --impersonate   Browser to impersonate (default: chrome)
```

## Transparent Proxy Mode

The transparent proxy automatically detects and solves Cloudflare challenges for any application that supports HTTP proxies.

### Command Line

```bash
# Start the proxy
cfsolver proxy -P 8080

# In another terminal, use the proxy
curl -x http://127.0.0.1:8080 https://protected-site.com

# Or set environment variable
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
curl https://protected-site.com
```

### Programmatic Usage

```python
from cfsolver import CloudAPITransparentProxy

# Start proxy
proxy = CloudAPITransparentProxy(
    api_key="your-api-key",
    host="127.0.0.1",
    port=8080,
)
proxy.start()

# Use with requests
import requests
response = requests.get(
    "https://protected-site.com",
    proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"},
    verify=False,
)

# Stop proxy
proxy.stop()

# Or use context manager
with CloudAPITransparentProxy(api_key="your-api-key", port=8080) as proxy:
    response = requests.get(
        "https://protected-site.com",
        proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"},
        verify=False,
    )
```

### Proxy Options

- `api_key`: CloudFlyer API key (required)
- `api_base`: API base URL (default: `https://solver.zetx.site`)
- `host`: Listen address (default: `127.0.0.1`)
- `port`: Listen port (default: `8080`)
- `upstream_proxy`: Upstream proxy for forwarding requests
- `api_proxy`: Proxy for API calls to CloudFlyer
- `enable_detection`: Enable challenge detection (default: `True`)
- `no_cache`: Disable cf_clearance caching (default: `False`)
- `timeout`: Challenge solve timeout in seconds (default: `120`)

## Python API Usage

### Basic Usage (Auto-solve on challenge)

```python
from cfsolver import CloudflareSolver

# Default: solve only when challenge is detected
solver = CloudflareSolver("your-api-key")

response = solver.get("https://example.com/")
print(response.text)
```

### Solving Modes

```python
from cfsolver import CloudflareSolver

# Mode 1: Solve only when CF challenge is detected (default, recommended)
solver = CloudflareSolver("your-api-key")

# Mode 2: Always pre-solve before each request (slow but most reliable)
solver = CloudflareSolver("your-api-key", solve=True, on_challenge=False)

# Mode 3: Disable solving entirely (direct requests only)
solver = CloudflareSolver("your-api-key", solve=False)
```

### Solve Turnstile

```python
from cfsolver import CloudflareSolver

solver = CloudflareSolver("your-api-key")
token = solver.solve_turnstile("https://example.com", "0x4AAAAAAA...")
print(f"Token: {token}")
```

### With Proxies

```python
# Use proxy for HTTP requests only
solver = CloudflareSolver(
    "your-api-key",
    proxy="http://your-proxy:8080"
)

# Use separate proxies for HTTP requests and API calls
solver = CloudflareSolver(
    "your-api-key",
    proxy="http://proxy-for-http-requests:8080",
    api_proxy="http://proxy-for-api-calls:8081"
)
```

### Context Manager

```python
with CloudflareSolver("your-api-key") as solver:
    resp = solver.get("https://example.com/")
    print(resp.json())
```

### Async Usage

```python
import asyncio
from cfsolver import AsyncCloudflareSolver

async def main():
    async with AsyncCloudflareSolver("your-api-key") as solver:
        response = await solver.get("https://protected-site.com")
        print(response.text)

asyncio.run(main())
```

## Parameters

- `api_key`: Your API key (required)
- `api_base`: CloudFlyer service URL (default: `https://solver.zetx.site`)
- `solve`: Enable challenge solving (default `True`, set to `False` to disable completely)
- `on_challenge`: Solve only on challenge detection (default `True`), or always pre-solve (`False`)
- `proxy`: Proxy for outgoing HTTP requests (optional)
- `api_proxy`: Proxy for service API calls (optional)
- `impersonate`: Browser to impersonate (default: `chrome`)

## Environment Variables

- `CLOUDFLYER_API_KEY`: Default API key
- `CLOUDFLYER_API_BASE`: Default API base URL

## License

MIT
