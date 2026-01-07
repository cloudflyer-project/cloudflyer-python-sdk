# CFSolver

Python HTTP client that automatically bypasses Cloudflare challenges.

## Installation

```bash
pip install cfsolver
```

## Features

- **Drop-in replacement** for `requests` and `httpx`
- **Automatic challenge detection and solving**
- **Flexible solving modes**: auto-detect, always solve, or disable
- **Proxy support** for both HTTP requests and API calls
- Compatible with synchronous and asynchronous code

## Quick Start

Works just like `requests`, but automatically handles Cloudflare challenges:

```python
from cfsolver import CloudflareSolver

solver = CloudflareSolver("your-api-key")
response = solver.get("https://protected-site.com")
print(response.text)
```

## Usage

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

## Parameters

- `api_key`: Your API key (required)
- `api_base`: CloudFlyer service URL (default: `https://solver.zetx.site`)
- `solve`: Enable challenge solving (default `True`, set to `False` to disable completely)
- `on_challenge`: Solve only on challenge detection (default `True`), or always pre-solve (`False`)
- `proxy`: Proxy for outgoing HTTP requests (optional)
- `api_proxy`: Proxy for service API calls (optional)

## Security Notes

- **Token generation**: Connector tokens are auto-generated internally using `secrets.token_urlsafe()` for cryptographically secure randomness, never exposed to users
- **Proxy separation**: HTTP requests use `proxy` parameter, while API calls use `api_proxy` parameter for independent proxy configuration

## License

MIT
