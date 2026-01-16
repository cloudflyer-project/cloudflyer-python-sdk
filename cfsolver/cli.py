"""
Command-line interface for cfsolver SDK.

Provides commands for solving Cloudflare challenges and running a transparent proxy.
"""

import click
import sys
import os
import json
import logging

from . import __version__


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Suppress noisy loggers even in verbose mode
    logging.getLogger("hpack").setLevel(logging.WARNING)
    logging.getLogger("hpack.hpack").setLevel(logging.WARNING)
    logging.getLogger("hpack.table").setLevel(logging.WARNING)
    logging.getLogger("pywssocks").setLevel(logging.WARNING)
    logging.getLogger("pywssocks.relay").setLevel(logging.WARNING)
    logging.getLogger("pywssocks.relay.ws").setLevel(logging.WARNING)
    logging.getLogger("websockets").setLevel(logging.WARNING)
    logging.getLogger("passlib").setLevel(logging.WARNING)


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.version_option(version=__version__, prog_name="cfsolver")
@click.pass_context
def main(ctx, verbose):
    """CFSolver - Cloudflare challenge solver using cloud API."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)


def get_api_key(api_key: str = None) -> str:
    """Get API key from argument or environment variable."""
    key = api_key or os.environ.get("CLOUDFLYER_API_KEY", "")
    if not key:
        click.echo(
            "Error: API key required. Use -K/--api-key or set CLOUDFLYER_API_KEY environment variable.",
            err=True,
        )
        sys.exit(1)
    return key


def get_api_base(api_base: str = None) -> str:
    """Get API base URL from argument or environment variable."""
    return api_base or os.environ.get("CLOUDFLYER_API_BASE", "https://solver.zetx.site")


@main.group()
def solve():
    """Solve Cloudflare challenges."""
    pass


@solve.command("cloudflare")
@click.argument("url")
@click.option("-K", "--api-key", help="API key (or set CLOUDFLYER_API_KEY env var)")
@click.option(
    "-B", "--api-base", help="API base URL (default: https://solver.zetx.site)"
)
@click.option("-X", "--proxy", help="Proxy for HTTP requests (scheme://host:port)")
@click.option("--api-proxy", help="Proxy for API calls (scheme://host:port)")
@click.option(
    "-I",
    "--impersonate",
    default="chrome",
    help="Browser to impersonate (default: chrome)",
)
@click.option(
    "-T", "--timeout", type=int, default=120, help="Timeout in seconds (default: 120)"
)
@click.option("--json", "output_json", is_flag=True, help="Output result as JSON")
@click.pass_context
def solve_cloudflare(
    ctx, url, api_key, api_base, proxy, api_proxy, impersonate, timeout, output_json
):
    """Solve Cloudflare challenge for a URL.

    URL: Target URL protected by Cloudflare
    """
    from .client import CloudflareSolver

    api_key = get_api_key(api_key)
    api_base = get_api_base(api_base)

    logger = logging.getLogger(__name__)
    logger.info(f"Solving Cloudflare challenge for: {url}")

    try:
        with CloudflareSolver(
            api_key=api_key,
            api_base=api_base,
            proxy=proxy,
            api_proxy=api_proxy,
            impersonate=impersonate,
            solve=True,
            on_challenge=False,  # Force solve
        ) as solver:
            resp = solver.get(url, timeout=timeout)

            result = {
                "success": True,
                "url": url,
                "status_code": resp.status_code,
                "cookies": dict(solver._session.cookies),
                "user_agent": solver._session.headers.get("User-Agent", ""),
            }

            if output_json:
                click.echo(json.dumps(result, indent=2))
            else:
                click.echo(f"[+] Challenge solved successfully!")
                click.echo(f"    Status: {resp.status_code}")
                click.echo(f"    Cookies: {result['cookies']}")
                if result["user_agent"]:
                    click.echo(f"    User-Agent: {result['user_agent']}")

    except Exception as e:
        if output_json:
            click.echo(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            click.echo(f"[x] Error: {e}", err=True)
        sys.exit(1)


@solve.command("turnstile")
@click.argument("url")
@click.argument("sitekey")
@click.option("-K", "--api-key", help="API key (or set CLOUDFLYER_API_KEY env var)")
@click.option(
    "-B", "--api-base", help="API base URL (default: https://solver.zetx.site)"
)
@click.option("--api-proxy", help="Proxy for API calls (scheme://host:port)")
@click.option(
    "-T", "--timeout", type=int, default=120, help="Timeout in seconds (default: 120)"
)
@click.option("--json", "output_json", is_flag=True, help="Output result as JSON")
@click.pass_context
def solve_turnstile(
    ctx, url, sitekey, api_key, api_base, api_proxy, timeout, output_json
):
    """Solve Turnstile challenge and get token.

    URL: Website URL containing the Turnstile widget
    SITEKEY: Turnstile site key (from cf-turnstile element)
    """
    from .client import CloudflareSolver

    api_key = get_api_key(api_key)
    api_base = get_api_base(api_base)

    logger = logging.getLogger(__name__)
    logger.info(f"Solving Turnstile challenge for: {url}")
    logger.info(f"Site key: {sitekey}")

    try:
        with CloudflareSolver(
            api_key=api_key,
            api_base=api_base,
            api_proxy=api_proxy,
        ) as solver:
            token = solver.solve_turnstile(url, sitekey)

            result = {
                "success": True,
                "url": url,
                "sitekey": sitekey,
                "token": token,
            }

            if output_json:
                click.echo(json.dumps(result, indent=2))
            else:
                click.echo(f"[+] Turnstile solved successfully!")
                click.echo(
                    f"    Token: {token[:80]}..."
                    if len(token) > 80
                    else f"    Token: {token}"
                )
                click.echo(f"    Token length: {len(token)}")

    except Exception as e:
        if output_json:
            click.echo(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            click.echo(f"[x] Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option("-K", "--api-key", help="API key (or set CLOUDFLYER_API_KEY env var)")
@click.option(
    "-B", "--api-base", help="API base URL (default: https://solver.zetx.site)"
)
@click.option(
    "-H", "--host", default="127.0.0.1", help="Listen address (default: 127.0.0.1)"
)
@click.option(
    "-P", "--port", type=int, default=8080, help="Listen port (default: 8080)"
)
@click.option(
    "-X",
    "--proxy",
    help="Proxy for all requests (socks5://host:port or http://host:port)",
)
@click.option("--api-proxy", help="Proxy for API calls (scheme://host:port)")
@click.option(
    "-I",
    "--impersonate",
    default="chrome",
    help="Browser to impersonate (default: chrome)",
)
@click.option(
    "-D",
    "--disable-detection",
    is_flag=True,
    help="Disable challenge detection (proxy-only mode)",
)
@click.option("-S", "--no-cache", is_flag=True, help="Disable cf_clearance caching")
@click.option(
    "-T",
    "--timeout",
    type=int,
    default=120,
    help="Challenge solve timeout (default: 120)",
)
@click.pass_context
def proxy(
    ctx,
    api_key,
    api_base,
    host,
    port,
    proxy,
    api_proxy,
    impersonate,
    disable_detection,
    no_cache,
    timeout,
):
    """Start transparent proxy with Cloudflare challenge detection.

    The proxy automatically detects and solves Cloudflare challenges using the cloud API.
    Configure your application to use this proxy (http://host:port) for automatic bypass.

    The --proxy option specifies a proxy that will be used for:
    1. Normal requests (via mitmproxy upstream)
    2. Challenge solving (via linksocks tunnel, requires socks5://)

    Example:
        cfsolver proxy -K your_api_key -P 8080
        cfsolver proxy -K your_api_key -X socks5://127.0.0.1:1080
        curl -x http://127.0.0.1:8080 https://protected-site.com
    """
    from .tproxy import start_transparent_proxy

    api_key = get_api_key(api_key)
    api_base = get_api_base(api_base)

    logger = logging.getLogger(__name__)
    logger.info(f"Starting transparent proxy on {host}:{port}")

    try:
        start_transparent_proxy(
            api_key=api_key,
            api_base=api_base,
            host=host,
            port=port,
            user_proxy=proxy,
            api_proxy=api_proxy,
            impersonate=impersonate,
            enable_detection=not disable_detection,
            no_cache=no_cache,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        click.echo("\nProxy stopped by user")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("url")
@click.option("-K", "--api-key", help="API key (or set CLOUDFLYER_API_KEY env var)")
@click.option(
    "-B", "--api-base", help="API base URL (default: https://solver.zetx.site)"
)
@click.option("-X", "--proxy", help="Proxy for HTTP requests (scheme://host:port)")
@click.option("--api-proxy", help="Proxy for API calls (scheme://host:port)")
@click.option(
    "-I",
    "--impersonate",
    default="chrome",
    help="Browser to impersonate (default: chrome)",
)
@click.option("-m", "--method", default="GET", help="HTTP method (default: GET)")
@click.option("-d", "--data", help="Request body data")
@click.option(
    "-H", "--header", multiple=True, help="Request header (can be used multiple times)"
)
@click.option("-o", "--output", help="Output file path")
@click.option(
    "--json", "output_json", is_flag=True, help="Output response info as JSON"
)
@click.pass_context
def request(
    ctx,
    url,
    api_key,
    api_base,
    proxy,
    api_proxy,
    impersonate,
    method,
    data,
    header,
    output,
    output_json,
):
    """Make HTTP request with automatic challenge bypass.

    URL: Target URL

    Examples:
        cfsolver request https://example.com
        cfsolver request -m POST -d '{"key":"value"}' https://api.example.com
        cfsolver request -H "Authorization: Bearer token" https://api.example.com
    """
    from .client import CloudflareSolver

    api_key = get_api_key(api_key)
    api_base = get_api_base(api_base)

    logger = logging.getLogger(__name__)
    logger.info(f"Making {method} request to: {url}")

    # Parse headers
    headers = {}
    for h in header:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()

    try:
        with CloudflareSolver(
            api_key=api_key,
            api_base=api_base,
            proxy=proxy,
            api_proxy=api_proxy,
            impersonate=impersonate,
        ) as solver:
            kwargs = {"headers": headers} if headers else {}
            if data:
                kwargs["data"] = data

            resp = solver.request(method.upper(), url, **kwargs)

            if output:
                with open(output, "wb") as f:
                    f.write(resp.content)
                click.echo(f"[+] Response saved to: {output}")
            elif output_json:
                result = {
                    "url": url,
                    "method": method.upper(),
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "cookies": dict(solver._session.cookies),
                    "content_length": len(resp.content),
                }
                click.echo(json.dumps(result, indent=2))
            else:
                click.echo(resp.text)

    except Exception as e:
        if output_json:
            click.echo(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            click.echo(f"[x] Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option("-K", "--api-key", help="API key (or set CLOUDFLYER_API_KEY env var)")
@click.option(
    "-B", "--api-base", help="API base URL (default: https://solver.zetx.site)"
)
@click.option("--api-proxy", help="Proxy for API calls (scheme://host:port)")
@click.pass_context
def balance(ctx, api_key, api_base, api_proxy):
    """Check account balance."""
    from curl_cffi.requests import Session

    api_key = get_api_key(api_key)
    api_base = get_api_base(api_base)

    try:
        with Session(verify=False, proxy=api_proxy) as session:
            resp = session.post(
                f"{api_base}/api/getBalance",
                json={"clientKey": api_key},
            )

            if resp.status_code != 200:
                click.echo(f"[x] Error: HTTP {resp.status_code}", err=True)
                sys.exit(1)

            data = resp.json()
            if data.get("errorId"):
                click.echo(
                    f"[x] Error: {data.get('errorDescription', 'Unknown error')}",
                    err=True,
                )
                sys.exit(1)

            balance_val = data.get("balance", 0)
            click.echo(f"[+] Balance: {balance_val}")

    except Exception as e:
        click.echo(f"[x] Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
