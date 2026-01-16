"""
Example: Solve Cloudflare Challenge on 2captcha demo page using cfsolver SDK.

This script demonstrates how to use the CloudflareSolver to bypass
Cloudflare's challenge protection on the 2captcha demo site.

Usage:
    pip install cfsolver
    export CLOUDFLYER_API_KEY="your_api_key"
    python sdk_challenge.py --proxy http://user:pass@host:port
"""

import os
import sys
import logging
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from cfsolver import CloudflareSolver

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


DEMO_URL = "https://cloudflyer.zetx.site/demo/challenge"


def main():
    parser = argparse.ArgumentParser(
        description="Solve Cloudflare Challenge using cfsolver SDK"
    )
    parser.add_argument(
        "--proxy",
        dest="task_proxy",
        help="Task proxy for solver (e.g. http://user:pass@host:port)",
    )
    args = parser.parse_args()

    api_key = os.environ.get("CLOUDFLYER_API_KEY", "")
    api_base = os.environ.get("CLOUDFLYER_API_BASE", "https://solver.zetx.site")

    if not api_key:
        logger.error("Please set CLOUDFLYER_API_KEY environment variable")
        sys.exit(1)

    logger.info(f"Target URL: {DEMO_URL}")
    logger.info(f"API Base: {api_base}")
    if args.task_proxy:
        logger.info(f"Proxy: {args.task_proxy}")

    with CloudflareSolver(
        api_key=api_key,
        api_base=api_base,
        solve=True,
        on_challenge=True,
        proxy=args.task_proxy,
    ) as solver:
        logger.info("Sending request to demo page...")
        resp = solver.get(DEMO_URL)

        logger.info(f"Response status: {resp.status_code}")

        if resp.status_code == 200:
            if "cf-turnstile" in resp.text.lower() and "challenge" in resp.text.lower():
                logger.warning("Challenge page still present - solve may have failed")
            else:
                logger.info("Challenge bypassed successfully!")
                logger.info(f"Cookies obtained: {dict(solver._session.cookies)}")
        else:
            logger.error(f"Request failed with status {resp.status_code}")
            logger.error(f"Response: {resp.text[:500]}")


if __name__ == "__main__":
    main()
