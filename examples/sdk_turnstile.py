"""
Example: Solve Cloudflare Turnstile using cfsolver SDK.

This script demonstrates how to use the CloudflareSolver to solve
Turnstile challenges and obtain the token.

Usage:
    set CLOUDFLYER_API_KEY=your_api_key
    python sdk_turnstile.py --proxy http://user:pass@host:port
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


DEMO_URL = "https://cloudflyer.zetx.site/demo/turnstile"
SITE_KEY = "0x4AAAAAACJkAlPHW8xr1T2J"


def main():
    parser = argparse.ArgumentParser(
        description="Solve Cloudflare Turnstile using cfsolver SDK"
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
    logger.info(f"Site Key: {SITE_KEY}")
    if args.task_proxy:
        logger.info(f"Task Proxy: {args.task_proxy}")

    with CloudflareSolver(
        api_key=api_key,
        api_base=api_base,
        task_proxy=args.task_proxy,
    ) as solver:
        logger.info("Solving Turnstile challenge...")
        token = solver.solve_turnstile(DEMO_URL, SITE_KEY)

        logger.info("Turnstile solved successfully!")
        logger.info(f"Token: {token[:80]}...")
        logger.info(f"Token length: {len(token)}")


if __name__ == "__main__":
    main()
