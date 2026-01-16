from .client import CloudflareSolver
from .async_client import AsyncCloudflareSolver
from .exceptions import (
    CFSolverError,
    CFSolverAPIError,
    CFSolverChallengeError,
    CFSolverTimeoutError,
    CFSolverConnectionError,
    CFSolverProxyError,
)

__version__ = "0.0.0"

__all__ = [
    "CloudflareSolver",
    "AsyncCloudflareSolver",
    "CFSolverError",
    "CFSolverAPIError",
    "CFSolverChallengeError",
    "CFSolverTimeoutError",
    "CFSolverConnectionError",
    "CFSolverProxyError",
    "__version__",
]


# Lazy imports for optional dependencies
def __getattr__(name):
    if name == "CloudAPITransparentProxy":
        from .tproxy import CloudAPITransparentProxy

        return CloudAPITransparentProxy
    if name == "start_transparent_proxy":
        from .tproxy import start_transparent_proxy

        return start_transparent_proxy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
