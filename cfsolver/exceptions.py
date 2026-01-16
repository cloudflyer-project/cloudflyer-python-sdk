"""
CFSolver Exceptions

Custom exception classes for the CFSolver library.
"""


class CFSolverError(Exception):
    """Base exception for all CFSolver errors."""
    pass


class CFSolverAPIError(CFSolverError):
    """Raised when API request fails."""
    pass


class CFSolverChallengeError(CFSolverError):
    """Raised when challenge solving fails."""
    pass


class CFSolverTimeoutError(CFSolverError):
    """Raised when operation times out."""
    pass


class CFSolverConnectionError(CFSolverError):
    """Raised when connection to service fails."""
    pass


class CFSolverProxyError(CFSolverError):
    """Raised when transparent proxy operation fails."""
    pass
