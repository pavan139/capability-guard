"""Local capability authorization; no login service or operating-system sandbox."""

from .authority import Authority, AuthorizationError, Claims, Operation

__all__ = ["Authority", "AuthorizationError", "Claims", "Operation"]
