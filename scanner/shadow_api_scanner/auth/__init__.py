"""Session acquisition for authenticated targets."""

from shadow_api_scanner.auth.session_manager import (
    LoginConfigError,
    LoginError,
    SessionContext,
    SessionManager,
)

__all__ = [
    "SessionManager",
    "SessionContext",
    "LoginConfigError",
    "LoginError",
]
