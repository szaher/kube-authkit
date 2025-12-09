"""
Custom exceptions for OpenShift AI authentication library.

This module defines the exception hierarchy used throughout the library.
All exceptions inherit from AuthenticationError, making it easy to catch
any authentication-related error.
"""


class AuthenticationError(Exception):
    """Base exception for all authentication-related errors.

    This is the base class for all exceptions raised by this library.
    Catching this exception will catch all authentication errors.

    Args:
        message: Human-readable error message
        details: Optional additional details about the error
    """

    def __init__(self, message: str, details: str | None = None) -> None:
        self.message = message
        self.details = details
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}\nDetails: {self.details}"
        return self.message


class ConfigurationError(AuthenticationError):
    """Configuration is invalid or incomplete.

    Raised when the provided AuthConfig contains invalid or missing
    required parameters for the requested authentication method.

    Example:
        >>> config = AuthConfig(method="oidc")  # Missing required OIDC parameters
        >>> # Raises: ConfigurationError("OIDC authentication requires oidc_issuer")
    """
    pass


class TokenRefreshError(AuthenticationError):
    """Failed to refresh authentication token.

    Raised when automatic token refresh fails. This typically indicates
    that the refresh token has expired or been revoked, and the user
    needs to re-authenticate.

    Example:
        >>> # Token refresh fails after refresh_token expires
        >>> # Raises: TokenRefreshError("Refresh token expired, re-authentication required")
    """
    pass


class StrategyNotAvailableError(AuthenticationError):
    """Requested authentication strategy cannot be used in current environment.

    Raised when a specific authentication method is requested but cannot
    be used in the current environment. For example, requesting in-cluster
    authentication when not running inside a Kubernetes pod.

    Example:
        >>> config = AuthConfig(method="incluster")
        >>> # Running locally without service account token
        >>> # Raises: StrategyNotAvailableError("In-cluster auth not available: ...")
    """
    pass


class OIDCError(AuthenticationError):
    """OIDC-specific authentication error.

    Raised when OIDC authentication fails for reasons specific to the
    OIDC protocol (discovery failures, token endpoint errors, etc.).
    """
    pass


class OpenShiftOAuthError(AuthenticationError):
    """OpenShift OAuth-specific authentication error.

    Raised when OpenShift OAuth authentication fails for reasons specific
    to OpenShift's OAuth implementation.
    """
    pass
