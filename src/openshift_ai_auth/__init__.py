"""
OpenShift AI Authentication Library.

A lightweight Python library for unified authentication to OpenShift and
Kubernetes clusters. Supports multiple authentication methods through a
single, consistent interface.

Quick Start:
    >>> from openshift_ai_auth import get_k8s_client
    >>> from kubernetes import client
    >>>
    >>> # Auto-detect and authenticate
    >>> api_client = get_k8s_client()
    >>> v1 = client.CoreV1Api(api_client)
    >>> pods = v1.list_pod_for_all_namespaces()

For more control:
    >>> from openshift_ai_auth import get_k8s_client, AuthConfig
    >>>
    >>> config = AuthConfig(
    ...     method="oidc",
    ...     oidc_issuer="https://keycloak.example.com/auth/realms/myrealm",
    ...     client_id="my-client"
    ... )
    >>> api_client = get_k8s_client(config)
"""

import logging

# Public API
from .config import AuthConfig
from .exceptions import (
    AuthenticationError,
    ConfigurationError,
    OIDCError,
    OpenShiftOAuthError,
    StrategyNotAvailableError,
    TokenRefreshError,
)
from .factory import get_k8s_client

# Version
__version__ = "0.1.0"

# Public exports
__all__ = [
    # Main function
    "get_k8s_client",
    # Configuration
    "AuthConfig",
    # Exceptions
    "AuthenticationError",
    "ConfigurationError",
    "TokenRefreshError",
    "StrategyNotAvailableError",
    "OIDCError",
    "OpenShiftOAuthError",
    # Version
    "__version__",
]

# Configure logging
# Users can configure the logger in their own code:
#   import logging
#   logging.getLogger("openshift_ai_auth").setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())  # Avoid "No handler" warnings
