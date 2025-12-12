"""
Authentication factory for strategy selection.

This module provides the main entry point for authentication and implements
the auto-detection logic that selects the appropriate authentication strategy
based on the environment and configuration.
"""

import logging
import os

from kubernetes.client import ApiClient

from .config import AuthConfig
from .exceptions import AuthenticationError, ConfigurationError
from .strategies.base import AuthStrategy
from .strategies.incluster import InClusterStrategy
from .strategies.kubeconfig import KubeConfigStrategy
from .strategies.oidc import OIDCStrategy
from .strategies.openshift import OpenShiftOAuthStrategy

logger = logging.getLogger(__name__)


def get_k8s_client(config: AuthConfig | None = None) -> ApiClient:
    """Get authenticated Kubernetes API client.

    This is the main entry point for the library. It automatically detects
    the best authentication method based on the environment and configuration,
    then returns a ready-to-use Kubernetes ApiClient.

    Args:
        config: Optional AuthConfig. If None, uses auto-detection with defaults.

    Returns:
        Configured Kubernetes ApiClient ready to make API calls

    Raises:
        ConfigurationError: If configuration is invalid
        AuthenticationError: If authentication fails
        StrategyNotAvailableError: If requested method is not available

    Example:
        >>> # Auto-detection (simplest)
        >>> api_client = get_k8s_client()
        >>> v1 = client.CoreV1Api(api_client)
        >>>
        >>> # Explicit configuration
        >>> config = AuthConfig(method="oidc", oidc_issuer="...", client_id="...")
        >>> api_client = get_k8s_client(config)
    """
    # Use default config if none provided
    if config is None:
        config = AuthConfig()

    logger.debug(f"Getting Kubernetes client with config: {config}")

    # Select and execute authentication strategy
    factory = AuthFactory(config)
    strategy = factory.get_strategy()

    logger.info(f"Using authentication strategy: {strategy.get_description()}")

    # Authenticate and return ApiClient
    return strategy.authenticate()


class AuthFactory:
    """Factory for selecting and creating authentication strategies.

    This class implements the strategy selection logic, including
    auto-detection of the best authentication method based on
    the current environment.

    Args:
        config: AuthConfig instance with authentication parameters
    """

    def __init__(self, config: AuthConfig) -> None:
        """Initialize factory with configuration.

        Args:
            config: AuthConfig instance
        """
        self.config = config

    def get_strategy(self) -> AuthStrategy:
        """Select and return appropriate authentication strategy.

        This method implements the auto-detection logic when method="auto",
        or returns the explicitly requested strategy when method is specified.

        Returns:
            AuthStrategy instance ready to authenticate

        Raises:
            ConfigurationError: If method is invalid or required params missing
            StrategyNotAvailableError: If requested strategy not available
        """
        # If method is explicitly specified, use that
        if self.config.method != "auto":
            return self._get_strategy_by_name(self.config.method)

        # Auto-detection logic
        logger.debug("Auto-detecting authentication method")
        return self._auto_detect_strategy()

    def _get_strategy_by_name(self, method: str) -> AuthStrategy:
        """Get strategy by explicit method name.

        Args:
            method: Strategy name ("kubeconfig", "incluster", "oidc", "openshift")

        Returns:
            AuthStrategy instance

        Raises:
            ConfigurationError: If method is unknown
            StrategyNotAvailableError: If strategy prerequisites not met
        """
        strategy_map = {
            "kubeconfig": KubeConfigStrategy,
            "incluster": InClusterStrategy,
            "oidc": OIDCStrategy,
            "openshift": OpenShiftOAuthStrategy,
        }

        strategy_class = strategy_map.get(method)
        if strategy_class is None:
            available = ", ".join(sorted(strategy_map.keys()))
            raise ConfigurationError(
                f"Unknown authentication method: {method}",
                f"Available methods: {available}"
            )

        # Create and validate strategy
        strategy = strategy_class(self.config)

        if not strategy.is_available():
            raise ConfigurationError(
                f"Authentication method '{method}' is not available in this environment",
                f"Strategy check failed: {strategy.get_description()}"
            )

        return strategy

    def _auto_detect_strategy(self) -> AuthStrategy:
        """Auto-detect best authentication strategy for current environment.

        Detection precedence:
        1. Environment variables (OIDC_CLIENT_ID, etc.) -> OIDC
        2. In-cluster (KUBERNETES_SERVICE_HOST, service account) -> InCluster
        3. KubeConfig (~/.kube/config or KUBECONFIG) -> KubeConfig
        4. Interactive fallback (Phase 2) -> OIDC with device/browser flow

        Returns:
            AuthStrategy instance

        Raises:
            AuthenticationError: If no suitable strategy found
        """
        # Check for OIDC environment variables
        if self._has_oidc_env_vars():
            logger.debug("Detected OIDC environment variables")
            oidc_strategy = OIDCStrategy(self.config)
            if oidc_strategy.is_available():
                logger.debug("OIDC authentication available")
                return oidc_strategy

        # Check for OpenShift OAuth (token or k8s_api_host)
        if self.config.openshift_token or os.getenv("OPENSHIFT_TOKEN"):
            logger.debug("Detected OpenShift token")
            openshift_strategy = OpenShiftOAuthStrategy(self.config)
            if openshift_strategy.is_available():
                logger.debug("OpenShift OAuth available")
                return openshift_strategy

        # Check for in-cluster environment
        incluster_strategy = InClusterStrategy(self.config)
        if incluster_strategy.is_available():
            logger.debug("Detected in-cluster environment")
            return incluster_strategy

        # Check for kubeconfig
        kubeconfig_strategy = KubeConfigStrategy(self.config)
        if kubeconfig_strategy.is_available():
            logger.debug("Detected kubeconfig")
            return kubeconfig_strategy

        # No strategy available
        raise AuthenticationError(
            "No authentication method available",
            "Could not find any valid authentication credentials. Tried:\n"
            "1. OIDC environment variables (OIDC_ISSUER, OIDC_CLIENT_ID) - not found or invalid\n"
            "2. In-cluster service account - not available\n"
            "3. KubeConfig file (~/.kube/config) - not found\n\n"
            "Please provide authentication credentials using one of these methods:\n"
            "- Use kubectl to log in and generate ~/.kube/config\n"
            "- Run inside a Kubernetes Pod with a service account\n"
            "- Provide explicit OIDC configuration via AuthConfig\n"
            "- Set OIDC environment variables (OIDC_ISSUER, OIDC_CLIENT_ID)"
        )

    def _has_oidc_env_vars(self) -> bool:
        """Check if OIDC environment variables are present.

        Returns:
            True if OIDC env vars are set, False otherwise
        """
        # Check for minimal OIDC configuration in environment
        has_issuer = os.getenv("OIDC_ISSUER") is not None
        has_client_id = os.getenv("OIDC_CLIENT_ID") is not None

        return has_issuer and has_client_id
