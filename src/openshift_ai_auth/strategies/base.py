"""
Abstract base class for authentication strategies.

This module defines the AuthStrategy interface that all concrete
authentication strategies must implement. The Strategy Pattern allows
us to easily add new authentication methods without modifying existing code.
"""

from abc import ABC, abstractmethod

from kubernetes.client import ApiClient

from ..config import AuthConfig


class AuthStrategy(ABC):
    """Abstract base class for authentication strategies.

    Each authentication strategy (KubeConfig, InCluster, OIDC, etc.) must
    implement this interface. This ensures a consistent API across all
    authentication methods.

    Args:
        config: AuthConfig instance containing authentication parameters

    Example:
        >>> class MyStrategy(AuthStrategy):
        ...     def is_available(self) -> bool:
        ...         return True  # Check if strategy can be used
        ...
        ...     def authenticate(self) -> ApiClient:
        ...         # Implement authentication logic
        ...         return configured_api_client
    """

    def __init__(self, config: AuthConfig) -> None:
        """Initialize strategy with configuration.

        Args:
            config: AuthConfig instance with authentication parameters
        """
        self.config = config

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this strategy can be used in the current environment.

        This method should check whether the necessary prerequisites for
        this authentication strategy are present. For example:
        - KubeConfigStrategy checks if ~/.kube/config exists
        - InClusterStrategy checks if service account token is mounted
        - OIDCStrategy checks if required OIDC config is provided

        Returns:
            True if strategy can be used, False otherwise

        Example:
            >>> strategy = KubeConfigStrategy(config)
            >>> if strategy.is_available():
            ...     client = strategy.authenticate()
        """
        pass

    @abstractmethod
    def authenticate(self) -> ApiClient:
        """Authenticate and return configured Kubernetes ApiClient.

        This method performs the actual authentication and returns a
        configured kubernetes.client.ApiClient that can be used immediately
        to make API calls to the cluster.

        Returns:
            Configured Kubernetes ApiClient ready to use

        Raises:
            AuthenticationError: If authentication fails
            StrategyNotAvailableError: If strategy prerequisites not met

        Example:
            >>> strategy = InClusterStrategy(config)
            >>> api_client = strategy.authenticate()
            >>> v1 = client.CoreV1Api(api_client)
            >>> pods = v1.list_pod_for_all_namespaces()
        """
        pass

    def refresh_if_needed(self) -> None:
        """Refresh authentication token if needed.

        This method is optional and only relevant for strategies that
        support token refresh (e.g., OIDC). The default implementation
        does nothing.

        Strategies that support token refresh should override this method
        to check if the token is expired and refresh it if necessary.

        Raises:
            TokenRefreshError: If token refresh fails
        """
        raise NotImplementedError

    def get_description(self) -> str:
        """Get human-readable description of this strategy.

        Returns:
            Description of the authentication strategy

        Example:
            >>> strategy.get_description()
            'Kubernetes KubeConfig (~/.kube/config)'
        """
        return self.__class__.__name__
