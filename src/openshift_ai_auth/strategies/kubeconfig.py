"""
KubeConfig authentication strategy.

This strategy uses the standard Kubernetes kubeconfig file (~/.kube/config)
for authentication. This is the most common authentication method for local
development and kubectl usage.
"""

import logging
import os
from pathlib import Path

from kubernetes import client
from kubernetes import config as k8s_config
from kubernetes.client import ApiClient
from kubernetes.config import ConfigException

from ..exceptions import AuthenticationError, StrategyNotAvailableError
from .base import AuthStrategy

logger = logging.getLogger(__name__)


class KubeConfigStrategy(AuthStrategy):
    """Authenticate using Kubernetes kubeconfig file.

    This strategy loads authentication credentials from a kubeconfig file,
    which is the standard way kubectl and other Kubernetes tools authenticate.

    The strategy searches for kubeconfig in this order:
    1. Path specified in AuthConfig.kubeconfig_path
    2. Path specified in KUBECONFIG environment variable
    3. Default path: ~/.kube/config

    Example:
        >>> config = AuthConfig(method="kubeconfig")
        >>> strategy = KubeConfigStrategy(config)
        >>> if strategy.is_available():
        ...     api_client = strategy.authenticate()
    """

    def is_available(self) -> bool:
        """Check if kubeconfig file exists and is readable.

        Returns:
            True if kubeconfig file exists, False otherwise
        """
        kubeconfig_path = self._get_kubeconfig_path()
        if kubeconfig_path is None:
            logger.debug("No kubeconfig file found")
            return False

        if not os.path.exists(kubeconfig_path):
            logger.debug(f"Kubeconfig file does not exist: {kubeconfig_path}")
            return False

        if not os.access(kubeconfig_path, os.R_OK):
            logger.warning(f"Kubeconfig file is not readable: {kubeconfig_path}")
            return False

        logger.debug(f"Kubeconfig file found: {kubeconfig_path}")
        return True

    def authenticate(self) -> ApiClient:
        """Authenticate using kubeconfig file.

        Returns:
            Configured Kubernetes ApiClient

        Raises:
            StrategyNotAvailableError: If kubeconfig file not found
            AuthenticationError: If authentication fails
        """
        if not self.is_available():
            raise StrategyNotAvailableError(
                "KubeConfig authentication not available",
                f"No kubeconfig file found. Checked:\n"
                f"1. Config parameter: {self.config.kubeconfig_path}\n"
                f"2. KUBECONFIG env var: {os.getenv('KUBECONFIG')}\n"
                f"3. Default path: ~/.kube/config"
            )

        kubeconfig_path = self._get_kubeconfig_path()
        logger.info(f"Authenticating using kubeconfig: {kubeconfig_path}")

        try:
            # Load kubeconfig and return configured ApiClient
            # The load_kube_config function configures the global kubernetes
            # client configuration. We then create an ApiClient from that config.
            k8s_config.load_kube_config(
                config_file=kubeconfig_path
            )

            # Create and return ApiClient
            api_client = client.ApiClient()

            # Apply custom CA cert if specified
            if self.config.ca_cert:
                logger.debug(f"Using custom CA certificate: {self.config.ca_cert}")
                api_client.configuration.ssl_ca_cert = self.config.ca_cert

            # Apply SSL verification setting
            if not self.config.verify_ssl:
                logger.warning("SSL verification is disabled")
                api_client.configuration.verify_ssl = False

            logger.info("Successfully authenticated using kubeconfig")
            return api_client

        except ConfigException as e:
            raise AuthenticationError(
                f"Failed to load kubeconfig from {kubeconfig_path}",
                f"Kubernetes config error: {str(e)}"
            ) from e
        except Exception as e:
            raise AuthenticationError(
                "Unexpected error loading kubeconfig",
                f"Error: {type(e).__name__}: {str(e)}"
            ) from e

    def _get_kubeconfig_path(self) -> str | None:
        """Determine the kubeconfig file path to use.

        Checks in order:
        1. AuthConfig.kubeconfig_path (explicit configuration)
        2. KUBECONFIG environment variable
        3. Default ~/.kube/config

        Returns:
            Path to kubeconfig file, or None if not found
        """
        # 1. Check explicit configuration
        if self.config.kubeconfig_path:
            return self.config.kubeconfig_path

        # 2. Check KUBECONFIG environment variable
        kubeconfig_env = os.getenv("KUBECONFIG")
        if kubeconfig_env:
            # KUBECONFIG can contain multiple paths separated by ':'
            # Take the first one
            paths = kubeconfig_env.split(os.pathsep)
            if paths:
                return paths[0]

        # 3. Check default location
        default_path = Path.home() / ".kube" / "config"
        if default_path.exists():
            return str(default_path)

        return None

    def get_description(self) -> str:
        """Get description of this strategy.

        Returns:
            Human-readable description
        """
        kubeconfig_path = self._get_kubeconfig_path()
        if kubeconfig_path:
            return f"Kubernetes KubeConfig ({kubeconfig_path})"
        return "Kubernetes KubeConfig (not found)"
