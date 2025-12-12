"""
In-cluster authentication strategy.

This strategy uses the service account token automatically mounted into
Kubernetes pods. This is the standard authentication method for applications
running inside a Kubernetes cluster (including OpenShift notebooks).
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


# Standard paths for in-cluster service account credentials
SERVICE_ACCOUNT_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount")
TOKEN_PATH = SERVICE_ACCOUNT_PATH / "token"
CA_CERT_PATH = SERVICE_ACCOUNT_PATH / "ca.crt"
NAMESPACE_PATH = SERVICE_ACCOUNT_PATH / "namespace"


class InClusterStrategy(AuthStrategy):
    """Authenticate using in-cluster service account.

    This strategy is used when running inside a Kubernetes Pod. Kubernetes
    automatically mounts a service account token and CA certificate into
    every pod at a well-known location.

    The strategy checks for:
    - Service account token: /var/run/secrets/kubernetes.io/serviceaccount/token
    - CA certificate: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    - KUBERNETES_SERVICE_HOST environment variable (set by Kubernetes)

    Example:
        >>> # Inside a Kubernetes Pod
        >>> config = AuthConfig(method="incluster")
        >>> strategy = InClusterStrategy(config)
        >>> api_client = strategy.authenticate()
    """

    def is_available(self) -> bool:
        """Check if running inside a Kubernetes cluster.

        Returns:
            True if in-cluster credentials are available, False otherwise
        """
        # Check for Kubernetes environment variables
        has_k8s_env = os.getenv("KUBERNETES_SERVICE_HOST") is not None

        # Check for service account token
        has_token = TOKEN_PATH.exists() and TOKEN_PATH.is_file()

        # Check for CA certificate
        has_ca = CA_CERT_PATH.exists() and CA_CERT_PATH.is_file()

        if not has_k8s_env:
            logger.debug("KUBERNETES_SERVICE_HOST environment variable not set")
            return False

        if not has_token:
            logger.debug(f"Service account token not found at {TOKEN_PATH}")
            return False

        if not has_ca:
            logger.debug(f"CA certificate not found at {CA_CERT_PATH}")
            return False

        # Check token is readable
        if not os.access(TOKEN_PATH, os.R_OK):
            logger.warning(f"Service account token is not readable: {TOKEN_PATH}")
            return False

        # Check CA cert is readable
        if not os.access(CA_CERT_PATH, os.R_OK):
            logger.warning(f"CA certificate is not readable: {CA_CERT_PATH}")
            return False

        logger.debug("In-cluster credentials available")
        return True

    def authenticate(self) -> ApiClient:
        """Authenticate using in-cluster service account.

        Returns:
            Configured Kubernetes ApiClient

        Raises:
            StrategyNotAvailableError: If not running in a cluster
            AuthenticationError: If authentication fails
        """
        if not self.is_available():
            raise StrategyNotAvailableError(
                "In-cluster authentication not available",
                "Not running inside a Kubernetes cluster. In-cluster auth requires:\n"
                f"1. KUBERNETES_SERVICE_HOST environment variable\n"
                f"2. Service account token at {TOKEN_PATH}\n"
                f"3. CA certificate at {CA_CERT_PATH}\n\n"
                "This authentication method only works when running inside a Kubernetes Pod."
            )

        logger.info("Authenticating using in-cluster service account")

        try:
            # Load in-cluster config
            # This configures the global kubernetes client with the service account token
            k8s_config.load_incluster_config()

            # Create ApiClient from the loaded configuration
            api_client = client.ApiClient()

            # The CA certificate is automatically used by load_incluster_config,
            # but we can override if a custom CA cert is specified
            if self.config.ca_cert:
                logger.debug(f"Using custom CA certificate: {self.config.ca_cert}")
                api_client.configuration.ssl_ca_cert = self.config.ca_cert

            # Apply SSL verification setting
            # WARNING: Disabling SSL verification in-cluster is especially dangerous
            if not self.config.verify_ssl:
                logger.warning(
                    "SSL verification is disabled for in-cluster authentication. "
                    "This defeats the purpose of the mounted CA certificate and "
                    "exposes you to man-in-the-middle attacks within the cluster."
                )
                api_client.configuration.verify_ssl = False

            # Log the namespace we're running in (if available)
            namespace = self._get_namespace()
            if namespace:
                logger.info(f"Running in namespace: {namespace}")

            logger.info("Successfully authenticated using in-cluster service account")
            return api_client

        except ConfigException as e:
            raise AuthenticationError(
                "Failed to load in-cluster configuration",
                f"Kubernetes config error: {str(e)}\n\n"
                "This may indicate that the service account token or CA certificate "
                "is invalid or corrupted."
            ) from e
        except Exception as e:
            raise AuthenticationError(
                "Unexpected error during in-cluster authentication",
                f"Error: {type(e).__name__}: {str(e)}"
            ) from e

    def _get_namespace(self) -> str | None:
        """Get the namespace this pod is running in.

        Reads the namespace from the service account namespace file.

        Returns:
            Namespace name, or None if not available
        """
        try:
            if NAMESPACE_PATH.exists():
                return NAMESPACE_PATH.read_text().strip()
        except Exception as e:
            logger.debug(f"Could not read namespace file: {e}")

        return None

    def get_description(self) -> str:
        """Get description of this strategy.

        Returns:
            Human-readable description
        """
        namespace = self._get_namespace()
        if namespace:
            return f"In-Cluster Service Account (namespace: {namespace})"
        return "In-Cluster Service Account"
