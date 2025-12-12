"""
Configuration dataclass for authentication.

This module provides the AuthConfig dataclass that centralizes all
authentication configuration options.
"""

import os
import warnings
from dataclasses import dataclass, field

from .exceptions import ConfigurationError


@dataclass
class AuthConfig:
    """Configuration for Kubernetes/OpenShift authentication.

    This dataclass holds all configuration options for authenticating to
    a Kubernetes or OpenShift cluster. It supports multiple authentication
    methods and can be configured explicitly or through environment variables.

    Args:
        method: Authentication method to use. Options:
            - "auto": Auto-detect best method (default)
            - "kubeconfig": Use ~/.kube/config or KUBECONFIG
            - "incluster": Use in-cluster service account
            - "oidc": Use OpenID Connect
            - "openshift": Use OpenShift OAuth
        k8s_api_host: Kubernetes API server URL (auto-detected if None)
        oidc_issuer: OIDC issuer URL (required for OIDC)
        client_id: OIDC client ID (required for OIDC)
        client_secret: OIDC client secret (for confidential clients)
        openshift_token: OpenShift OAuth token (for OpenShift method)
        scopes: OIDC scopes to request
        use_device_flow: Use Device Code Flow instead of Authorization Code
        use_keyring: Store refresh tokens in system keyring
        oidc_callback_port: Port for OAuth callback server (default: 8080)
        ca_cert: Path to custom CA certificate bundle
        verify_ssl: Verify SSL certificates (WARNING: only disable for development)
        kubeconfig_path: Path to kubeconfig file (overrides KUBECONFIG env var)

    Example:
        >>> # Auto-detection (simplest)
        >>> config = AuthConfig()
        >>>
        >>> # Explicit OIDC with device flow
        >>> config = AuthConfig(
        ...     method="oidc",
        ...     oidc_issuer="https://keycloak.example.com/auth/realms/myrealm",
        ...     client_id="my-client",
        ...     use_device_flow=True
        ... )
    """

    method: str = "auto"
    k8s_api_host: str | None = None
    oidc_issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    openshift_token: str | None = None
    scopes: list[str] = field(default_factory=lambda: ["openid"])
    use_device_flow: bool = False
    use_keyring: bool = False
    oidc_callback_port: int = 8080
    ca_cert: str | None = None
    verify_ssl: bool = True
    kubeconfig_path: str | None = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization.

        This method is automatically called after __init__ to:
        1. Load configuration from environment variables if not explicitly set
        2. Validate that required parameters are present for the chosen method
        3. Emit security warnings for dangerous configurations

        Raises:
            ConfigurationError: If configuration is invalid or incomplete
        """
        # Load from environment variables if not explicitly set
        self._load_from_environment()

        # Normalize method name
        self.method = self.method.lower()

        # Validate method is known
        valid_methods = {"auto", "kubeconfig", "incluster", "oidc", "openshift"}
        if self.method not in valid_methods:
            raise ConfigurationError(
                f"Invalid authentication method: {self.method}",
                f"Valid methods are: {', '.join(sorted(valid_methods))}"
            )

        # Validate OIDC-specific configuration
        if self.method == "oidc":
            if not self.oidc_issuer:
                raise ConfigurationError(
                    "OIDC authentication requires 'oidc_issuer' parameter",
                    "Provide oidc_issuer or set OIDC_ISSUER environment variable"
                )
            if not self.client_id:
                raise ConfigurationError(
                    "OIDC authentication requires 'client_id' parameter",
                    "Provide client_id or set OIDC_CLIENT_ID environment variable"
                )
            # Validate issuer URL format
            if not self.oidc_issuer.startswith(("https://", "http://")):
                raise ConfigurationError(
                    f"OIDC issuer must be a valid URL: {self.oidc_issuer}",
                    "issuer should start with https:// (or http:// for local development)"
                )
            # Warn about http:// (insecure)
            if self.oidc_issuer.startswith("http://"):
                warnings.warn(
                    f"OIDC issuer uses insecure http:// protocol: {self.oidc_issuer}. "
                    "This should only be used for local development.",
                    SecurityWarning,
                    stacklevel=2
                )

        # Security warning for disabled SSL verification
        if not self.verify_ssl:
            warnings.warn(
                "TLS/SSL verification is disabled (verify_ssl=False). "
                "This is insecure and should only be used in development environments. "
                "Your credentials and data may be exposed to man-in-the-middle attacks.",
                SecurityWarning,
                stacklevel=2
            )

        # Validate CA cert path if provided
        if self.ca_cert and not os.path.exists(self.ca_cert):
            raise ConfigurationError(
                f"CA certificate file not found: {self.ca_cert}",
                "Provide a valid path to a CA certificate bundle"
            )

        # Validate kubeconfig path if provided
        if self.kubeconfig_path and not os.path.exists(self.kubeconfig_path):
            raise ConfigurationError(
                f"Kubeconfig file not found: {self.kubeconfig_path}",
                "Provide a valid path to a kubeconfig file"
            )

    def _load_from_environment(self) -> None:
        """Load configuration from environment variables.

        This method loads configuration from environment variables for
        parameters that were not explicitly set. It allows users to
        configure authentication through environment variables without
        modifying code.

        Environment Variables:
            OIDC_ISSUER: OIDC issuer URL
            OIDC_CLIENT_ID: OIDC client ID
            OIDC_CLIENT_SECRET: OIDC client secret
            OPENSHIFT_TOKEN: OpenShift OAuth token
            KUBECONFIG: Path to kubeconfig file
            K8S_API_HOST: Kubernetes API server URL
        """
        # Load OIDC configuration from environment
        if not self.oidc_issuer:
            self.oidc_issuer = os.getenv("OIDC_ISSUER")

        if not self.client_id:
            self.client_id = os.getenv("OIDC_CLIENT_ID")

        if not self.client_secret:
            self.client_secret = os.getenv("OIDC_CLIENT_SECRET")

        # Load OpenShift token from environment
        if not self.openshift_token:
            self.openshift_token = os.getenv("OPENSHIFT_TOKEN")

        # Load kubeconfig path from environment
        if not self.kubeconfig_path:
            self.kubeconfig_path = os.getenv("KUBECONFIG")

        # Load API host from environment
        if not self.k8s_api_host:
            self.k8s_api_host = os.getenv("K8S_API_HOST")

        # Validate callback port
        if self.oidc_callback_port < 1 or self.oidc_callback_port > 65535:
            raise ConfigurationError(
                f"Invalid OIDC callback port: {self.oidc_callback_port}",
                "Port must be between 1 and 65535"
            )

    def __repr__(self) -> str:
        """Return string representation with sensitive fields redacted.

        This ensures that sensitive information like client_secret is not
        exposed in logs or error messages.

        Returns:
            String representation with secrets redacted
        """
        # Create a copy of the config dict and redact sensitive fields
        config_dict = {
            "method": self.method,
            "k8s_api_host": self.k8s_api_host,
            "oidc_issuer": self.oidc_issuer,
            "client_id": self.client_id,
            "client_secret": "***REDACTED***" if self.client_secret else None,
            "openshift_token": "***REDACTED***" if self.openshift_token else None,
            "scopes": self.scopes,
            "use_device_flow": self.use_device_flow,
            "use_keyring": self.use_keyring,
            "oidc_callback_port": self.oidc_callback_port,
            "ca_cert": self.ca_cert,
            "verify_ssl": self.verify_ssl,
            "kubeconfig_path": self.kubeconfig_path,
        }

        params = ", ".join(f"{k}={v!r}" for k, v in config_dict.items() if v is not None)
        return f"AuthConfig({params})"

    @classmethod
    def from_dict(cls, config_dict: dict) -> "AuthConfig":
        """Create AuthConfig from dictionary.

        This is useful for loading configuration from JSON or YAML files.

        Args:
            config_dict: Dictionary containing configuration parameters

        Returns:
            AuthConfig instance

        Example:
            >>> config_data = {
            ...     "method": "oidc",
            ...     "oidc_issuer": "https://keycloak.example.com",
            ...     "client_id": "my-client"
            ... }
            >>> config = AuthConfig.from_dict(config_data)
        """
        # Filter out unknown keys to avoid TypeError
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_dict = {k: v for k, v in config_dict.items() if k in valid_fields}
        return cls(**filtered_dict)


class SecurityWarning(UserWarning):
    """Warning category for security-related issues.

    This custom warning category allows users to filter security warnings
    separately from other warnings if desired.
    """
    pass
