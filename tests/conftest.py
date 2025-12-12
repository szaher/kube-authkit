"""
Shared pytest fixtures for testing.

This module provides reusable fixtures for mocking Kubernetes
environments, kubeconfig files, and service account tokens.
"""

from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def mock_kubeconfig(tmp_path: Path) -> Path:
    """Create a mock kubeconfig file.

    Args:
        tmp_path: pytest temporary directory

    Returns:
        Path to the temporary kubeconfig file

    Example:
        >>> def test_kubeconfig(mock_kubeconfig):
        ...     assert mock_kubeconfig.exists()
    """
    kubeconfig_content = """
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
    server: https://127.0.0.1:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token-12345
"""
    kubeconfig_path = tmp_path / "config"
    kubeconfig_path.write_text(kubeconfig_content)
    return kubeconfig_path


@pytest.fixture
def mock_service_account(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create mock service account files for in-cluster authentication.

    Creates the standard Kubernetes service account directory structure and patches
    the hardcoded paths in InClusterStrategy to use the mock files.

    Args:
        tmp_path: pytest temporary directory
        monkeypatch: pytest monkeypatch fixture

    Returns:
        Path to the mock service account directory

    Example:
        >>> def test_incluster(mock_service_account):
        ...     token_path = mock_service_account / "token"
        ...     assert token_path.exists()
    """
    # Create service account directory structure
    sa_path = tmp_path / "var" / "run" / "secrets" / "kubernetes.io" / "serviceaccount"
    sa_path.mkdir(parents=True)

    # Create token file
    token_path = sa_path / "token"
    token_path.write_text("test-sa-token-content")

    # Create CA certificate file
    ca_path = sa_path / "ca.crt"
    ca_cert_content = """-----BEGIN CERTIFICATE-----
MIICyDCCAbCgAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwprdWJl
cm5ldGVzMB4XDTE5MDEwMTAwMDAwMFoXDTI5MDEwMTAwMDAwMFowFTETMBEGA1UE
AxMKa3ViZXJuZXRlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMGv
test-certificate-data
-----END CERTIFICATE-----"""
    ca_path.write_text(ca_cert_content)

    # Create namespace file
    namespace_path = sa_path / "namespace"
    namespace_path.write_text("default")

    # Set environment variable for Kubernetes service
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    # Patch the hardcoded paths in InClusterStrategy to use our mock files
    monkeypatch.setattr("openshift_ai_auth.strategies.incluster.TOKEN_PATH", token_path)
    monkeypatch.setattr("openshift_ai_auth.strategies.incluster.CA_CERT_PATH", ca_path)
    monkeypatch.setattr("openshift_ai_auth.strategies.incluster.NAMESPACE_PATH", namespace_path)

    # Also patch the kubernetes library's hardcoded paths
    monkeypatch.setattr("kubernetes.config.incluster_config.SERVICE_TOKEN_FILENAME", str(token_path))
    monkeypatch.setattr("kubernetes.config.incluster_config.SERVICE_CERT_FILENAME", str(ca_path))

    return sa_path


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Clear all authentication-related environment variables.

    This ensures tests start with a clean slate and don't inherit
    environment variables from the test runner's environment.

    Args:
        monkeypatch: pytest monkeypatch fixture

    Example:
        >>> def test_no_env(mock_env_vars):
        ...     assert os.getenv("KUBECONFIG") is None
    """
    # Clear all relevant environment variables
    env_vars = [
        "KUBECONFIG",
        "KUBERNETES_SERVICE_HOST",
        "KUBERNETES_SERVICE_PORT",
        "OIDC_ISSUER",
        "OIDC_CLIENT_ID",
        "OIDC_CLIENT_SECRET",
        "K8S_API_HOST",
        "OPENSHIFT_TOKEN",
    ]

    for var in env_vars:
        monkeypatch.delenv(var, raising=False)

    yield


@pytest.fixture
def mock_oidc_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up OIDC environment variables.

    Args:
        monkeypatch: pytest monkeypatch fixture

    Example:
        >>> def test_oidc_env(mock_oidc_env):
        ...     assert os.getenv("OIDC_ISSUER") is not None
    """
    monkeypatch.setenv("OIDC_ISSUER", "https://keycloak.example.com/auth/realms/test")
    monkeypatch.setenv("OIDC_CLIENT_ID", "test-client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-secret")


# Integration testing fixtures

@pytest.fixture(scope="session")
def mock_oauth_server():
    """Create and start a mock OAuth server for integration tests.

    This fixture starts a mock OAuth/OIDC server that implements:
    - OIDC discovery
    - Authorization Code Flow with PKCE
    - Device Code Flow
    - Token refresh

    The server runs on localhost:9999 and auto-approves all requests.

    Example:
        >>> @pytest.mark.integration
        >>> def test_with_mock_server(mock_oauth_server):
        ...     config = AuthConfig(
        ...         method="oidc",
        ...         oidc_issuer=mock_oauth_server.base_url,
        ...         client_id="test-client"
        ...     )
    """
    from .mock_oauth_server import MockOAuthServer

    server = MockOAuthServer(host="localhost", port=9999)
    server.auto_approve = True
    server.start()

    yield server

    server.stop()


@pytest.fixture
def oauth_config(mock_oauth_server):
    """Get configuration for mock OAuth server.

    Args:
        mock_oauth_server: Mock OAuth server fixture

    Returns:
        Dictionary with OAuth server configuration

    Example:
        >>> def test_oauth(oauth_config):
        ...     assert oauth_config["issuer"] == "http://localhost:9999"
    """
    return {
        "issuer": mock_oauth_server.base_url,
        "client_id": mock_oauth_server.client_id,
        "client_secret": mock_oauth_server.client_secret,
        "token_endpoint": f"{mock_oauth_server.base_url}/token",
        "auth_endpoint": f"{mock_oauth_server.base_url}/authorize",
        "device_endpoint": f"{mock_oauth_server.base_url}/device/code",
    }


# Pytest markers for different test levels
def pytest_configure(config):
    """Register custom pytest markers."""
    config.addinivalue_line(
        "markers", "unit: Unit tests that don't require external services"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests that use mock servers"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end tests that require real external services"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take longer to run"
    )
