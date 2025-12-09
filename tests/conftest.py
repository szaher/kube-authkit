"""
Shared pytest fixtures for testing.

This module provides reusable fixtures for mocking Kubernetes
environments, kubeconfig files, and service account tokens.
"""

import os
from pathlib import Path
from typing import Generator

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

    Creates the standard Kubernetes service account directory structure:
    - /var/run/secrets/kubernetes.io/serviceaccount/token
    - /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    - /var/run/secrets/kubernetes.io/serviceaccount/namespace

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
    token_path.write_text("eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.test-service-account-token")

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
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

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
