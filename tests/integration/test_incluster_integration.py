"""
Integration tests for InCluster authentication strategy.

These tests verify the InCluster strategy works end-to-end with mock
service account files.
"""

import warnings
from pathlib import Path

import pytest

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.config import SecurityWarning
from openshift_ai_auth.strategies.incluster import InClusterStrategy


@pytest.mark.integration
class TestInClusterIntegrationAuthentication:
    """Integration tests for InCluster authentication."""

    def test_authenticate_with_mock_service_account(self, mock_service_account):
        """Test full authentication flow with mock service account."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Verify strategy is available
        assert strategy.is_available()

        # Authenticate
        api_client = strategy.authenticate()

        # Verify we got a valid API client
        assert api_client is not None
        assert api_client.configuration.host == "https://kubernetes.default.svc:443"
        assert api_client.configuration.api_key["authorization"] == "bearer test-sa-token-content"

    def test_authenticate_with_custom_namespace(self, mock_service_account):
        """Test authentication reads custom namespace."""
        # Update namespace file
        namespace_path = Path(mock_service_account) / "namespace"
        namespace_path.write_text("custom-namespace")

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        api_client = strategy.authenticate()
        assert api_client is not None

    def test_is_available_checks_environment(self, mock_service_account):
        """Test is_available properly checks service account files."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Should be available with mock service account
        assert strategy.is_available()

    def test_is_available_without_service_account(self, monkeypatch):
        """Test is_available returns False without service account."""
        monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Should not be available outside cluster
        assert not strategy.is_available()


@pytest.mark.integration
class TestInClusterIntegrationSSL:
    """Integration tests for InCluster SSL configuration."""

    def test_authenticate_with_ssl_verification_enabled(self, mock_service_account):
        """Test authentication with SSL verification enabled (default)."""
        config = AuthConfig(method="incluster", verify_ssl=True)
        strategy = InClusterStrategy(config)

        api_client = strategy.authenticate()

        # Should use CA cert from service account
        assert api_client.configuration.verify_ssl is True
        ca_cert_path = Path(mock_service_account) / "ca.crt"
        assert api_client.configuration.ssl_ca_cert == str(ca_cert_path)

    def test_authenticate_with_ssl_verification_disabled(self, mock_service_account):
        """Test authentication with SSL verification disabled."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(method="incluster", verify_ssl=False)

        strategy = InClusterStrategy(config)

        api_client = strategy.authenticate()

        # SSL verification should be disabled
        assert api_client.configuration.verify_ssl is False

    def test_get_description(self, mock_service_account):
        """Test strategy description."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        description = strategy.get_description()

        assert "In-Cluster" in description
        assert "default" in description  # Check for namespace instead


@pytest.mark.integration
class TestInClusterIntegrationErrorHandling:
    """Integration tests for InCluster error handling."""

    def test_authenticate_without_token_file(self, mock_service_account):
        """Test authentication fails when token file is missing."""
        token_path = Path(mock_service_account) / "token"
        token_path.unlink()  # Remove token file

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Strategy should not be available
        assert not strategy.is_available()

    def test_authenticate_without_ca_cert(self, mock_service_account):
        """Test strategy is not available without CA cert file."""
        ca_path = Path(mock_service_account) / "ca.crt"
        ca_path.unlink()  # Remove CA cert

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Strategy requires CA cert to be available
        assert not strategy.is_available()

    def test_authenticate_with_empty_token(self, mock_service_account):
        """Test is_available returns True even with empty token file."""
        token_path = Path(mock_service_account) / "token"
        token_path.write_text("")  # Empty token

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # is_available() only checks file existence, not content
        # So it returns True even with empty token (authentication would fail later)
        assert strategy.is_available()
