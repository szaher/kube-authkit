"""
Integration tests for OpenShift OAuth authentication strategy.

These tests verify the OpenShift OAuth strategy works end-to-end with a mock
OAuth server.
"""

import warnings

import pytest

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.config import SecurityWarning
from openshift_ai_auth.exceptions import StrategyNotAvailableError
from openshift_ai_auth.strategies.openshift import OpenShiftOAuthStrategy


@pytest.mark.integration
class TestOpenShiftIntegrationAuthentication:
    """Integration tests for OpenShift OAuth authentication."""

    def test_authenticate_with_explicit_token(self, mock_env_vars):
        """Test authentication with explicitly provided token."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="https://api.openshift.example.com:6443",
                openshift_token="sha256~explicit-test-token",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        # Should be available with explicit token
        assert strategy.is_available()

        # Authenticate
        api_client = strategy.authenticate()

        # Verify we got a valid API client
        assert api_client is not None
        assert api_client.configuration.host == "https://api.openshift.example.com:6443"
        assert "Bearer sha256~explicit-test-token" in str(api_client.configuration.api_key["authorization"])

    def test_authenticate_with_env_token(self, monkeypatch, mock_env_vars):
        """Test authentication with token from environment variable."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~env-test-token")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="https://api.openshift.example.com:6443",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        assert strategy.is_available()

        api_client = strategy.authenticate()
        assert api_client is not None
        assert "Bearer sha256~env-test-token" in str(api_client.configuration.api_key["authorization"])

    def test_oauth_discovery_with_mock_server(self, mock_oauth_server, mock_env_vars):
        """Test OAuth metadata discovery."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host=mock_oauth_server.base_url,
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        # Discover OAuth metadata
        metadata = strategy._discover_oauth_metadata()

        # Verify metadata structure
        assert metadata["issuer"] == mock_oauth_server.base_url
        assert "authorization_endpoint" in metadata
        assert "token_endpoint" in metadata

    def test_is_available_with_token(self, mock_env_vars):
        """Test strategy is available when token is provided."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="https://api.openshift.example.com:6443",
                openshift_token="sha256~test-token",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)
        assert strategy.is_available()

    def test_is_not_available_without_host(self):
        """Test strategy is not available without k8s_api_host."""
        config = AuthConfig(method="openshift")
        strategy = OpenShiftOAuthStrategy(config)

        assert not strategy.is_available()


@pytest.mark.integration
class TestOpenShiftIntegrationOAuthFlow:
    """Integration tests for OpenShift OAuth interactive flow."""

    def test_oauth_server_reachable(self, mock_oauth_server, mock_env_vars):
        """Test that OAuth server is reachable and discoverable."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host=mock_oauth_server.base_url,
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        # Should be able to discover OAuth endpoints
        assert strategy.is_available()

    def test_create_api_client_with_token(self, mock_env_vars):
        """Test creating API client with access token."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="https://api.openshift.example.com:6443",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)
        strategy._access_token = "test-access-token-123"

        api_client = strategy._create_api_client()

        assert api_client is not None
        assert "Bearer test-access-token-123" in str(api_client.configuration.api_key["authorization"])


@pytest.mark.integration
class TestOpenShiftIntegrationErrorHandling:
    """Integration tests for OpenShift error handling."""

    def test_discovery_failure_with_invalid_host(self, mock_env_vars):
        """Test discovery handles invalid OAuth server."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="http://nonexistent-openshift.invalid:6443",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        # Should not be available if discovery fails
        assert not strategy.is_available()

    def test_authenticate_without_token_or_server(self, mock_env_vars):
        """Test authentication fails without token or reachable server."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="http://nonexistent-openshift.invalid:6443",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        with pytest.raises(StrategyNotAvailableError):
            # Should fail because strategy is not available
            strategy.authenticate()

    def test_get_description(self, mock_env_vars):
        """Test strategy description."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="https://api.openshift.example.com:6443",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        description = strategy.get_description()

        assert "OpenShift" in description
        assert "api.openshift.example.com" in description


@pytest.mark.integration
class TestOpenShiftIntegrationSSL:
    """Integration tests for OpenShift SSL configuration."""

    def test_authenticate_with_ssl_verification_disabled(self, mock_env_vars):
        """Test authentication with SSL verification disabled."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="openshift",
                k8s_api_host="https://api.openshift.example.com:6443",
                openshift_token="sha256~test-token",
                verify_ssl=False
            )

        strategy = OpenShiftOAuthStrategy(config)

        api_client = strategy.authenticate()

        assert api_client.configuration.verify_ssl is False
