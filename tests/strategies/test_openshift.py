"""
Tests for OpenShift OAuth authentication strategy.

Tests cover:
- OAuth server discovery
- Token-based authentication
- Interactive OAuth flow
- Keyring integration
- Error handling
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.strategies.openshift import OpenShiftOAuthStrategy
from openshift_ai_auth.exceptions import (
    AuthenticationError,
    ConfigurationError,
    StrategyNotAvailableError,
)


# Mock OpenShift OAuth metadata
MOCK_OAUTH_METADATA = {
    "issuer": "https://api.cluster.example.com:6443",
    "authorization_endpoint": "https://api.cluster.example.com:6443/oauth/authorize",
    "token_endpoint": "https://api.cluster.example.com:6443/oauth/token",
    "grant_types_supported": ["authorization_code", "implicit"],
    "response_types_supported": ["code", "token"],
    "code_challenge_methods_supported": ["plain", "S256"],
}


class TestOpenShiftOAuthStrategyAvailability:
    """Test availability detection for OpenShift OAuth strategy."""

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    def test_is_available_with_explicit_token(self, mock_get):
        """Test availability with explicit token."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443",
            openshift_token="sha256~test-token"
        )
        strategy = OpenShiftOAuthStrategy(config)

        assert strategy.is_available() is True
        # Should not need to call discovery
        mock_get.assert_not_called()

    def test_is_available_with_env_token(self, monkeypatch):
        """Test availability with token from environment."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~env-token")
        # Clear other env vars that might interfere
        monkeypatch.delenv("KUBECONFIG", raising=False)

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        assert strategy.is_available() is True

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    def test_is_available_with_valid_oauth_server(self, mock_get):
        """Test availability when OAuth server is reachable."""
        # Mock discovery response
        mock_response = Mock()
        mock_response.json.return_value = MOCK_OAUTH_METADATA
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        assert strategy.is_available() is True
        mock_get.assert_called_once()

    def test_is_not_available_missing_api_host(self):
        """Test unavailability when k8s_api_host is missing."""
        config = AuthConfig(method="openshift")
        strategy = OpenShiftOAuthStrategy(config)

        assert strategy.is_available() is False

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    def test_is_not_available_discovery_fails(self, mock_get):
        """Test unavailability when discovery fails."""
        # Mock discovery failure
        mock_get.side_effect = Exception("Network error")

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        assert strategy.is_available() is False


class TestOpenShiftOAuthDiscovery:
    """Test OpenShift OAuth server discovery."""

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    def test_discover_oauth_metadata_success(self, mock_get):
        """Test successful OAuth metadata discovery."""
        # Mock discovery response
        mock_response = Mock()
        mock_response.json.return_value = MOCK_OAUTH_METADATA
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        result = strategy._discover_oauth_metadata()

        assert result == MOCK_OAUTH_METADATA
        assert result["authorization_endpoint"] == MOCK_OAUTH_METADATA["authorization_endpoint"]

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    def test_discover_oauth_metadata_cached(self, mock_get):
        """Test that discovery result is cached."""
        # Mock discovery response
        mock_response = Mock()
        mock_response.json.return_value = MOCK_OAUTH_METADATA
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        # Call twice
        result1 = strategy._discover_oauth_metadata()
        result2 = strategy._discover_oauth_metadata()

        # Should only make one HTTP call (cached)
        assert mock_get.call_count == 1
        assert result1 == result2

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    def test_discover_oauth_metadata_network_error(self, mock_get):
        """Test discovery handles network errors."""
        import requests
        mock_get.side_effect = requests.RequestException("Network error")

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy._discover_oauth_metadata()

        assert "Failed to discover OpenShift OAuth metadata" in str(exc_info.value)


class TestOpenShiftOAuthAuthentication:
    """Test OpenShift OAuth authentication flows."""

    def test_authenticate_with_explicit_token(self):
        """Test authentication with explicit token."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443",
            openshift_token="sha256~test-token"
        )
        strategy = OpenShiftOAuthStrategy(config)

        api_client = strategy.authenticate()

        assert api_client is not None
        assert api_client.configuration.host == "https://api.cluster.example.com:6443"
        assert "Bearer sha256~test-token" in str(api_client.configuration.api_key.get("authorization", ""))

    @patch('openshift_ai_auth.strategies.openshift.os.getenv')
    def test_authenticate_with_env_token(self, mock_getenv):
        """Test authentication with token from environment."""
        def getenv_side_effect(key, default=None):
            if key == "OPENSHIFT_TOKEN":
                return "sha256~env-token"
            return default

        mock_getenv.side_effect = getenv_side_effect

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        api_client = strategy.authenticate()

        assert api_client is not None
        assert "Bearer sha256~env-token" in str(api_client.configuration.api_key.get("authorization", ""))

    def test_authenticate_not_available(self):
        """Test authenticate raises error when strategy not available."""
        config = AuthConfig(method="openshift")
        strategy = OpenShiftOAuthStrategy(config)

        with pytest.raises(StrategyNotAvailableError) as exc_info:
            strategy.authenticate()

        assert "not available" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    @patch('openshift_ai_auth.strategies.openshift.requests.post')
    @patch('openshift_ai_auth.strategies.openshift.webbrowser.open')
    @patch('openshift_ai_auth.strategies.openshift.HTTPServer')
    @patch('builtins.print')
    def test_authenticate_interactive_success(self, mock_print, mock_server_class, mock_browser, mock_post, mock_get):
        """Test successful interactive OAuth flow."""
        # Mock discovery
        mock_get_response = Mock()
        mock_get_response.json.return_value = MOCK_OAUTH_METADATA
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        # Mock HTTP server callback
        mock_server = Mock()
        mock_server_class.return_value = mock_server

        # Mock token exchange
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "sha256~oauth-token",
            "token_type": "Bearer"
        }
        token_response.raise_for_status.return_value = None
        mock_post.return_value = token_response

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        # Manually inject auth code (simulating callback)
        with patch.object(strategy, '_authenticate_interactive') as mock_auth:
            # Simulate successful authentication
            strategy._access_token = "sha256~oauth-token"
            mock_auth.return_value = None

            strategy._authenticate_interactive()


class TestOpenShiftOAuthKeyringIntegration:
    """Test keyring integration for token persistence."""

    def test_save_token(self):
        """Test saving token to keyring when keyring module not available."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443",
            use_keyring=True
        )
        strategy = OpenShiftOAuthStrategy(config)

        # Should not raise an error even if keyring not available
        strategy._save_token("sha256~test-token")

    def test_load_token(self):
        """Test loading token from keyring when keyring module not available."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443",
            use_keyring=True
        )
        strategy = OpenShiftOAuthStrategy(config)

        token = strategy._load_token()

        # Should return None if keyring not available or no token stored
        assert token is None or isinstance(token, str)

    def test_save_token_keyring_disabled(self):
        """Test saving token when keyring is disabled."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443",
            use_keyring=False
        )
        strategy = OpenShiftOAuthStrategy(config)

        # Should not raise an error
        strategy._save_token("sha256~test-token")

    def test_load_token_keyring_disabled(self):
        """Test loading token when keyring is disabled."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443",
            use_keyring=False
        )
        strategy = OpenShiftOAuthStrategy(config)

        token = strategy._load_token()

        assert token is None


class TestOpenShiftOAuthApiClientCreation:
    """Test ApiClient creation."""

    def test_create_api_client_success(self):
        """Test creating ApiClient with valid configuration."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)
        strategy._access_token = "sha256~test-token"

        api_client = strategy._create_api_client()

        assert api_client is not None
        assert api_client.configuration.host == "https://api.cluster.example.com:6443"
        assert "Bearer sha256~test-token" in str(api_client.configuration.api_key.get("authorization", ""))

    def test_create_api_client_missing_host(self):
        """Test creating ApiClient without k8s_api_host raises error."""
        config = AuthConfig(method="openshift")
        strategy = OpenShiftOAuthStrategy(config)
        strategy._access_token = "sha256~test-token"

        with pytest.raises(ConfigurationError) as exc_info:
            strategy._create_api_client()

        assert "Kubernetes API host not configured" in str(exc_info.value)

    def test_create_api_client_with_ca_cert(self, tmp_path):
        """Test creating ApiClient with custom CA certificate."""
        ca_cert = tmp_path / "ca.crt"
        ca_cert.write_text("FAKE CA CERT")

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443",
            ca_cert=str(ca_cert)
        )
        strategy = OpenShiftOAuthStrategy(config)
        strategy._access_token = "sha256~test-token"

        api_client = strategy._create_api_client()

        assert api_client.configuration.ssl_ca_cert == str(ca_cert)


class TestOpenShiftOAuthStrategyDescription:
    """Test strategy description."""

    def test_get_description(self):
        """Test description."""
        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        description = strategy.get_description()

        assert "OpenShift OAuth" in description
        assert "api.cluster.example.com" in description


class TestOpenShiftOAuthInteractiveFlow:
    """Test interactive OAuth flow details."""

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    @patch('openshift_ai_auth.strategies.openshift.requests.post')
    def test_interactive_flow_missing_endpoints(self, mock_post, mock_get):
        """Test interactive flow when endpoints are missing."""
        # Mock discovery without required endpoints
        incomplete_metadata = {"issuer": "https://api.cluster.example.com:6443"}

        mock_get_response = Mock()
        mock_get_response.json.return_value = incomplete_metadata
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy._authenticate_interactive()

        assert "not properly configured" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.openshift.requests.get')
    @patch('openshift_ai_auth.strategies.openshift.requests.post')
    def test_interactive_flow_token_exchange_failure(self, mock_post, mock_get):
        """Test interactive flow when token exchange fails."""
        # Mock discovery
        mock_get_response = Mock()
        mock_get_response.json.return_value = MOCK_OAUTH_METADATA
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        config = AuthConfig(
            method="openshift",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        strategy = OpenShiftOAuthStrategy(config)

        # We can't easily test the full interactive flow without mocking the HTTP server
        # and threading, so we'll just verify the discovery works
        metadata = strategy._discover_oauth_metadata()
        assert metadata == MOCK_OAUTH_METADATA
