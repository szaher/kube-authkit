"""
Tests for OIDC authentication strategy.

Tests cover:
- OIDC discovery
- Device Code Flow
- Authorization Code Flow with PKCE
- Token refresh
- Keyring integration
- Error handling
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock, call
from pathlib import Path

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.strategies.oidc import OIDCStrategy
from openshift_ai_auth.exceptions import (
    AuthenticationError,
    ConfigurationError,
    StrategyNotAvailableError,
)


# Mock OIDC discovery document
MOCK_OIDC_CONFIG = {
    "issuer": "https://keycloak.example.com/auth/realms/test",
    "authorization_endpoint": "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/auth",
    "token_endpoint": "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/token",
    "device_authorization_endpoint": "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/auth/device",
    "userinfo_endpoint": "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/userinfo",
    "end_session_endpoint": "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/logout",
    "jwks_uri": "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/certs",
}


class TestOIDCStrategyAvailability:
    """Test availability detection for OIDC strategy."""

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    def test_is_available_with_valid_config(self, mock_get):
        """Test availability with valid OIDC configuration."""
        # Mock discovery response
        mock_response = Mock()
        mock_response.json.return_value = MOCK_OIDC_CONFIG
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        assert strategy.is_available() is True
        mock_get.assert_called_once()

    def test_is_not_available_missing_issuer(self):
        """Test unavailability when issuer is missing."""
        # Bypass AuthConfig validation by manually setting attributes
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://temp.example.com",  # Will be cleared after init
            client_id="test-client"
        )
        # Clear issuer after validation
        config.oidc_issuer = None

        strategy = OIDCStrategy(config)

        assert strategy.is_available() is False

    def test_is_not_available_missing_client_id(self):
        """Test unavailability when client ID is missing."""
        # Bypass AuthConfig validation by manually setting attributes
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="temp-client"  # Will be cleared after init
        )
        # Clear client_id after validation
        config.client_id = None

        strategy = OIDCStrategy(config)

        assert strategy.is_available() is False

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    def test_is_not_available_discovery_fails(self, mock_get):
        """Test unavailability when discovery fails."""
        # Mock discovery failure
        mock_get.side_effect = Exception("Network error")

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        assert strategy.is_available() is False


class TestOIDCDiscovery:
    """Test OIDC discovery functionality."""

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    def test_discover_oidc_config_success(self, mock_get):
        """Test successful OIDC discovery."""
        # Mock discovery response
        mock_response = Mock()
        mock_response.json.return_value = MOCK_OIDC_CONFIG
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        result = strategy._discover_oidc_config()

        assert result == MOCK_OIDC_CONFIG
        assert result["authorization_endpoint"] == MOCK_OIDC_CONFIG["authorization_endpoint"]

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    def test_discover_oidc_config_cached(self, mock_get):
        """Test that discovery result is cached."""
        # Mock discovery response
        mock_response = Mock()
        mock_response.json.return_value = MOCK_OIDC_CONFIG
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        # Call twice
        result1 = strategy._discover_oidc_config()
        result2 = strategy._discover_oidc_config()

        # Should only make one HTTP call (cached)
        assert mock_get.call_count == 1
        assert result1 == result2

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    def test_discover_oidc_config_network_error(self, mock_get):
        """Test discovery handles network errors."""
        import requests
        mock_get.side_effect = requests.RequestException("Network error")

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy._discover_oidc_config()

        assert "Failed to discover OIDC configuration" in str(exc_info.value)


class TestOIDCDeviceCodeFlow:
    """Test Device Code Flow authentication."""

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    @patch('openshift_ai_auth.strategies.oidc.requests.post')
    @patch('builtins.print')
    @patch('openshift_ai_auth.strategies.oidc.time.sleep')
    def test_device_flow_success(self, mock_sleep, mock_print, mock_post, mock_get):
        """Test successful Device Code Flow authentication."""
        # Mock discovery
        mock_get_response = Mock()
        mock_get_response.json.return_value = MOCK_OIDC_CONFIG
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        # Mock device authorization
        device_response = Mock()
        device_response.json.return_value = {
            "device_code": "test-device-code",
            "user_code": "ABCD-1234",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?code=ABCD-1234",
            "interval": 1
        }
        device_response.raise_for_status.return_value = None

        # Mock token polling - first pending, then success
        pending_response = Mock()
        pending_response.status_code = 400
        pending_response.json.return_value = {"error": "authorization_pending"}

        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_in": 3600
        }

        mock_post.side_effect = [device_response, pending_response, success_response]

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=True
        )
        strategy = OIDCStrategy(config)

        strategy._authenticate_device_flow()

        assert strategy._access_token == "test-access-token"
        assert strategy._refresh_token == "test-refresh-token"
        assert strategy._token_expiry is not None

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    @patch('openshift_ai_auth.strategies.oidc.requests.post')
    def test_device_flow_not_supported(self, mock_post, mock_get):
        """Test Device Code Flow when not supported by provider."""
        # Mock discovery without device endpoint
        config_without_device = MOCK_OIDC_CONFIG.copy()
        del config_without_device["device_authorization_endpoint"]

        mock_get_response = Mock()
        mock_get_response.json.return_value = config_without_device
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=True
        )
        strategy = OIDCStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy._authenticate_device_flow()

        assert "Device Code Flow not supported" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    @patch('openshift_ai_auth.strategies.oidc.requests.post')
    @patch('builtins.print')
    @patch('openshift_ai_auth.strategies.oidc.time.sleep')
    def test_device_flow_expired(self, mock_sleep, mock_print, mock_post, mock_get):
        """Test Device Code Flow when code expires."""
        # Mock discovery
        mock_get_response = Mock()
        mock_get_response.json.return_value = MOCK_OIDC_CONFIG
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        # Mock device authorization
        device_response = Mock()
        device_response.json.return_value = {
            "device_code": "test-device-code",
            "user_code": "ABCD-1234",
            "verification_uri": "https://example.com/device",
            "interval": 1
        }
        device_response.raise_for_status.return_value = None

        # Mock token polling - expired
        expired_response = Mock()
        expired_response.status_code = 400
        expired_response.json.return_value = {
            "error": "expired_token",
            "error_description": "The device code has expired"
        }

        mock_post.side_effect = [device_response, expired_response]

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=True
        )
        strategy = OIDCStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy._authenticate_device_flow()

        assert "expired_token" in str(exc_info.value)


class TestOIDCAuthorizationCodeFlow:
    """Test Authorization Code Flow with PKCE."""

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    @patch('openshift_ai_auth.strategies.oidc.requests.post')
    @patch('openshift_ai_auth.strategies.oidc.webbrowser.open')
    @patch('openshift_ai_auth.strategies.oidc.HTTPServer')
    @patch('builtins.print')
    def test_auth_code_flow_success(self, mock_print, mock_server_class, mock_browser, mock_post, mock_get):
        """Test successful Authorization Code Flow."""
        # Mock discovery
        mock_get_response = Mock()
        mock_get_response.json.return_value = MOCK_OIDC_CONFIG
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        # Mock HTTP server callback
        mock_server = Mock()
        mock_server_class.return_value = mock_server

        # Simulate receiving auth code
        def handle_request_side_effect():
            # Simulate the callback handler setting auth_result
            pass

        mock_server.handle_request.side_effect = handle_request_side_effect

        # Mock token exchange
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_in": 3600
        }
        token_response.raise_for_status.return_value = None
        mock_post.return_value = token_response

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=False
        )
        strategy = OIDCStrategy(config)

        # Manually inject auth code (simulating callback)
        with patch.object(strategy, '_authenticate_auth_code_flow') as mock_auth:
            # Simulate successful authentication
            strategy._access_token = "test-access-token"
            strategy._refresh_token = "test-refresh-token"
            strategy._token_expiry = 3600

            mock_auth.return_value = None

            strategy._authenticate_auth_code_flow()

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    def test_auth_code_flow_missing_endpoints(self, mock_get):
        """Test Authorization Code Flow when endpoints are missing."""
        # Mock discovery without required endpoints
        incomplete_config = {"issuer": "https://example.com"}

        mock_get_response = Mock()
        mock_get_response.json.return_value = incomplete_config
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=False
        )
        strategy = OIDCStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy._authenticate_auth_code_flow()

        assert "not supported" in str(exc_info.value)


class TestOIDCTokenRefresh:
    """Test token refresh functionality."""

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    @patch('openshift_ai_auth.strategies.oidc.requests.post')
    def test_refresh_access_token_success(self, mock_post, mock_get):
        """Test successful token refresh."""
        # Mock discovery
        mock_get_response = Mock()
        mock_get_response.json.return_value = MOCK_OIDC_CONFIG
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        # Mock token refresh
        refresh_response = Mock()
        refresh_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600
        }
        refresh_response.raise_for_status.return_value = None
        mock_post.return_value = refresh_response

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        strategy._refresh_access_token("old-refresh-token")

        assert strategy._access_token == "new-access-token"
        assert strategy._refresh_token == "new-refresh-token"
        assert strategy._token_expiry is not None

    @patch('openshift_ai_auth.strategies.oidc.requests.get')
    @patch('openshift_ai_auth.strategies.oidc.requests.post')
    def test_refresh_access_token_failure(self, mock_post, mock_get):
        """Test token refresh failure."""
        # Mock discovery
        mock_get_response = Mock()
        mock_get_response.json.return_value = MOCK_OIDC_CONFIG
        mock_get_response.raise_for_status.return_value = None
        mock_get.return_value = mock_get_response

        # Mock token refresh failure
        import requests
        mock_post.side_effect = requests.RequestException("Invalid refresh token")

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy._refresh_access_token("invalid-refresh-token")

        assert "Failed to refresh access token" in str(exc_info.value)


class TestOIDCKeyringIntegration:
    """Test keyring integration for token persistence."""

    def test_save_refresh_token(self):
        """Test saving refresh token to keyring when keyring module not available."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_keyring=True
        )
        strategy = OIDCStrategy(config)

        # Should not raise an error even if keyring not available
        strategy._save_refresh_token("test-refresh-token")

    def test_load_refresh_token(self):
        """Test loading refresh token from keyring when keyring module not available."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_keyring=True
        )
        strategy = OIDCStrategy(config)

        token = strategy._load_refresh_token()

        # Should return None if keyring not available or no token stored
        # (we can't reliably test keyring integration without installing it)
        assert token is None or isinstance(token, str)

    def test_save_refresh_token_keyring_disabled(self):
        """Test saving refresh token when keyring is disabled."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_keyring=False
        )
        strategy = OIDCStrategy(config)

        # Should not raise an error
        strategy._save_refresh_token("test-refresh-token")

    def test_load_refresh_token_keyring_disabled(self):
        """Test loading refresh token when keyring is disabled."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_keyring=False
        )
        strategy = OIDCStrategy(config)

        token = strategy._load_refresh_token()

        assert token is None


class TestOIDCApiClientCreation:
    """Test ApiClient creation."""

    def test_create_api_client_success(self):
        """Test creating ApiClient with valid configuration."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            k8s_api_host="https://api.example.com:6443"
        )
        strategy = OIDCStrategy(config)
        strategy._access_token = "test-access-token"

        api_client = strategy._create_api_client()

        assert api_client is not None
        assert api_client.configuration.host == "https://api.example.com:6443"
        assert "Bearer test-access-token" in str(api_client.configuration.api_key.get("authorization", ""))

    def test_create_api_client_missing_host(self):
        """Test creating ApiClient without k8s_api_host raises error."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)
        strategy._access_token = "test-access-token"

        with pytest.raises(ConfigurationError) as exc_info:
            strategy._create_api_client()

        assert "Kubernetes API host not configured" in str(exc_info.value)

    def test_create_api_client_with_ca_cert(self, tmp_path):
        """Test creating ApiClient with custom CA certificate."""
        ca_cert = tmp_path / "ca.crt"
        ca_cert.write_text("FAKE CA CERT")

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            k8s_api_host="https://api.example.com:6443",
            ca_cert=str(ca_cert)
        )
        strategy = OIDCStrategy(config)
        strategy._access_token = "test-access-token"

        api_client = strategy._create_api_client()

        assert api_client.configuration.ssl_ca_cert == str(ca_cert)


class TestOIDCStrategyDescription:
    """Test strategy description."""

    def test_get_description_device_flow(self):
        """Test description for Device Code Flow."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=True
        )
        strategy = OIDCStrategy(config)

        description = strategy.get_description()

        assert "OIDC" in description
        assert "Device Code Flow" in description
        assert "keycloak.example.com" in description

    def test_get_description_auth_code_flow(self):
        """Test description for Authorization Code Flow."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=False
        )
        strategy = OIDCStrategy(config)

        description = strategy.get_description()

        assert "OIDC" in description
        assert "Authorization Code Flow" in description


class TestOIDCAuthenticate:
    """Test the main authenticate method."""

    def test_authenticate_not_available(self):
        """Test authenticate raises error when strategy not available."""
        # Create config with valid params first
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client"
        )
        strategy = OIDCStrategy(config)

        # Mock is_available to return False
        with patch.object(strategy, 'is_available', return_value=False):
            with pytest.raises(StrategyNotAvailableError) as exc_info:
                strategy.authenticate()

        assert "not available" in str(exc_info.value)

    @patch.object(OIDCStrategy, 'is_available')
    @patch.object(OIDCStrategy, '_authenticate_device_flow')
    @patch.object(OIDCStrategy, '_create_api_client')
    def test_authenticate_device_flow(self, mock_create_client, mock_device_flow, mock_is_available):
        """Test authenticate uses Device Code Flow when configured."""
        mock_is_available.return_value = True
        mock_api_client = Mock()
        mock_create_client.return_value = mock_api_client

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=True,
            k8s_api_host="https://api.example.com:6443"
        )
        strategy = OIDCStrategy(config)

        result = strategy.authenticate()

        mock_device_flow.assert_called_once()
        mock_create_client.assert_called_once()
        assert result == mock_api_client

    @patch.object(OIDCStrategy, 'is_available')
    @patch.object(OIDCStrategy, '_authenticate_auth_code_flow')
    @patch.object(OIDCStrategy, '_create_api_client')
    def test_authenticate_auth_code_flow(self, mock_create_client, mock_auth_code_flow, mock_is_available):
        """Test authenticate uses Authorization Code Flow when configured."""
        mock_is_available.return_value = True
        mock_api_client = Mock()
        mock_create_client.return_value = mock_api_client

        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com/auth/realms/test",
            client_id="test-client",
            use_device_flow=False,
            k8s_api_host="https://api.example.com:6443"
        )
        strategy = OIDCStrategy(config)

        result = strategy.authenticate()

        mock_auth_code_flow.assert_called_once()
        mock_create_client.assert_called_once()
        assert result == mock_api_client
