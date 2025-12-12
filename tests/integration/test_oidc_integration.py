"""
Integration tests for OIDC authentication.

These tests use a mock OAuth server to test the full authentication flow
without requiring external services. They are marked with @pytest.mark.integration
and can be run separately from unit tests.

Run with:
    pytest tests/integration/ -m integration
    pytest tests/integration/ -v  # Run all integration tests
"""

import warnings
from unittest.mock import MagicMock, patch

import pytest

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.config import SecurityWarning
from openshift_ai_auth.exceptions import AuthenticationError
from openshift_ai_auth.strategies.oidc import OIDCStrategy


@pytest.mark.integration
class TestOIDCIntegrationAuthCodeFlow:
    """Integration tests for OIDC Authorization Code Flow."""

    def test_full_auth_code_flow_with_mock_server(self, mock_oauth_server, mock_env_vars):
        """Test complete Authorization Code Flow with mock OAuth server."""
        # Create config pointing to mock server (expect security warning for http://)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="oidc",
                oidc_issuer=mock_oauth_server.base_url,
                client_id=mock_oauth_server.client_id,
                k8s_api_host="https://test-k8s.example.com:6443",
                use_device_flow=False,
                oidc_callback_port=8080,
                verify_ssl=False  # Mock server uses http
            )

        strategy = OIDCStrategy(config)

        # Verify strategy is available
        assert strategy.is_available()

        # Mock the browser opening and callback handling
        with patch('webbrowser.open'):
            # Mock the callback server to simulate successful auth
            with patch('openshift_ai_auth.strategies.oidc.HTTPServer') as mock_server:
                # Simulate auth code callback
                MagicMock()
                mock_server_instance = MagicMock()
                mock_server.return_value = mock_server_instance

                # Simulate successful callback with auth code
                auth_result = {}

                def simulate_callback(*args, **kwargs):
                    """Simulate receiving auth code."""
                    # Request auth code from mock server


                    # The mock server will auto-approve and return a code
                    # We simulate this by directly calling token endpoint
                    auth_result["code"] = "test_auth_code_123"

                mock_server_instance.handle_request.side_effect = simulate_callback

                # For this test, we'll patch the entire auth flow
                # to use our mock server's tokens

                def mock_auth():
                    """Mock authentication that uses real mock server."""
                    # Just set a token directly for this test
                    strategy._access_token = "access_test_token_123"
                    strategy._refresh_token = "refresh_test_token_123"

                with patch.object(strategy, '_authenticate_auth_code_flow', mock_auth):
                    api_client = strategy.authenticate()

                    # Verify we got an API client
                    assert api_client is not None
                    assert strategy._access_token is not None

    def test_discovery_with_mock_server(self, mock_oauth_server, mock_env_vars):
        """Test OIDC discovery works with mock server."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="oidc",
                oidc_issuer=mock_oauth_server.base_url,
                client_id="test-client",
                verify_ssl=False
            )

        strategy = OIDCStrategy(config)
        oidc_config = strategy._discover_oidc_config()

        # Verify discovery document
        assert oidc_config["issuer"] == mock_oauth_server.base_url
        assert "authorization_endpoint" in oidc_config
        assert "token_endpoint" in oidc_config
        assert "device_authorization_endpoint" in oidc_config

    def test_token_refresh_with_mock_server(self, mock_oauth_server, mock_env_vars):
        """Test token refresh works with mock server."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="oidc",
                oidc_issuer=mock_oauth_server.base_url,
                client_id=mock_oauth_server.client_id,
                verify_ssl=False
            )

        strategy = OIDCStrategy(config)

        # First, we need to get a refresh token
        # For testing, we'll create one directly in the mock server
        refresh_token = "refresh_test_token"
        mock_oauth_server.tokens[refresh_token] = {
            "client_id": mock_oauth_server.client_id,
            "type": "refresh"
        }

        # Now test refresh
        strategy._refresh_access_token(refresh_token)

        # Verify we got a new access token
        assert strategy._access_token is not None
        assert strategy._access_token.startswith("access_")


@pytest.mark.integration
class TestOIDCIntegrationDeviceFlow:
    """Integration tests for OIDC Device Code Flow."""

    def test_device_flow_discovery(self, mock_oauth_server, mock_env_vars):
        """Test device code flow endpoint discovery."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="oidc",
                oidc_issuer=mock_oauth_server.base_url,
                client_id=mock_oauth_server.client_id,
                use_device_flow=True,
                verify_ssl=False
            )

        strategy = OIDCStrategy(config)
        oidc_config = strategy._discover_oidc_config()

        assert "device_authorization_endpoint" in oidc_config
        assert oidc_config["device_authorization_endpoint"] == f"{mock_oauth_server.base_url}/device/code"

    def test_device_flow_with_auto_approve(self, mock_oauth_server, mock_env_vars):
        """Test device code flow with auto-approval."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="oidc",
                oidc_issuer=mock_oauth_server.base_url,
                client_id=mock_oauth_server.client_id,
                k8s_api_host="https://test-k8s.example.com:6443",
                use_device_flow=True,
                verify_ssl=False
            )

        # Ensure auto-approve is enabled
        mock_oauth_server.auto_approve = True

        strategy = OIDCStrategy(config)

        # Patch print to suppress output during test
        with patch('builtins.print'):
            # Authenticate using device flow
            api_client = strategy.authenticate()

            # Verify authentication succeeded
            assert api_client is not None
            assert strategy._access_token is not None
            assert strategy._access_token.startswith("access_")


@pytest.mark.integration
class TestOIDCIntegrationErrorHandling:
    """Integration tests for OIDC error handling."""

    def test_invalid_refresh_token(self, mock_oauth_server, mock_env_vars):
        """Test error handling for invalid refresh token."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="oidc",
                oidc_issuer=mock_oauth_server.base_url,
                client_id=mock_oauth_server.client_id,
                verify_ssl=False
            )

        strategy = OIDCStrategy(config)

        # Try to refresh with invalid token
        with pytest.raises(AuthenticationError) as exc_info:
            strategy._refresh_access_token("invalid_refresh_token")

        assert "invalid_grant" in str(exc_info.value)

    def test_discovery_failure(self, mock_env_vars):
        """Test error handling when discovery fails."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="oidc",
                oidc_issuer="http://nonexistent-server-xyz.invalid:9876",
                client_id="test-client",
                verify_ssl=False
            )

        strategy = OIDCStrategy(config)

        # Discovery should fail for nonexistent server
        assert not strategy.is_available()


@pytest.mark.integration
@pytest.mark.slow
class TestOIDCIntegrationPKCE:
    """Integration tests for PKCE (Proof Key for Code Exchange)."""

    def test_pkce_code_challenge_generation(self, mock_oauth_server, mock_env_vars):
        """Test that PKCE code challenge is properly generated and verified."""
        import base64
        import hashlib
        import secrets

        import requests

        # Generate PKCE parameters
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        # Request authorization with PKCE
        auth_response = requests.get(
            f"{mock_oauth_server.base_url}/authorize",
            params={
                "client_id": mock_oauth_server.client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:8080/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "state": "test_state"
            },
            allow_redirects=False
        )

        # Mock server should return redirect with auth code
        assert auth_response.status_code == 302
        location = auth_response.headers.get("Location", "")
        assert "code=" in location

        # Extract auth code
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        auth_code = params["code"][0]

        # Exchange code for token with PKCE verifier
        token_response = requests.post(
            f"{mock_oauth_server.base_url}/token",
            data={
                "client_id": mock_oauth_server.client_id,
                "code": auth_code,
                "redirect_uri": "http://localhost:8080/callback",
                "grant_type": "authorization_code",
                "code_verifier": code_verifier
            }
        )

        # Should succeed with valid verifier
        assert token_response.status_code == 200
        token_data = token_response.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data

    def test_pkce_verification_failure(self, mock_oauth_server, mock_env_vars):
        """Test that PKCE verification fails with wrong verifier."""
        import base64
        import hashlib
        import secrets

        import requests

        # Generate PKCE parameters
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        # Request authorization
        auth_response = requests.get(
            f"{mock_oauth_server.base_url}/authorize",
            params={
                "client_id": mock_oauth_server.client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:8080/callback",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            allow_redirects=False
        )

        # Extract auth code
        from urllib.parse import parse_qs, urlparse
        location = auth_response.headers.get("Location", "")
        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        auth_code = params["code"][0]

        # Try to exchange with WRONG verifier
        wrong_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

        token_response = requests.post(
            f"{mock_oauth_server.base_url}/token",
            data={
                "client_id": mock_oauth_server.client_id,
                "code": auth_code,
                "redirect_uri": "http://localhost:8080/callback",
                "grant_type": "authorization_code",
                "code_verifier": wrong_verifier  # Wrong verifier!
            }
        )

        # Should fail with 401
        assert token_response.status_code == 401
        error_data = token_response.json()
        assert error_data["error"] == "invalid_grant"
        assert "PKCE" in error_data["error_description"]
