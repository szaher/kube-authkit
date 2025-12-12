"""
Tests for InCluster authentication strategy.

Tests cover:
- Availability detection
- Authentication flow
- Error handling
- Namespace detection
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.config import SecurityWarning
from openshift_ai_auth.exceptions import (
    AuthenticationError,
    StrategyNotAvailableError,
)
from openshift_ai_auth.strategies.incluster import InClusterStrategy


class TestInClusterStrategyAvailability:
    """Test availability detection for InCluster strategy."""

    def test_is_available_in_cluster(self, mock_service_account):
        """Test availability when running in cluster."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # The mock_service_account fixture sets up the environment properly
        # but uses a temp path. We need to patch the constants.
        with patch('openshift_ai_auth.strategies.incluster.TOKEN_PATH', mock_service_account / "token"):
            with patch('openshift_ai_auth.strategies.incluster.CA_CERT_PATH', mock_service_account / "ca.crt"):
                assert strategy.is_available() is True

    def test_is_not_available_missing_env_var(self, mock_service_account, monkeypatch):
        """Test unavailability when KUBERNETES_SERVICE_HOST is missing."""
        monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        with patch('openshift_ai_auth.strategies.incluster.TOKEN_PATH', mock_service_account / "token"):
            with patch('openshift_ai_auth.strategies.incluster.CA_CERT_PATH', mock_service_account / "ca.crt"):
                assert strategy.is_available() is False

    def test_is_not_available_missing_token(self, monkeypatch):
        """Test unavailability when service account token is missing."""
        monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Use non-existent paths
        with patch('openshift_ai_auth.strategies.incluster.TOKEN_PATH', Path("/nonexistent/token")):
            with patch('openshift_ai_auth.strategies.incluster.CA_CERT_PATH', Path("/nonexistent/ca.crt")):
                assert strategy.is_available() is False

    def test_is_not_available_missing_ca_cert(self, tmp_path, monkeypatch):
        """Test unavailability when CA certificate is missing."""
        monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

        # Create token but not CA cert
        token_path = tmp_path / "token"
        token_path.write_text("test-token")

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        with patch('openshift_ai_auth.strategies.incluster.TOKEN_PATH', token_path):
            with patch('openshift_ai_auth.strategies.incluster.CA_CERT_PATH', Path("/nonexistent/ca.crt")):
                assert strategy.is_available() is False

    def test_is_not_available_unreadable_token(self, mock_service_account, monkeypatch):
        """Test unavailability when token is unreadable."""
        monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

        token_path = mock_service_account / "token"
        ca_path = mock_service_account / "ca.crt"

        # Make token unreadable
        token_path.chmod(0o000)

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        with patch('openshift_ai_auth.strategies.incluster.TOKEN_PATH', token_path):
            with patch('openshift_ai_auth.strategies.incluster.CA_CERT_PATH', ca_path):
                is_avail = strategy.is_available()

        # Restore permissions for cleanup
        token_path.chmod(0o644)

        assert is_avail is False

    def test_is_not_available_unreadable_ca_cert(self, mock_service_account, monkeypatch):
        """Test unavailability when CA cert is unreadable."""
        monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

        token_path = mock_service_account / "token"
        ca_path = mock_service_account / "ca.crt"

        # Make CA cert unreadable
        ca_path.chmod(0o000)

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        with patch('openshift_ai_auth.strategies.incluster.TOKEN_PATH', token_path):
            with patch('openshift_ai_auth.strategies.incluster.CA_CERT_PATH', ca_path):
                is_avail = strategy.is_available()

        # Restore permissions for cleanup
        ca_path.chmod(0o644)

        assert is_avail is False


class TestInClusterStrategyAuthentication:
    """Test authentication flow for InCluster strategy."""

    @patch('openshift_ai_auth.strategies.incluster.k8s_config.load_incluster_config')
    @patch('openshift_ai_auth.strategies.incluster.client.ApiClient')
    def test_authenticate_success(self, mock_api_client, mock_load_config, mock_service_account):
        """Test successful authentication."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_api_client.return_value = mock_client_instance

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Mock is_available to return True
        with patch.object(strategy, 'is_available', return_value=True):
            result = strategy.authenticate()

        # Verify
        assert result == mock_client_instance
        mock_load_config.assert_called_once()

    @patch('openshift_ai_auth.strategies.incluster.k8s_config.load_incluster_config')
    @patch('openshift_ai_auth.strategies.incluster.client.ApiClient')
    def test_authenticate_with_custom_ca_cert(self, mock_api_client, mock_load_config, mock_service_account, tmp_path):
        """Test authentication with custom CA certificate."""
        # Create a mock CA cert file
        ca_cert_path = tmp_path / "custom_ca.crt"
        ca_cert_path.write_text("CUSTOM CA CERT")

        # Setup mocks
        mock_client_instance = MagicMock()
        mock_api_client.return_value = mock_client_instance

        config = AuthConfig(method="incluster", ca_cert=str(ca_cert_path))
        strategy = InClusterStrategy(config)

        # Mock is_available to return True
        with patch.object(strategy, 'is_available', return_value=True):
            strategy.authenticate()

        # Verify CA cert was applied
        assert mock_client_instance.configuration.ssl_ca_cert == str(ca_cert_path)

    @patch('openshift_ai_auth.strategies.incluster.k8s_config.load_incluster_config')
    @patch('openshift_ai_auth.strategies.incluster.client.ApiClient')
    def test_authenticate_with_ssl_verification_disabled(self, mock_api_client, mock_load_config, mock_service_account):
        """Test authentication with SSL verification disabled."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_api_client.return_value = mock_client_instance

        # Expect SecurityWarning when disabling SSL verification
        with pytest.warns(SecurityWarning, match="TLS/SSL verification is disabled"):
            config = AuthConfig(method="incluster", verify_ssl=False)

        strategy = InClusterStrategy(config)

        # Mock is_available to return True
        with patch.object(strategy, 'is_available', return_value=True):
            strategy.authenticate()

        # Verify SSL verification was disabled
        assert mock_client_instance.configuration.verify_ssl is False

    @patch('openshift_ai_auth.strategies.incluster.k8s_config.load_incluster_config')
    @patch('openshift_ai_auth.strategies.incluster.client.ApiClient')
    def test_authenticate_with_namespace(self, mock_api_client, mock_load_config, mock_service_account):
        """Test authentication logs namespace when available."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_api_client.return_value = mock_client_instance

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Mock is_available and _get_namespace
        with patch.object(strategy, 'is_available', return_value=True):
            with patch.object(strategy, '_get_namespace', return_value="test-namespace"):
                result = strategy.authenticate()

        assert result == mock_client_instance

    def test_authenticate_strategy_not_available(self):
        """Test authentication fails when strategy not available."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # is_available will return False since we're not in a cluster
        with pytest.raises(StrategyNotAvailableError) as exc_info:
            strategy.authenticate()

        assert "not available" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.incluster.k8s_config.load_incluster_config')
    def test_authenticate_config_exception(self, mock_load_config, mock_service_account):
        """Test authentication handles kubernetes ConfigException."""
        from kubernetes.config import ConfigException

        # Make load_incluster_config raise an exception
        mock_load_config.side_effect = ConfigException("Invalid config")

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Mock is_available to return True
        with patch.object(strategy, 'is_available', return_value=True):
            with pytest.raises(AuthenticationError) as exc_info:
                strategy.authenticate()

        assert "Failed to load in-cluster configuration" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.incluster.k8s_config.load_incluster_config')
    def test_authenticate_unexpected_exception(self, mock_load_config, mock_service_account):
        """Test authentication handles unexpected exceptions."""
        # Make load_incluster_config raise an unexpected exception
        mock_load_config.side_effect = RuntimeError("Unexpected error")

        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        # Mock is_available to return True
        with patch.object(strategy, 'is_available', return_value=True):
            with pytest.raises(AuthenticationError) as exc_info:
                strategy.authenticate()

        assert "Unexpected error" in str(exc_info.value)


class TestInClusterStrategyNamespace:
    """Test namespace detection."""

    def test_get_namespace_available(self, mock_service_account):
        """Test getting namespace when file exists."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        namespace_path = mock_service_account / "namespace"

        with patch('openshift_ai_auth.strategies.incluster.NAMESPACE_PATH', namespace_path):
            namespace = strategy._get_namespace()

        assert namespace == "default"

    def test_get_namespace_not_available(self, tmp_path):
        """Test getting namespace when file doesn't exist."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        with patch('openshift_ai_auth.strategies.incluster.NAMESPACE_PATH', tmp_path / "nonexistent"):
            namespace = strategy._get_namespace()

        assert namespace is None

    def test_get_namespace_read_error(self, mock_service_account):
        """Test getting namespace handles read errors gracefully."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        namespace_path = mock_service_account / "namespace"
        namespace_path.chmod(0o000)

        with patch('openshift_ai_auth.strategies.incluster.NAMESPACE_PATH', namespace_path):
            namespace = strategy._get_namespace()

        # Restore permissions
        namespace_path.chmod(0o644)

        assert namespace is None


class TestInClusterStrategyDescription:
    """Test strategy description."""

    def test_get_description_with_namespace(self, mock_service_account):
        """Test description when namespace is available."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        namespace_path = mock_service_account / "namespace"

        with patch('openshift_ai_auth.strategies.incluster.NAMESPACE_PATH', namespace_path):
            description = strategy.get_description()

        assert "In-Cluster" in description
        assert "default" in description

    def test_get_description_without_namespace(self, tmp_path):
        """Test description when namespace is not available."""
        config = AuthConfig(method="incluster")
        strategy = InClusterStrategy(config)

        with patch('openshift_ai_auth.strategies.incluster.NAMESPACE_PATH', tmp_path / "nonexistent"):
            description = strategy.get_description()

        assert "In-Cluster" in description
        assert "Service Account" in description
