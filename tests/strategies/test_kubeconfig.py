"""
Tests for KubeConfig authentication strategy.

Tests cover:
- Availability detection
- Authentication flow
- Error handling
- Path resolution
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
from openshift_ai_auth.strategies.kubeconfig import KubeConfigStrategy


class TestKubeConfigStrategyAvailability:
    """Test availability detection for KubeConfig strategy."""

    def test_is_available_with_explicit_path(self, mock_kubeconfig):
        """Test availability when explicit kubeconfig path is provided."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        assert strategy.is_available() is True

    def test_is_available_with_kubeconfig_env(self, mock_kubeconfig, monkeypatch):
        """Test availability when KUBECONFIG env var is set."""
        monkeypatch.setenv("KUBECONFIG", str(mock_kubeconfig))
        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        assert strategy.is_available() is True

    def test_is_available_with_default_path(self, mock_kubeconfig, monkeypatch):
        """Test availability when kubeconfig exists at default path."""
        # Mock the _get_kubeconfig_path to return our mock kubeconfig
        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        # Patch the method to return our mock path
        with patch.object(strategy, '_get_kubeconfig_path', return_value=str(mock_kubeconfig)):
            assert strategy.is_available() is True

    def test_is_not_available_no_kubeconfig(self, tmp_path, monkeypatch):
        """Test unavailability when no kubeconfig exists."""
        # Point to non-existent path
        monkeypatch.delenv("KUBECONFIG", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "nonexistent")

        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        assert strategy.is_available() is False

    def test_is_not_available_unreadable_file(self, mock_kubeconfig, monkeypatch):
        """Test unavailability when kubeconfig file is not readable."""
        # Make file unreadable
        mock_kubeconfig.chmod(0o000)

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        is_avail = strategy.is_available()

        # Restore permissions for cleanup
        mock_kubeconfig.chmod(0o644)

        assert is_avail is False


class TestKubeConfigStrategyAuthentication:
    """Test authentication flow for KubeConfig strategy."""

    @patch('openshift_ai_auth.strategies.kubeconfig.k8s_config.load_kube_config')
    @patch('openshift_ai_auth.strategies.kubeconfig.client.ApiClient')
    def test_authenticate_success(self, mock_api_client, mock_load_config, mock_kubeconfig):
        """Test successful authentication."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_api_client.return_value = mock_client_instance

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        # Authenticate
        result = strategy.authenticate()

        # Verify
        assert result == mock_client_instance
        mock_load_config.assert_called_once_with(config_file=str(mock_kubeconfig))

    @patch('openshift_ai_auth.strategies.kubeconfig.k8s_config.load_kube_config')
    @patch('openshift_ai_auth.strategies.kubeconfig.client.ApiClient')
    def test_authenticate_with_custom_ca_cert(self, mock_api_client, mock_load_config, mock_kubeconfig, tmp_path):
        """Test authentication with custom CA certificate."""
        # Create a mock CA cert file
        ca_cert_path = tmp_path / "ca.crt"
        ca_cert_path.write_text("FAKE CA CERT")

        # Setup mocks
        mock_client_instance = MagicMock()
        mock_api_client.return_value = mock_client_instance

        config = AuthConfig(
            method="kubeconfig",
            kubeconfig_path=str(mock_kubeconfig),
            ca_cert=str(ca_cert_path)
        )
        strategy = KubeConfigStrategy(config)

        # Authenticate
        strategy.authenticate()

        # Verify CA cert was applied
        assert mock_client_instance.configuration.ssl_ca_cert == str(ca_cert_path)

    @patch('openshift_ai_auth.strategies.kubeconfig.k8s_config.load_kube_config')
    @patch('openshift_ai_auth.strategies.kubeconfig.client.ApiClient')
    def test_authenticate_with_ssl_verification_disabled(self, mock_api_client, mock_load_config, mock_kubeconfig):
        """Test authentication with SSL verification disabled."""
        # Setup mocks
        mock_client_instance = MagicMock()
        mock_api_client.return_value = mock_client_instance

        # Expect SecurityWarning when disabling SSL verification
        with pytest.warns(SecurityWarning, match="TLS/SSL verification is disabled"):
            config = AuthConfig(
                method="kubeconfig",
                kubeconfig_path=str(mock_kubeconfig),
                verify_ssl=False
            )

        strategy = KubeConfigStrategy(config)

        # Authenticate
        strategy.authenticate()

        # Verify SSL verification was disabled
        assert mock_client_instance.configuration.verify_ssl is False

    def test_authenticate_strategy_not_available(self, tmp_path):
        """Test authentication fails when strategy not available."""
        # Don't set kubeconfig_path in config to avoid validation error
        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        # Mock is_available to return False
        with patch.object(strategy, 'is_available', return_value=False):
            with patch.object(strategy, '_get_kubeconfig_path', return_value=None):
                with pytest.raises(StrategyNotAvailableError) as exc_info:
                    strategy.authenticate()

        assert "not available" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.kubeconfig.k8s_config.load_kube_config')
    def test_authenticate_config_exception(self, mock_load_config, mock_kubeconfig):
        """Test authentication handles kubernetes ConfigException."""
        from kubernetes.config import ConfigException

        # Make load_kube_config raise an exception
        mock_load_config.side_effect = ConfigException("Invalid config")

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy.authenticate()

        assert "Failed to load kubeconfig" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.kubeconfig.k8s_config.load_kube_config')
    def test_authenticate_unexpected_exception(self, mock_load_config, mock_kubeconfig):
        """Test authentication handles unexpected exceptions."""
        # Make load_kube_config raise an unexpected exception
        mock_load_config.side_effect = RuntimeError("Unexpected error")

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        with pytest.raises(AuthenticationError) as exc_info:
            strategy.authenticate()

        assert "Unexpected error" in str(exc_info.value)


class TestKubeConfigStrategyPathResolution:
    """Test kubeconfig path resolution logic."""

    def test_get_kubeconfig_path_explicit(self, mock_kubeconfig):
        """Test path resolution prefers explicit configuration."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        path = strategy._get_kubeconfig_path()
        assert path == str(mock_kubeconfig)

    def test_get_kubeconfig_path_from_env(self, mock_kubeconfig, monkeypatch):
        """Test path resolution uses KUBECONFIG env var."""
        monkeypatch.setenv("KUBECONFIG", str(mock_kubeconfig))

        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        path = strategy._get_kubeconfig_path()
        assert path == str(mock_kubeconfig)

    def test_get_kubeconfig_path_multiple_in_env(self, mock_kubeconfig, tmp_path, monkeypatch):
        """Test path resolution uses first path from KUBECONFIG with multiple paths."""
        other_config = tmp_path / "other_config"
        other_config.write_text("other config")

        # KUBECONFIG can have multiple paths separated by ':'
        # Clear any existing KUBECONFIG first
        monkeypatch.delenv("KUBECONFIG", raising=False)

        # Don't use AuthConfig yet - just test the strategy's path resolution
        # We need to set the env var after creating config to avoid validation
        config = AuthConfig(method="kubeconfig")

        # Now set the KUBECONFIG with multiple paths
        monkeypatch.setenv("KUBECONFIG", f"{mock_kubeconfig}:{other_config}")

        strategy = KubeConfigStrategy(config)

        path = strategy._get_kubeconfig_path()
        assert path == str(mock_kubeconfig)

    def test_get_kubeconfig_path_from_default(self, mock_kubeconfig, monkeypatch):
        """Test path resolution uses default ~/.kube/config."""
        # Clear KUBECONFIG env var
        monkeypatch.delenv("KUBECONFIG", raising=False)

        # Create the config without a kubeconfig_path
        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        # Patch the default path check to return our mock kubeconfig

        with patch('openshift_ai_auth.strategies.kubeconfig.Path') as mock_path_class:
            mock_path_instance = MagicMock()
            mock_path_instance.exists.return_value = True
            mock_path_instance.__str__.return_value = str(mock_kubeconfig)

            # Make Path.home() return the parent of .kube
            mock_home = MagicMock()
            mock_home.__truediv__.return_value.__truediv__.return_value = mock_path_instance
            mock_path_class.home.return_value = mock_home

            path = strategy._get_kubeconfig_path()
            assert path == str(mock_kubeconfig)

    def test_get_kubeconfig_path_none(self, tmp_path, monkeypatch):
        """Test path resolution returns None when no kubeconfig found."""
        monkeypatch.delenv("KUBECONFIG", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "nonexistent")

        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        path = strategy._get_kubeconfig_path()
        assert path is None


class TestKubeConfigStrategyDescription:
    """Test strategy description."""

    def test_get_description_with_kubeconfig(self, mock_kubeconfig):
        """Test description when kubeconfig is found."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        description = strategy.get_description()
        assert "KubeConfig" in description
        assert str(mock_kubeconfig) in description

    def test_get_description_without_kubeconfig(self, tmp_path, monkeypatch):
        """Test description when kubeconfig is not found."""
        monkeypatch.delenv("KUBECONFIG", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "nonexistent")

        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        description = strategy.get_description()
        assert "not found" in description
