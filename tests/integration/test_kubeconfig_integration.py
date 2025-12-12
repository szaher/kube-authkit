"""
Integration tests for KubeConfig authentication strategy.

These tests verify the KubeConfig strategy works end-to-end with real
kubeconfig files.
"""

from pathlib import Path

import pytest

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.exceptions import AuthenticationError
from openshift_ai_auth.strategies.kubeconfig import KubeConfigStrategy


@pytest.mark.integration
class TestKubeConfigIntegrationAuthentication:
    """Integration tests for KubeConfig authentication."""

    def test_authenticate_with_mock_kubeconfig(self, mock_kubeconfig):
        """Test full authentication flow with mock kubeconfig."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        # Verify strategy is available
        assert strategy.is_available()

        # Authenticate
        api_client = strategy.authenticate()

        # Verify we got a valid API client
        assert api_client is not None
        assert api_client.configuration.host == "https://127.0.0.1:6443"
        # CA cert will be set from kubeconfig
        assert api_client.configuration.ssl_ca_cert is not None

    def test_authenticate_with_env_kubeconfig(self, mock_kubeconfig, monkeypatch):
        """Test authentication using KUBECONFIG environment variable."""
        monkeypatch.setenv("KUBECONFIG", str(mock_kubeconfig))

        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        assert strategy.is_available()

        api_client = strategy.authenticate()
        assert api_client is not None

    def test_authenticate_with_default_location(self, mock_kubeconfig, monkeypatch, tmp_path):
        """Test authentication with kubeconfig in default location."""
        # Create .kube directory in home
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()

        # Copy mock kubeconfig to default location
        default_config = kube_dir / "config"
        default_config.write_text(mock_kubeconfig.read_text())

        # Mock the home directory
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.delenv("KUBECONFIG", raising=False)

        config = AuthConfig(method="kubeconfig")
        strategy = KubeConfigStrategy(config)

        # Should find config in default location
        assert strategy.is_available()

        api_client = strategy.authenticate()
        assert api_client is not None

    def test_get_kubeconfig_path_precedence(self, mock_kubeconfig, monkeypatch, tmp_path):
        """Test kubeconfig path resolution precedence."""
        # Create .kube directory with default config
        kube_dir = tmp_path / ".kube"
        kube_dir.mkdir()
        default_config = kube_dir / "config"
        default_config.write_text("default: kubeconfig")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Test 1: Explicit path takes precedence
        config1 = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy1 = KubeConfigStrategy(config1)
        assert strategy1._get_kubeconfig_path() == str(mock_kubeconfig)

        # Test 2: KUBECONFIG env var takes precedence over default
        monkeypatch.setenv("KUBECONFIG", str(mock_kubeconfig))
        config2 = AuthConfig(method="kubeconfig")
        strategy2 = KubeConfigStrategy(config2)
        assert strategy2._get_kubeconfig_path() == str(mock_kubeconfig)

        # Test 3: Default location when nothing else specified
        monkeypatch.delenv("KUBECONFIG", raising=False)
        config3 = AuthConfig(method="kubeconfig")
        strategy3 = KubeConfigStrategy(config3)
        assert strategy3._get_kubeconfig_path() == str(default_config)


@pytest.mark.integration
class TestKubeConfigIntegrationErrorHandling:
    """Integration tests for KubeConfig error handling."""

    def test_authenticate_with_nonexistent_file(self, tmp_path):
        """Test configuration validation catches nonexistent file."""
        from openshift_ai_auth.exceptions import ConfigurationError

        non_existent = tmp_path / "nonexistent" / "config"

        # AuthConfig now validates kubeconfig_path exists during initialization
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="kubeconfig", kubeconfig_path=str(non_existent))

        assert "Kubeconfig file not found" in str(exc_info.value)

    def test_authenticate_with_invalid_yaml(self, tmp_path):
        """Test authentication fails with invalid YAML."""
        invalid_config = tmp_path / "invalid.yaml"
        invalid_config.write_text("this is not valid yaml: [[[")

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(invalid_config))
        strategy = KubeConfigStrategy(config)

        # May still be "available" (file exists) but authenticate should fail
        with pytest.raises(AuthenticationError):
            strategy.authenticate()

    def test_description(self, mock_kubeconfig):
        """Test strategy description includes kubeconfig path."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        strategy = KubeConfigStrategy(config)

        description = strategy.get_description()

        assert "KubeConfig" in description
        assert str(mock_kubeconfig) in description
