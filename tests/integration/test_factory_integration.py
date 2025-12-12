"""
Integration tests for authentication factory and auto-detection.

These tests verify the factory can properly detect and select authentication
strategies based on the environment.
"""

import warnings
from pathlib import Path

import pytest

from openshift_ai_auth import AuthConfig, get_k8s_client
from openshift_ai_auth.config import SecurityWarning
from openshift_ai_auth.exceptions import AuthenticationError, ConfigurationError
from openshift_ai_auth.factory import AuthFactory
from openshift_ai_auth.strategies.kubeconfig import KubeConfigStrategy
from openshift_ai_auth.strategies.oidc import OIDCStrategy
from openshift_ai_auth.strategies.openshift import OpenShiftOAuthStrategy


@pytest.mark.integration
class TestFactoryIntegrationAutoDetection:
    """Integration tests for factory auto-detection."""

    def test_auto_detect_kubeconfig(self, mock_kubeconfig, mock_env_vars):
        """Test auto-detection selects kubeconfig when available."""
        config = AuthConfig(method="auto", kubeconfig_path=str(mock_kubeconfig))
        factory = AuthFactory(config)

        strategy = factory.get_strategy()

        assert isinstance(strategy, KubeConfigStrategy)
        assert strategy.is_available()

    def test_auto_detect_oidc_from_env(self, mock_oauth_server, mock_env_vars, monkeypatch):
        """Test auto-detection selects OIDC when env vars are set."""
        monkeypatch.setenv("OIDC_ISSUER", mock_oauth_server.base_url)
        monkeypatch.setenv("OIDC_CLIENT_ID", "test-client")
        monkeypatch.delenv("KUBECONFIG", raising=False)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)
            config = AuthConfig(
                method="auto",
                k8s_api_host="https://test-k8s.example.com:6443",
                verify_ssl=False
            )

        factory = AuthFactory(config)
        strategy = factory.get_strategy()

        assert isinstance(strategy, OIDCStrategy)

    def test_auto_detect_with_explicit_method(self, mock_kubeconfig):
        """Test factory uses explicit method when specified."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        factory = AuthFactory(config)

        strategy = factory.get_strategy()

        assert isinstance(strategy, KubeConfigStrategy)

    def test_auto_detect_no_auth_available(self, mock_env_vars, monkeypatch, tmp_path):
        """Test auto-detection raises error when no auth available."""
        # Clear all auth-related environment variables
        monkeypatch.delenv("KUBECONFIG", raising=False)
        monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
        monkeypatch.delenv("OIDC_ISSUER", raising=False)
        monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
        monkeypatch.delenv("OPENSHIFT_TOKEN", raising=False)

        # Mock home to a directory without .kube/config
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        config = AuthConfig(method="auto")
        factory = AuthFactory(config)

        with pytest.raises(AuthenticationError) as exc_info:
            factory._auto_detect_strategy()

        assert "No authentication method available" in str(exc_info.value)


@pytest.mark.integration
class TestFactoryIntegrationGetK8sClient:
    """Integration tests for get_k8s_client function."""

    def test_get_k8s_client_with_kubeconfig(self, mock_kubeconfig):
        """Test get_k8s_client successfully returns client."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))

        client = get_k8s_client(config)

        assert client is not None
        assert client.configuration.host == "https://127.0.0.1:6443"

    def test_get_k8s_client_with_auto(self, mock_kubeconfig):
        """Test get_k8s_client with auto-detection."""
        config = AuthConfig(method="auto", kubeconfig_path=str(mock_kubeconfig))

        client = get_k8s_client(config)

        assert client is not None

    def test_get_k8s_client_invalid_method(self):
        """Test get_k8s_client raises error for invalid method."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="invalid")

        assert "Invalid authentication method" in str(exc_info.value)


@pytest.mark.integration
class TestFactoryIntegrationStrategySelection:
    """Integration tests for strategy selection logic."""

    def test_factory_creates_all_strategy_types(self, mock_kubeconfig, mock_oauth_server, mock_env_vars):
        """Test factory can create all strategy types."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SecurityWarning)

            # Test KubeConfig
            config1 = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
            factory1 = AuthFactory(config1)
            strategy1 = factory1.get_strategy()
            assert isinstance(strategy1, KubeConfigStrategy)

            # Test OIDC
            config2 = AuthConfig(
                method="oidc",
                oidc_issuer=mock_oauth_server.base_url,
                client_id="test-client",
                verify_ssl=False
            )
            factory2 = AuthFactory(config2)
            strategy2 = factory2.get_strategy()
            assert isinstance(strategy2, OIDCStrategy)

            # Test OpenShift (note: will fail is_available() but should create)
            config3 = AuthConfig(
                method="openshift",
                k8s_api_host=mock_oauth_server.base_url,
                verify_ssl=False
            )
            factory3 = AuthFactory(config3)
            strategy3 = factory3.get_strategy()
            assert isinstance(strategy3, OpenShiftOAuthStrategy)

    def test_factory_validates_strategy_availability(self, tmp_path):
        """Test configuration validates kubeconfig path during initialization."""
        # AuthConfig now validates kubeconfig_path exists during initialization
        non_existent = tmp_path / "nonexistent" / "config"

        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="kubeconfig", kubeconfig_path=str(non_existent))

        assert "Kubeconfig file not found" in str(exc_info.value)
