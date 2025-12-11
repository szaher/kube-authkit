"""
Tests for authentication factory and auto-detection logic.

Tests cover:
- Auto-detection precedence
- Strategy selection
- Error handling when no auth available
- get_k8s_client() function
"""

from unittest.mock import patch

import pytest

from openshift_ai_auth import AuthConfig, get_k8s_client
from openshift_ai_auth.exceptions import AuthenticationError, ConfigurationError
from openshift_ai_auth.factory import AuthFactory
from openshift_ai_auth.strategies.openshift import OpenShiftOAuthStrategy


class TestGetK8sClient:
    """Test the main get_k8s_client() entry point."""

    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    @patch('openshift_ai_auth.strategies.incluster.InClusterStrategy.is_available')
    def test_with_default_config(self, mock_incluster_avail, mock_kube_avail, mock_env_vars):
        """Test get_k8s_client with no arguments raises error when no auth available."""
        # Mock both strategies as unavailable
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        with pytest.raises(AuthenticationError) as exc_info:
            get_k8s_client()

        assert "No authentication method available" in str(exc_info.value)

    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    def test_with_explicit_config(self, mock_is_available, mock_env_vars):
        """Test get_k8s_client with explicit configuration."""
        # Mock strategy as unavailable to trigger ConfigurationError
        mock_is_available.return_value = False

        config = AuthConfig(method="kubeconfig")

        # This will fail because kubeconfig is not available
        with pytest.raises(ConfigurationError):
            get_k8s_client(config)


class TestAuthFactoryStrategySelection:
    """Test strategy selection logic."""

    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    def test_explicit_kubeconfig_method(self, mock_is_available, mock_env_vars):
        """Test selecting KubeConfig strategy explicitly."""
        # Mock strategy as unavailable to trigger ConfigurationError
        mock_is_available.return_value = False

        config = AuthConfig(method="kubeconfig")
        factory = AuthFactory(config)

        with pytest.raises(ConfigurationError):
            # Should try to use KubeConfig but fail because it's not available
            factory.get_strategy()

    def test_explicit_incluster_method(self, mock_env_vars):
        """Test selecting InCluster strategy explicitly."""
        config = AuthConfig(method="incluster")
        factory = AuthFactory(config)

        with pytest.raises(ConfigurationError):
            # Should try to use InCluster but fail because it's not available
            factory.get_strategy()

    def test_unknown_method_raises_error(self, mock_env_vars):
        """Test that unknown method raises ConfigurationError."""
        # The validation happens in AuthConfig.__post_init__, not in factory.get_strategy()
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="unknown")

        assert "Invalid authentication method" in str(exc_info.value)


class TestAuthFactoryAutoDetection:
    """Test auto-detection logic."""

    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    @patch('openshift_ai_auth.strategies.incluster.InClusterStrategy.is_available')
    def test_auto_detect_with_oidc_env(self, mock_incluster_avail, mock_kube_avail, mock_oidc_env):
        """Test auto-detection prefers OIDC when env vars present."""
        # Mock both strategies as unavailable
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        config = AuthConfig()  # method="auto" by default
        factory = AuthFactory(config)

        # OIDC env vars are set, but OIDC strategy not yet implemented
        # Should fall back to other methods
        with pytest.raises(AuthenticationError) as exc_info:
            factory.get_strategy()

        # Should indicate that it detected OIDC env but couldn't use it
        error_msg = str(exc_info.value)
        assert "No authentication method available" in error_msg

    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    @patch('openshift_ai_auth.strategies.incluster.InClusterStrategy.is_available')
    def test_auto_detect_no_auth_available(self, mock_incluster_avail, mock_kube_avail, mock_env_vars):
        """Test auto-detection when no auth method is available."""
        # Mock both strategies as unavailable
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        config = AuthConfig()
        factory = AuthFactory(config)

        with pytest.raises(AuthenticationError) as exc_info:
            factory.get_strategy()

        error_msg = str(exc_info.value)
        assert "No authentication method available" in error_msg
        assert "In-cluster service account - not available" in error_msg
        assert "KubeConfig file" in error_msg

    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    def test_auto_detect_kubeconfig(self, mock_is_available, mock_env_vars):
        """Test auto-detection selects KubeConfig when available."""
        mock_is_available.return_value = True

        config = AuthConfig()
        factory = AuthFactory(config)
        strategy = factory.get_strategy()

        # Should return a KubeConfigStrategy
        from openshift_ai_auth.strategies.kubeconfig import KubeConfigStrategy
        assert isinstance(strategy, KubeConfigStrategy)

    @patch('openshift_ai_auth.strategies.incluster.InClusterStrategy.is_available')
    def test_auto_detect_incluster(self, mock_is_available, mock_env_vars):
        """Test auto-detection selects InCluster when available."""
        mock_is_available.return_value = True

        config = AuthConfig()
        factory = AuthFactory(config)
        strategy = factory.get_strategy()

        # Should return an InClusterStrategy
        from openshift_ai_auth.strategies.incluster import InClusterStrategy
        assert isinstance(strategy, InClusterStrategy)

    @patch('openshift_ai_auth.strategies.incluster.InClusterStrategy.is_available')
    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    def test_auto_detect_precedence(self, mock_kube_avail, mock_incluster_avail, mock_env_vars):
        """Test that in-cluster is preferred over kubeconfig in auto-detection."""
        # Both are available
        mock_incluster_avail.return_value = True
        mock_kube_avail.return_value = True

        config = AuthConfig()
        factory = AuthFactory(config)
        strategy = factory.get_strategy()

        # Should prefer InCluster
        from openshift_ai_auth.strategies.incluster import InClusterStrategy
        assert isinstance(strategy, InClusterStrategy)


class TestAuthFactoryHasOIDCEnvVars:
    """Test OIDC environment variable detection."""

    def test_has_oidc_env_vars_true(self, mock_oidc_env):
        """Test detection when OIDC env vars are present."""
        config = AuthConfig()
        factory = AuthFactory(config)

        assert factory._has_oidc_env_vars() is True

    def test_has_oidc_env_vars_false(self, mock_env_vars):
        """Test detection when OIDC env vars are absent."""
        config = AuthConfig()
        factory = AuthFactory(config)

        assert factory._has_oidc_env_vars() is False

    def test_has_oidc_env_vars_partial(self, mock_env_vars, monkeypatch):
        """Test detection with only partial OIDC env vars."""
        monkeypatch.setenv("OIDC_ISSUER", "https://test.example.com")
        # Missing OIDC_CLIENT_ID

        config = AuthConfig()
        factory = AuthFactory(config)

        assert factory._has_oidc_env_vars() is False


class TestAuthFactoryErrorHandling:
    """Test error handling in AuthFactory."""

    def test_get_k8s_client_success(self, mock_kubeconfig):
        """Test get_k8s_client successfully returns ApiClient."""
        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))

        client = get_k8s_client(config)

        assert client is not None
        assert client.configuration.host == "https://127.0.0.1:6443"

    @patch('openshift_ai_auth.factory.AuthFactory.get_strategy')
    def test_get_k8s_client_strategy_error(self, mock_get_strategy):
        """Test get_k8s_client handles strategy errors."""
        mock_get_strategy.side_effect = ConfigurationError("Strategy error", "Details")

        config = AuthConfig(method="auto")

        with pytest.raises(ConfigurationError):
            get_k8s_client(config)

    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    def test_get_strategy_explicit_method_not_available(self, mock_is_available, mock_kubeconfig):
        """Test get_strategy raises error when explicit method not available."""
        mock_is_available.return_value = False

        config = AuthConfig(method="kubeconfig", kubeconfig_path=str(mock_kubeconfig))
        factory = AuthFactory(config)

        with pytest.raises(ConfigurationError) as exc_info:
            factory.get_strategy()

        assert "not available" in str(exc_info.value)

    def test_auto_detect_with_openshift_token_env(self, monkeypatch):
        """Test auto-detection with OPENSHIFT_TOKEN environment variable."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~test-token")
        monkeypatch.delenv("KUBECONFIG", raising=False)

        config = AuthConfig(
            method="auto",
            k8s_api_host="https://api.cluster.example.com:6443"
        )
        factory = AuthFactory(config)

        strategy = factory._auto_detect_strategy()

        assert isinstance(strategy, OpenShiftOAuthStrategy)

    @patch('openshift_ai_auth.strategies.openshift.OpenShiftOAuthStrategy.is_available')
    @patch('openshift_ai_auth.strategies.incluster.InClusterStrategy.is_available')
    @patch('openshift_ai_auth.strategies.kubeconfig.KubeConfigStrategy.is_available')
    def test_auto_detect_openshift_not_available_fallback(self, mock_kube_avail, mock_incluster_avail, mock_openshift_avail, monkeypatch):
        """Test auto-detection falls back when OpenShift not available."""
        monkeypatch.setenv("OPENSHIFT_TOKEN", "sha256~test-token")
        monkeypatch.delenv("KUBECONFIG", raising=False)
        mock_openshift_avail.return_value = False
        mock_incluster_avail.return_value = False
        mock_kube_avail.return_value = False

        config = AuthConfig(method="auto", k8s_api_host="https://api.cluster.example.com:6443")
        factory = AuthFactory(config)

        # Should raise AuthenticationError when all strategies are unavailable
        with pytest.raises(AuthenticationError) as exc_info:
            factory._auto_detect_strategy()

        assert "No authentication method available" in str(exc_info.value)
