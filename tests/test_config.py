"""
Tests for AuthConfig configuration dataclass.

Tests cover:
- Default values
- Validation logic
- Environment variable loading
- Security warnings
- Sensitive data redaction
"""

import warnings
from pathlib import Path

import pytest

from openshift_ai_auth.config import AuthConfig, SecurityWarning
from openshift_ai_auth.exceptions import ConfigurationError


class TestAuthConfigDefaults:
    """Test default values and initialization."""

    def test_default_config(self, mock_env_vars):
        """Test AuthConfig with all defaults."""
        config = AuthConfig()
        assert config.method == "auto"
        assert config.verify_ssl is True
        assert config.use_device_flow is False
        assert config.use_keyring is False
        assert config.scopes == ["openid"]

    def test_explicit_config(self, mock_env_vars):
        """Test AuthConfig with explicit values."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://test.example.com",
            client_id="test-client",
            client_secret="test-secret",
            scopes=["openid", "profile", "email"],
            use_device_flow=True,
        )
        assert config.method == "oidc"
        assert config.oidc_issuer == "https://test.example.com"
        assert config.client_id == "test-client"
        assert config.client_secret == "test-secret"
        assert config.scopes == ["openid", "profile", "email"]
        assert config.use_device_flow is True


class TestAuthConfigValidation:
    """Test configuration validation logic."""

    def test_invalid_method(self, mock_env_vars):
        """Test that invalid method raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="invalid")

        assert "Invalid authentication method" in str(exc_info.value)
        assert "invalid" in str(exc_info.value)

    def test_oidc_missing_issuer(self, mock_env_vars):
        """Test that OIDC without issuer raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="oidc", client_id="test-client")

        assert "oidc_issuer" in str(exc_info.value)

    def test_oidc_missing_client_id(self, mock_env_vars):
        """Test that OIDC without client_id raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(method="oidc", oidc_issuer="https://test.example.com")

        assert "client_id" in str(exc_info.value)

    def test_oidc_invalid_issuer_url(self, mock_env_vars):
        """Test that OIDC with invalid issuer URL raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(
                method="oidc",
                oidc_issuer="not-a-url",
                client_id="test-client"
            )

        assert "valid URL" in str(exc_info.value)

    def test_oidc_valid_config(self, mock_env_vars):
        """Test that valid OIDC config passes validation."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://keycloak.example.com",
            client_id="test-client"
        )
        assert config.method == "oidc"

    def test_invalid_ca_cert_path(self, mock_env_vars):
        """Test that invalid CA cert path raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(ca_cert="/nonexistent/ca.crt")

        assert "CA certificate file not found" in str(exc_info.value)

    def test_invalid_kubeconfig_path(self, mock_env_vars):
        """Test that invalid kubeconfig path raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(kubeconfig_path="/nonexistent/config")

        assert "Kubeconfig file not found" in str(exc_info.value)

    def test_invalid_callback_port_too_low(self, mock_env_vars):
        """Test that callback port < 1 raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(oidc_callback_port=0)

        assert "Invalid OIDC callback port" in str(exc_info.value)

    def test_invalid_callback_port_too_high(self, mock_env_vars):
        """Test that callback port > 65535 raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            AuthConfig(oidc_callback_port=70000)

        assert "Invalid OIDC callback port" in str(exc_info.value)

    def test_valid_callback_port(self, mock_env_vars):
        """Test that valid callback port is accepted."""
        config = AuthConfig(oidc_callback_port=3000)
        assert config.oidc_callback_port == 3000

    def test_default_callback_port(self, mock_env_vars):
        """Test that default callback port is 8080."""
        config = AuthConfig()
        assert config.oidc_callback_port == 8080


class TestAuthConfigEnvironmentVariables:
    """Test environment variable loading."""

    def test_load_oidc_from_env(self, mock_oidc_env):
        """Test loading OIDC config from environment variables."""
        config = AuthConfig(method="oidc")
        assert config.oidc_issuer == "https://keycloak.example.com/auth/realms/test"
        assert config.client_id == "test-client"
        assert config.client_secret == "test-secret"

    def test_explicit_overrides_env(self, mock_oidc_env):
        """Test that explicit params override environment variables."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://override.example.com",
            client_id="override-client"
        )
        assert config.oidc_issuer == "https://override.example.com"
        assert config.client_id == "override-client"

    def test_kubeconfig_from_env(self, mock_env_vars, monkeypatch, tmp_path):
        """Test loading kubeconfig path from KUBECONFIG env var."""
        kubeconfig_path = str(tmp_path / "config")
        # Create the file so validation passes
        Path(kubeconfig_path).write_text("test")

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        config = AuthConfig()
        assert config.kubeconfig_path == kubeconfig_path


class TestAuthConfigSecurityWarnings:
    """Test security-related warnings."""

    def test_verify_ssl_false_warning(self, mock_env_vars):
        """Test that verify_ssl=False emits security warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            AuthConfig(verify_ssl=False)

            assert len(w) == 1
            assert issubclass(w[0].category, SecurityWarning)
            assert "TLS/SSL verification is disabled" in str(w[0].message)

    def test_http_issuer_warning(self, mock_env_vars):
        """Test that http:// issuer emits security warning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            AuthConfig(
                method="oidc",
                oidc_issuer="http://insecure.example.com",
                client_id="test-client"
            )

            assert len(w) == 1
            assert issubclass(w[0].category, SecurityWarning)
            assert "insecure http://" in str(w[0].message)


class TestAuthConfigSensitiveDataHandling:
    """Test that sensitive data is properly redacted."""

    def test_repr_redacts_secret(self, mock_env_vars):
        """Test that __repr__ redacts client_secret."""
        config = AuthConfig(
            method="oidc",
            oidc_issuer="https://test.example.com",
            client_id="test-client",
            client_secret="super-secret-value"
        )

        repr_str = repr(config)
        assert "super-secret-value" not in repr_str
        assert "***REDACTED***" in repr_str
        assert "test-client" in repr_str  # Non-sensitive data should be visible

    def test_repr_without_secret(self, mock_env_vars):
        """Test __repr__ when no secret is set."""
        config = AuthConfig()
        repr_str = repr(config)
        assert "AuthConfig" in repr_str


class TestAuthConfigFromDict:
    """Test creating AuthConfig from dictionary."""

    def test_from_dict_basic(self, mock_env_vars):
        """Test creating config from dictionary."""
        config_dict = {
            "method": "oidc",
            "oidc_issuer": "https://test.example.com",
            "client_id": "test-client",
            "scopes": ["openid", "profile"]
        }
        config = AuthConfig.from_dict(config_dict)

        assert config.method == "oidc"
        assert config.oidc_issuer == "https://test.example.com"
        assert config.client_id == "test-client"
        assert config.scopes == ["openid", "profile"]

    def test_from_dict_ignores_unknown_keys(self, mock_env_vars):
        """Test that from_dict ignores unknown keys."""
        config_dict = {
            "method": "auto",
            "unknown_key": "should be ignored",
            "another_unknown": 123
        }
        config = AuthConfig.from_dict(config_dict)
        assert config.method == "auto"
        # Should not raise an error


class TestAuthConfigMethodNormalization:
    """Test that method names are normalized."""

    def test_method_lowercase(self, mock_env_vars):
        """Test that method is converted to lowercase."""
        config = AuthConfig(method="AUTO")
        assert config.method == "auto"

        config = AuthConfig(method="KubeConfig")
        assert config.method == "kubeconfig"
