"""
Tests for base authentication strategy.

Tests cover:
- Abstract method enforcement
- Default implementations
"""

import pytest

from openshift_ai_auth import AuthConfig
from openshift_ai_auth.strategies.base import AuthStrategy


class ConcreteStrategy(AuthStrategy):
    """Concrete implementation for testing."""

    def is_available(self) -> bool:
        return True

    def authenticate(self):
        return None


class IncompleteStrategy(AuthStrategy):
    """Incomplete implementation missing abstract methods."""
    pass


class TestAuthStrategyAbstractMethods:
    """Test abstract method enforcement."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that AuthStrategy cannot be instantiated directly."""
        config = AuthConfig()

        with pytest.raises(TypeError):
            AuthStrategy(config)

    def test_cannot_instantiate_incomplete_subclass(self):
        """Test that incomplete subclasses cannot be instantiated."""
        config = AuthConfig()

        with pytest.raises(TypeError):
            IncompleteStrategy(config)

    def test_can_instantiate_complete_subclass(self):
        """Test that complete subclasses can be instantiated."""
        config = AuthConfig()
        strategy = ConcreteStrategy(config)

        assert strategy.config == config

    def test_refresh_if_needed_not_implemented(self):
        """Test refresh_if_needed raises NotImplementedError by default."""
        config = AuthConfig()
        strategy = ConcreteStrategy(config)

        with pytest.raises(NotImplementedError):
            strategy.refresh_if_needed()

    def test_get_description_default(self):
        """Test get_description returns class name by default."""
        config = AuthConfig()
        strategy = ConcreteStrategy(config)

        description = strategy.get_description()

        assert description == "ConcreteStrategy"
