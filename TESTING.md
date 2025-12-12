# Testing Guide

This document describes the testing strategy and how to run different types of tests for the OpenShift AI Authentication library.

## Table of Contents

- [Test Organization](#test-organization)
- [Running Tests](#running-tests)
- [Test Types](#test-types)
- [Mock OAuth Server](#mock-oauth-server)
- [Integration Testing with Docker](#integration-testing-with-docker)
- [CI/CD](#cicd)
- [Writing Tests](#writing-tests)

## Test Organization

Tests are organized into three categories:

```
tests/
├── conftest.py                    # Shared fixtures
├── mock_oauth_server.py           # Mock OAuth/OIDC server
├── test_*.py                      # Unit tests
├── strategies/
│   ├── test_kubeconfig.py        # Unit tests for KubeConfig
│   ├── test_incluster.py         # Unit tests for In-Cluster
│   ├── test_oidc.py              # Unit tests for OIDC
│   └── test_openshift.py         # Unit tests for OpenShift OAuth
└── integration/
    └── test_oidc_integration.py   # Integration tests with mock server
```

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run only unit tests (fast, no external dependencies)
pytest -m "not integration and not e2e"

# Run integration tests (with mock OAuth server)
pytest -m integration

# Run specific test file
pytest tests/strategies/test_oidc.py -v

# Run with coverage report
pytest --cov=src/openshift_ai_auth --cov-report=html

# Run tests in parallel (faster)
pytest -n auto
```

### Test Markers

Tests are marked with pytest markers to categorize them:

- `@pytest.mark.unit` - Fast unit tests with mocked dependencies
- `@pytest.mark.integration` - Integration tests using mock OAuth server
- `@pytest.mark.e2e` - End-to-end tests requiring real services
- `@pytest.mark.slow` - Tests that take longer to run

### Running Specific Test Categories

```bash
# Only unit tests
pytest -m unit

# Only integration tests
pytest -m integration

# Only E2E tests (requires real Keycloak)
pytest -m e2e

# Skip slow tests
pytest -m "not slow"

# Multiple markers
pytest -m "integration and not slow"
```

## Test Types

### 1. Unit Tests

**Characteristics:**
- Fast execution (< 1 second each)
- No external dependencies
- Heavily mocked
- Test individual functions/methods

**Example:**
```python
from openshift_ai_auth import AuthConfig
from openshift_ai_auth.exceptions import ConfigurationError

def test_invalid_method(mock_env_vars):
    """Test that invalid method raises ConfigurationError."""
    with pytest.raises(ConfigurationError):
        AuthConfig(method="invalid")
```

**Run:**
```bash
pytest tests/ -m "not integration and not e2e"
```

### 2. Integration Tests

**Characteristics:**
- Use mock OAuth/OIDC server
- Test complete flows end-to-end
- No real external services needed
- Moderate execution time

**Example:**
```python
import pytest

@pytest.mark.integration
def test_device_flow_with_mock_server(mock_oauth_server):
    """Test device code flow with auto-approval."""
    config = AuthConfig(
        method="oidc",
        oidc_issuer=mock_oauth_server.base_url,
        client_id="test-client",
        use_device_flow=True
    )

    strategy = OIDCStrategy(config)
    api_client = strategy.authenticate()

    assert api_client is not None
```

**Run:**
```bash
pytest tests/integration/ -m integration -v
```

### 3. End-to-End (E2E) Tests

**Characteristics:**
- Use real Keycloak instance
- Test against real OAuth server
- Slower execution
- Require Docker or external services

**Example:**
```python
import pytest

@pytest.mark.e2e
def test_real_keycloak_auth():
    """Test authentication with real Keycloak."""
    config = AuthConfig(
        method="oidc",
        oidc_issuer=os.getenv("OIDC_ISSUER"),
        client_id=os.getenv("OIDC_CLIENT_ID"),
        client_secret=os.getenv("OIDC_CLIENT_SECRET"),
    )
    # ... test with real server
```

**Run:**
```bash
# Requires Keycloak running (see Docker section)
docker-compose up -d keycloak
pytest tests/ -m e2e
```

## Mock OAuth Server

The mock OAuth server (`tests/mock_oauth_server.py`) implements a complete OAuth/OIDC server for testing:

### Features

- ✅ OIDC Discovery (`/.well-known/openid-configuration`)
- ✅ Authorization Code Flow with PKCE
- ✅ Device Code Flow
- ✅ Token Refresh
- ✅ Auto-approval mode for automated testing
- ✅ OAuth error responses

### Usage in Tests

```python
def test_with_mock_server(mock_oauth_server, oauth_config):
    """Use mock OAuth server in tests."""
    # Server is automatically started as a fixture

    # Create config pointing to mock server
    config = AuthConfig(
        method="oidc",
        oidc_issuer=oauth_config["issuer"],
        client_id=oauth_config["client_id"],
        verify_ssl=False  # Mock server uses http
    )

    # Test your code
    strategy = OIDCStrategy(config)
    assert strategy.is_available()
```

### Manual Testing

You can also run the mock server standalone:

```python
from tests.mock_oauth_server import MockOAuthServer

server = MockOAuthServer(host="localhost", port=9999)
server.auto_approve = True
server.start()

# Server is now running on http://localhost:9999
# Discovery: http://localhost:9999/.well-known/openid-configuration

# When done:
server.stop()
```

## Integration Testing with Docker

### Docker Compose for E2E Tests

Run tests with real Keycloak using Docker Compose:

```bash
# Start services (Keycloak + mock K8s API)
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
docker-compose -f docker-compose.test.yml run test-runner

# Clean up
docker-compose -f docker-compose.test.yml down
```

### Services in Docker Compose

1. **Keycloak** - Real OIDC provider on port 8180
2. **Mock Kubernetes API** - Simulated K8s API on port 6443
3. **Test Runner** - Container running pytest

### Manual Keycloak Setup

If you want to run Keycloak manually:

```bash
# Start Keycloak
docker run -d --name keycloak \
  -p 8180:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e KC_HTTP_ENABLED=true \
  -e KC_HOSTNAME_STRICT=false \
  quay.io/keycloak/keycloak:23.0 \
  start-dev

# Wait for it to start
sleep 30

# Access admin console: http://localhost:8180
# Username: admin
# Password: admin
```

Then create a test realm and client manually or using the admin API.

## CI/CD

### GitHub Actions Workflow

The project uses GitHub Actions for automated testing:

**Workflow Jobs:**
1. **unit-tests** - Run on Python 3.9, 3.10, 3.11, 3.12
2. **integration-tests** - Use mock OAuth server
3. **e2e-tests** - Use real Keycloak (Docker service)
4. **lint** - Code quality checks (ruff, mypy)
5. **security** - Vulnerability scanning (Trivy)

**Trigger Events:**
- Push to `main` or `develop`
- Pull requests to `main` or `develop`

### Running Tests Like CI

To run tests exactly as they run in CI:

```bash
# Unit tests (all Python versions)
pytest tests/ -m "not integration and not e2e" \
  --cov=src/openshift_ai_auth \
  --cov-report=xml

# Integration tests
pytest tests/integration/ -m integration \
  --cov=src/openshift_ai_auth \
  --cov-report=xml

# Lint
ruff check src/ tests/
mypy src/openshift_ai_auth --ignore-missing-imports
```

## Writing Tests

### Best Practices

1. **Use Appropriate Markers**
   ```python
   @pytest.mark.integration
   def test_full_flow():
       pass
   ```

2. **Use Fixtures**
   ```python
   def test_config(mock_env_vars, mock_oauth_server):
       # Fixtures provide clean environment
       pass
   ```

3. **Descriptive Names**
   ```python
   def test_auth_code_flow_with_invalid_client_secret():
       """Test that authentication fails with wrong client secret."""
       pass
   ```

4. **Test Error Cases**
   ```python
   def test_discovery_failure():
       """Test error handling when OIDC discovery fails."""
       with pytest.raises(AuthenticationError) as exc_info:
           strategy._discover_oidc_config()
       assert "Failed to discover" in str(exc_info.value)
   ```

5. **Avoid External Dependencies in Unit Tests**
   ```python
   # Good - mocked
   @patch('requests.get')
   def test_discovery(mock_get):
       mock_get.return_value.json.return_value = {"issuer": "test"}

   # Bad - real network call
   def test_discovery():
       response = requests.get("https://real-server.com/.well-known/...")
   ```

### Integration Test Template

```python
import pytest
from openshift_ai_auth import AuthConfig
from openshift_ai_auth.strategies.oidc import OIDCStrategy


@pytest.mark.integration
class TestMyIntegration:
    """Integration tests for my feature."""

    def test_scenario(self, mock_oauth_server, mock_env_vars):
        """Test a specific scenario."""
        # Arrange
        config = AuthConfig(
            method="oidc",
            oidc_issuer=mock_oauth_server.base_url,
            client_id="test-client",
            verify_ssl=False
        )
        strategy = OIDCStrategy(config)

        # Act
        result = strategy.authenticate()

        # Assert
        assert result is not None
```

## Coverage Requirements

- **Minimum coverage:** 90%
- **Current coverage:** Run `pytest --cov` to see
- **View HTML report:** `open htmlcov/index.html`

### Improving Coverage

```bash
# See which lines are not covered
pytest --cov=src/openshift_ai_auth --cov-report=term-missing

# Focus on specific module
pytest --cov=src/openshift_ai_auth/strategies/oidc --cov-report=term-missing

# Generate HTML report for detailed analysis
pytest --cov=src/openshift_ai_auth --cov-report=html
open htmlcov/index.html
```

## Troubleshooting

### Common Issues

**Issue: Mock OAuth server port already in use**
```bash
# Solution: Kill process using port 9999
lsof -ti:9999 | xargs kill -9
```

**Issue: Tests pass locally but fail in CI**
```bash
# Solution: Run with same environment as CI
pytest -m "not integration and not e2e" --strict-markers
```

**Issue: Keycloak takes too long to start**
```bash
# Solution: Increase healthcheck retries in docker-compose.test.yml
healthcheck:
  retries: 60  # Increase from 30
```

**Issue: Coverage fails but all tests pass**
```bash
# Solution: Add integration tests to improve coverage
pytest tests/integration/ -m integration --cov-append
```

## Performance

### Test Execution Times

- Unit tests: ~10-15 seconds (120 tests)
- Integration tests: ~5-10 seconds (with mock server)
- E2E tests: ~60-120 seconds (with Docker Keycloak)

### Optimizations

```bash
# Run tests in parallel
pytest -n auto

# Run only failed tests
pytest --lf

# Run tests that failed last time, then all others
pytest --ff

# Stop at first failure
pytest -x

# Show slowest tests
pytest --durations=10
```

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [Keycloak documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 RFC](https://oauth.net/2/)
- [OIDC Specification](https://openid.net/connect/)
