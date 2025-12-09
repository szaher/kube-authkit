# OpenShift AI Authentication Library

A lightweight Python library that provides unified authentication for OpenShift and Kubernetes clusters. This library simplifies authentication by supporting multiple methods through a single, consistent interface.

## Features

- **Universal Authentication Support**
  - Standard Kubernetes KubeConfig (~/.kube/config)
  - In-Cluster Service Account (for Pods and Notebooks)
  - OIDC (OpenID Connect) with multiple flows
  - OpenShift OAuth

- **Auto-Detection**: Automatically detects and uses the best authentication method for your environment

- **Multiple OIDC Flows**
  - Authorization Code Flow with PKCE (for interactive apps)
  - Device Code Flow (for CLI tools and headless environments)
  - Client Credentials Flow (for service-to-service authentication)

- **Token Management**
  - Automatic token refresh
  - Optional persistent storage via system keyring
  - Secure in-memory storage by default

- **Security First**
  - TLS verification enabled by default
  - No sensitive data in logs
  - Minimal dependencies

## Installation

```bash
pip install openshift-ai-auth
```

For optional keyring support (persistent token storage):

```bash
pip install openshift-ai-auth[keyring]
```

## Quick Start

### Automatic Authentication (Recommended)

The library automatically detects your environment and chooses the appropriate authentication method:

```python
from openshift_ai_auth import get_k8s_client
from kubernetes import client

# Auto-detect environment and authenticate
api_client = get_k8s_client()

# Use with standard Kubernetes client
v1 = client.CoreV1Api(api_client)
pods = v1.list_pod_for_all_namespaces()
print(f"Found {len(pods.items)} pods")
```

This works seamlessly whether you're running:
- Locally with ~/.kube/config
- Inside a Kubernetes Pod or OpenShift Notebook (using Service Account)
- With OIDC credentials in environment variables

### Explicit OIDC Authentication

For CLI tools or when you need explicit control:

```python
from openshift_ai_auth import get_k8s_client, AuthConfig

config = AuthConfig(
    method="oidc",
    oidc_issuer="https://keycloak.example.com/auth/realms/myrealm",
    client_id="my-cli-tool",
    use_device_flow=True  # Good for headless/CLI environments
)

# This will print: "Visit https://... and enter code: ABCD-EFGH"
api_client = get_k8s_client(config)
```

### Interactive Browser-Based Authentication

For notebooks or interactive applications:

```python
from openshift_ai_auth import get_k8s_client, AuthConfig

config = AuthConfig(
    method="oidc",
    oidc_issuer="https://keycloak.example.com/auth/realms/myrealm",
    client_id="my-app",
    use_device_flow=False  # Use Authorization Code Flow (opens browser)
)

# Browser will open for authentication
api_client = get_k8s_client(config)
```

### Persistent Token Storage

Store refresh tokens securely in your system keyring:

```python
from openshift_ai_auth import get_k8s_client, AuthConfig

config = AuthConfig(
    method="oidc",
    oidc_issuer="https://keycloak.example.com/auth/realms/myrealm",
    client_id="my-app",
    use_keyring=True  # Store tokens in system keyring
)

# First run: Interactive authentication
# Subsequent runs: Uses stored refresh token automatically
api_client = get_k8s_client(config)
```

## Configuration

### AuthConfig Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `method` | str | "auto" | Authentication method: "auto", "kubeconfig", "incluster", "oidc", "openshift" |
| `k8s_api_host` | str | None | Kubernetes API server URL (auto-detected if not provided) |
| `oidc_issuer` | str | None | OIDC issuer URL (required for OIDC) |
| `client_id` | str | None | OIDC client ID (required for OIDC) |
| `client_secret` | str | None | OIDC client secret (for confidential clients) |
| `scopes` | list | ["openid"] | OIDC scopes to request |
| `use_device_flow` | bool | False | Use Device Code Flow instead of Authorization Code Flow |
| `use_keyring` | bool | False | Store refresh tokens in system keyring |
| `ca_cert` | str | None | Path to custom CA certificate bundle |
| `verify_ssl` | bool | True | Verify SSL certificates (disable only for development) |

### Environment Variables

The library respects these environment variables:

- `KUBECONFIG`: Path to kubeconfig file
- `KUBERNETES_SERVICE_HOST`: Auto-detected in-cluster (set by Kubernetes)
- `OIDC_ISSUER`: OIDC issuer URL
- `OIDC_CLIENT_ID`: OIDC client ID
- `OIDC_CLIENT_SECRET`: OIDC client secret
- `OPENSHIFT_TOKEN`: OpenShift OAuth token

## Architecture

This library uses the Strategy Pattern to provide a unified interface across different authentication methods:

```
AuthFactory (auto-detection)
    ├── KubeConfigStrategy (~/.kube/config)
    ├── InClusterStrategy (Service Account)
    ├── OIDCStrategy (OpenID Connect)
    └── OpenShiftOAuthStrategy (OpenShift OAuth)
```

Each strategy implements the same interface, making it easy to add new authentication methods in the future.

## Security Considerations

1. **TLS Verification**: Enabled by default. Only disable for development/testing.
2. **Token Storage**: In-memory by default. Use keyring for persistence across sessions.
3. **Logging**: No sensitive data (tokens, secrets) is ever logged.
4. **Dependencies**: Minimal dependency footprint to reduce supply chain risk.

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/openshift/openshift-ai-auth.git
cd openshift-ai-auth

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests with coverage
pytest

# Run specific test file
pytest tests/test_config.py

# Run with verbose output
pytest -v

# Type checking
mypy src/openshift_ai_auth

# Code formatting
black src/ tests/
ruff check src/ tests/

# Security scanning
bandit -r src/
```

## Examples

See the [examples/](examples/) directory for complete examples:

- `auto_auth.py` - Simple auto-detection
- `oidc_device_flow.py` - CLI tool with device flow
- `oidc_auth_code.py` - Interactive browser-based auth
- `notebook_usage.py` - Jupyter notebook example
- `explicit_config.py` - All configuration options
- `custom_ca.py` - Custom CA certificate

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Support

- Issues: https://github.com/openshift/openshift-ai-auth/issues
- Documentation: https://github.com/openshift/openshift-ai-auth#readme

## Acknowledgments

This library wraps and extends the official [Kubernetes Python Client](https://github.com/kubernetes-client/python) to provide simplified authentication workflows for OpenShift AI and Kubernetes environments.
