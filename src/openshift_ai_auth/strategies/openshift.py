"""
OpenShift OAuth authentication strategy.

This strategy implements OpenShift-specific OAuth authentication with support for:
- OpenShift OAuth Server discovery (/.well-known/oauth-authorization-server)
- Token request flow (similar to OIDC but with OpenShift specifics)
- WWW-Authenticate challenge handling
- OpenShift OAuth redirect flow
- Integration with openshift-challenging-client

OpenShift's OAuth implementation is similar to OIDC but has platform-specific
behaviors and endpoints.
"""

import base64
import hashlib
import logging
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from kubernetes.client import ApiClient, Configuration

from ..config import AuthConfig
from ..exceptions import (
    AuthenticationError,
    ConfigurationError,
    StrategyNotAvailableError,
)
from .base import AuthStrategy

logger = logging.getLogger(__name__)


class OpenShiftOAuthStrategy(AuthStrategy):
    """Authenticate using OpenShift OAuth.

    This strategy supports OpenShift's native OAuth implementation:
    - OAuth Server discovery via /.well-known/oauth-authorization-server
    - Authorization Code Flow with OpenShift-specific client
    - WWW-Authenticate challenge handling
    - Token request flow

    The strategy automatically handles:
    - OAuth server discovery
    - Token acquisition and refresh
    - Optional persistent token storage via system keyring

    Example:
        >>> # Auto-detect OpenShift cluster
        >>> config = AuthConfig(
        ...     method="openshift",
        ...     k8s_api_host="https://api.cluster.example.com:6443"
        ... )
        >>> strategy = OpenShiftOAuthStrategy(config)
        >>> api_client = strategy.authenticate()

        >>> # With explicit token
        >>> config = AuthConfig(
        ...     method="openshift",
        ...     k8s_api_host="https://api.cluster.example.com:6443",
        ...     openshift_token="sha256~..."
        ... )
        >>> strategy = OpenShiftOAuthStrategy(config)
        >>> api_client = strategy.authenticate()
    """

    def __init__(self, config: AuthConfig) -> None:
        """Initialize OpenShift OAuth strategy.

        Args:
            config: AuthConfig instance with OpenShift parameters
        """
        super().__init__(config)
        self._oauth_metadata: dict[str, Any] | None = None
        self._access_token: str | None = None

    def is_available(self) -> bool:
        """Check if OpenShift OAuth authentication is available.

        Returns:
            True if k8s_api_host is configured and OAuth server is reachable, False otherwise
        """
        if not self.config.k8s_api_host:
            logger.debug("OpenShift OAuth requires k8s_api_host")
            return False

        # Check for explicit token
        if self.config.openshift_token:
            logger.debug("OpenShift token provided explicitly")
            return True

        # Check environment variable
        if os.getenv("OPENSHIFT_TOKEN"):
            logger.debug("OpenShift token found in OPENSHIFT_TOKEN environment variable")
            return True

        # Try to discover OAuth server
        try:
            self._discover_oauth_metadata()
            logger.debug("OpenShift OAuth server discovered successfully")
            return True
        except Exception as e:
            logger.debug(f"OpenShift OAuth discovery failed: {e}")
            return False

    def authenticate(self) -> ApiClient:
        """Authenticate using OpenShift OAuth.

        This method will:
        1. Check for explicit token in config or environment
        2. If no token, perform interactive OAuth flow
        3. Configure ApiClient with token
        4. Optionally save token to keyring

        Returns:
            Configured Kubernetes ApiClient

        Raises:
            StrategyNotAvailableError: If OpenShift OAuth not configured
            AuthenticationError: If authentication fails
        """
        if not self.is_available():
            raise StrategyNotAvailableError(
                "OpenShift OAuth authentication not available",
                f"k8s_api_host must be configured and OAuth server must be reachable.\n"
                f"Current config: k8s_api_host={self.config.k8s_api_host}"
            )

        logger.info(f"Authenticating via OpenShift OAuth to {self.config.k8s_api_host}")

        # Check for explicit token
        if self.config.openshift_token:
            self._access_token = self.config.openshift_token
            logger.info("Using explicitly provided OpenShift token")
        elif os.getenv("OPENSHIFT_TOKEN"):
            self._access_token = os.getenv("OPENSHIFT_TOKEN")
            logger.info("Using OpenShift token from OPENSHIFT_TOKEN environment variable")
        else:
            # Try to load stored token
            if self.config.use_keyring:
                stored_token = self._load_token()
                if stored_token:
                    self._access_token = stored_token
                    logger.info("Using stored OpenShift token from keyring")

            # If we still don't have a token, perform interactive authentication
            if not self._access_token:
                self._authenticate_interactive()

        # Save token if keyring is enabled
        if self.config.use_keyring and self._access_token:
            self._save_token(self._access_token)

        # Create and configure ApiClient
        return self._create_api_client()

    def _discover_oauth_metadata(self) -> dict[str, Any]:
        """Discover OpenShift OAuth server metadata.

        Fetches the /.well-known/oauth-authorization-server document.

        Returns:
            Dictionary containing OAuth metadata

        Raises:
            AuthenticationError: If discovery fails
        """
        if self._oauth_metadata:
            return self._oauth_metadata

        # Construct discovery URL
        api_host = self.config.k8s_api_host.rstrip('/')
        discovery_url = f"{api_host}/.well-known/oauth-authorization-server"

        logger.debug(f"Fetching OpenShift OAuth metadata from {discovery_url}")

        try:
            response = requests.get(
                discovery_url,
                verify=self.config.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            self._oauth_metadata = response.json()

            logger.debug(f"OpenShift OAuth discovery successful. Endpoints: "
                        f"authorization={self._oauth_metadata.get('authorization_endpoint')}, "
                        f"token={self._oauth_metadata.get('token_endpoint')}")

            return self._oauth_metadata

        except requests.RequestException as e:
            raise AuthenticationError(
                f"Failed to discover OpenShift OAuth metadata from {self.config.k8s_api_host}",
                f"Error fetching {discovery_url}: {str(e)}"
            ) from e

    def _authenticate_interactive(self) -> None:
        """Authenticate using interactive OAuth flow.

        This flow opens a browser for interactive authentication.
        It starts a temporary local HTTP server to receive the callback.

        Raises:
            AuthenticationError: If authentication fails
        """
        logger.info("Starting OpenShift OAuth interactive flow")

        oauth_metadata = self._discover_oauth_metadata()
        authorization_endpoint = oauth_metadata.get("authorization_endpoint")
        token_endpoint = oauth_metadata.get("token_endpoint")

        if not authorization_endpoint or not token_endpoint:
            raise AuthenticationError(
                "OpenShift OAuth not properly configured",
                "OAuth metadata missing required endpoints"
            )

        # Generate PKCE challenge
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        # Start local callback server on configured port
        callback_port = self.config.oidc_callback_port
        redirect_uri = f"http://localhost:{callback_port}/callback"

        # Prepare to receive auth code
        auth_result = {}

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                """Handle OAuth callback."""
                parsed = urlparse(self.path)
                if parsed.path == "/callback":
                    params = parse_qs(parsed.query)

                    if "code" in params:
                        auth_result["code"] = params["code"][0]
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(b"""
                            <html><body>
                            <h1>OpenShift Authentication Successful!</h1>
                            <p>You can close this window and return to your application.</p>
                            </body></html>
                        """)
                    elif "error" in params:
                        auth_result["error"] = params["error"][0]
                        auth_result["error_description"] = params.get("error_description", [""])[0]
                        self.send_response(400)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(f"""
                            <html><body>
                            <h1>Authentication Failed</h1>
                            <p>Error: {auth_result['error']}</p>
                            <p>{auth_result.get('error_description', '')}</p>
                            </body></html>
                        """.encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                """Suppress server logs."""
                pass

        # Start server in background thread
        server = HTTPServer(("localhost", callback_port), CallbackHandler)
        server_thread = threading.Thread(target=server.handle_request, daemon=True)
        server_thread.start()

        # Build authorization URL
        # OpenShift uses 'openshift-browser-client' for browser-based flows
        auth_params = {
            "client_id": "openshift-browser-client",
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(16)
        }

        auth_url = f"{authorization_endpoint}?{urlencode(auth_params)}"

        # Open browser
        print("\nOpening browser for OpenShift authentication...")
        print(f"If the browser doesn't open, visit this URL:\n{auth_url}\n")

        webbrowser.open(auth_url)

        # Wait for callback (with timeout)
        server_thread.join(timeout=300)  # 5 minute timeout

        if "error" in auth_result:
            raise AuthenticationError(
                f"OpenShift OAuth failed: {auth_result['error']}",
                auth_result.get("error_description", "")
            )

        if "code" not in auth_result:
            raise AuthenticationError(
                "OpenShift OAuth failed",
                "No authorization code received (timeout or user cancelled)"
            )

        # Exchange code for token
        token_data = {
            "client_id": "openshift-browser-client",
            "code": auth_result["code"],
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier
        }

        try:
            response = requests.post(
                token_endpoint,
                data=token_data,
                verify=self.config.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            token_response = response.json()

            self._access_token = token_response.get("access_token")

            if not self._access_token:
                raise AuthenticationError(
                    "OpenShift OAuth failed",
                    "No access token in response"
                )

            logger.info("OpenShift OAuth authentication successful")
            print("Authentication successful!\n")

        except requests.RequestException as e:
            # Try to extract OAuth error details from response
            error_detail = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    error_type = error_data.get("error", "unknown_error")
                    error_desc = error_data.get("error_description", "")
                    error_detail = f"{error_type}: {error_desc}" if error_desc else error_type
                except Exception:
                    # If we can't parse JSON, use the original error
                    pass

            raise AuthenticationError(
                "Failed to exchange authorization code for token",
                error_detail
            ) from e

    def _create_api_client(self) -> ApiClient:
        """Create and configure Kubernetes ApiClient with OpenShift token.

        Returns:
            Configured ApiClient

        Raises:
            ConfigurationError: If Kubernetes API host not configured
        """
        if not self.config.k8s_api_host:
            raise ConfigurationError(
                "Kubernetes API host not configured",
                "Please provide k8s_api_host in AuthConfig when using OpenShift OAuth"
            )

        # Create configuration
        configuration = Configuration()
        configuration.host = self.config.k8s_api_host
        configuration.api_key = {"authorization": f"Bearer {self._access_token}"}
        configuration.verify_ssl = self.config.verify_ssl

        if self.config.ca_cert:
            configuration.ssl_ca_cert = self.config.ca_cert

        # Create ApiClient
        api_client = ApiClient(configuration)

        logger.info(f"Created ApiClient for {configuration.host}")
        return api_client

    def _load_token(self) -> str | None:
        """Load token from system keyring.

        Returns:
            Token if found, None otherwise
        """
        if not self.config.use_keyring:
            return None

        try:
            import keyring
            service_name = f"openshift-ai-auth:{self.config.k8s_api_host}"
            username = "openshift-token"

            token = keyring.get_password(service_name, username)
            if token:
                logger.debug("Loaded OpenShift token from keyring")
            return token

        except ImportError:
            logger.warning("keyring module not available. Install with: pip install keyring")
            return None
        except Exception as e:
            logger.warning(f"Failed to load token from keyring: {e}")
            return None

    def _save_token(self, token: str) -> None:
        """Save token to system keyring.

        Args:
            token: The token to save
        """
        if not self.config.use_keyring:
            return

        try:
            import keyring
            service_name = f"openshift-ai-auth:{self.config.k8s_api_host}"
            username = "openshift-token"

            keyring.set_password(service_name, username, token)
            logger.debug("Saved OpenShift token to keyring")

        except ImportError:
            logger.warning("keyring module not available. Install with: pip install keyring")
        except Exception as e:
            logger.warning(f"Failed to save token to keyring: {e}")

    def get_description(self) -> str:
        """Get description of this strategy.

        Returns:
            Human-readable description
        """
        return f"OpenShift OAuth ({self.config.k8s_api_host})"
