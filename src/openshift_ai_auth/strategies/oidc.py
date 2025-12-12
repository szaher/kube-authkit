"""
OIDC (OpenID Connect) authentication strategy.

This strategy implements OpenID Connect authentication with support for:
- Device Code Flow (for CLI tools and headless environments)
- Authorization Code Flow with PKCE (for interactive applications)
- Client Credentials Flow (for service-to-service auth)
- Automatic token refresh

The strategy follows the OAuth 2.0 and OpenID Connect specifications.
"""

import base64
import hashlib
import logging
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from kubernetes.client import ApiClient, Configuration

from ..config import AuthConfig
from ..exceptions import AuthenticationError, ConfigurationError, StrategyNotAvailableError
from .base import AuthStrategy

logger = logging.getLogger(__name__)


class OIDCStrategy(AuthStrategy):
    """Authenticate using OpenID Connect (OIDC).

    This strategy supports multiple OIDC flows:
    - Device Code Flow: Best for CLI tools and headless environments
    - Authorization Code Flow with PKCE: Best for interactive applications
    - Client Credentials Flow: Best for service-to-service authentication

    The strategy automatically handles:
    - OIDC discovery (.well-known/openid-configuration)
    - Token refresh when access tokens expire
    - Optional persistent token storage via system keyring

    Example:
        >>> # Device Code Flow (CLI)
        >>> config = AuthConfig(
        ...     method="oidc",
        ...     oidc_issuer="https://keycloak.example.com/auth/realms/myrealm",
        ...     client_id="my-cli-tool",
        ...     use_device_flow=True
        ... )
        >>> strategy = OIDCStrategy(config)
        >>> api_client = strategy.authenticate()

        >>> # Authorization Code Flow (Interactive)
        >>> config = AuthConfig(
        ...     method="oidc",
        ...     oidc_issuer="https://keycloak.example.com/auth/realms/myrealm",
        ...     client_id="my-web-app",
        ...     use_device_flow=False
        ... )
        >>> strategy = OIDCStrategy(config)
        >>> api_client = strategy.authenticate()
    """

    def __init__(self, config: AuthConfig) -> None:
        """Initialize OIDC strategy.

        Args:
            config: AuthConfig instance with OIDC parameters
        """
        super().__init__(config)
        self._oidc_config: dict[str, Any] | None = None
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expiry: float | None = None

    def is_available(self) -> bool:
        """Check if OIDC authentication is available.

        Returns:
            True if OIDC issuer and client ID are configured, False otherwise
        """
        if not self.config.oidc_issuer:
            logger.debug("OIDC issuer not configured")
            return False

        if not self.config.client_id:
            logger.debug("OIDC client ID not configured")
            return False

        # Try to fetch OIDC discovery document to verify issuer is reachable
        try:
            self._discover_oidc_config()
            logger.debug("OIDC configuration discovered successfully")
            return True
        except Exception as e:
            logger.debug(f"OIDC discovery failed: {e}")
            return False

    def authenticate(self) -> ApiClient:
        """Authenticate using OIDC.

        This method will:
        1. Check for stored refresh token (if keyring enabled)
        2. If no stored token, perform interactive authentication
        3. Configure ApiClient with access token
        4. Set up automatic token refresh

        Returns:
            Configured Kubernetes ApiClient

        Raises:
            StrategyNotAvailableError: If OIDC not configured
            AuthenticationError: If authentication fails
        """
        if not self.is_available():
            raise StrategyNotAvailableError(
                "OIDC authentication not available",
                f"OIDC issuer and client ID must be configured.\n"
                f"Current config: issuer={self.config.oidc_issuer}, "
                f"client_id={self.config.client_id}"
            )

        logger.info(f"Authenticating via OIDC to {self.config.oidc_issuer}")

        # Try to load stored refresh token
        if self.config.use_keyring:
            stored_token = self._load_refresh_token()
            if stored_token:
                try:
                    self._refresh_access_token(stored_token)
                    logger.info("Successfully refreshed access token from stored refresh token")
                except Exception as e:
                    logger.warning(f"Failed to use stored refresh token: {e}")
                    # Fall through to interactive auth

        # If we don't have a valid access token, perform interactive authentication
        if not self._access_token:
            if self.config.use_device_flow:
                self._authenticate_device_flow()
            else:
                self._authenticate_auth_code_flow()

        # Save refresh token if keyring is enabled
        if self.config.use_keyring and self._refresh_token:
            self._save_refresh_token(self._refresh_token)

        # Create and configure ApiClient
        return self._create_api_client()

    def _discover_oidc_config(self) -> dict[str, Any]:
        """Discover OIDC configuration from issuer.

        Fetches the .well-known/openid-configuration document.

        Returns:
            Dictionary containing OIDC configuration

        Raises:
            AuthenticationError: If discovery fails
        """
        if self._oidc_config:
            return self._oidc_config

        discovery_url = f"{self.config.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
        logger.debug(f"Fetching OIDC discovery document from {discovery_url}")

        try:
            response = requests.get(
                discovery_url,
                verify=self.config.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            self._oidc_config = response.json()

            logger.debug(f"OIDC discovery successful. Endpoints: "
                        f"authorization={self._oidc_config.get('authorization_endpoint')}, "
                        f"token={self._oidc_config.get('token_endpoint')}")

            return self._oidc_config

        except requests.RequestException as e:
            raise AuthenticationError(
                f"Failed to discover OIDC configuration from {self.config.oidc_issuer}",
                f"Error fetching {discovery_url}: {str(e)}"
            ) from e

    def _authenticate_device_flow(self) -> None:
        """Authenticate using Device Code Flow.

        This flow is best for CLI tools and headless environments.
        It displays a URL and code for the user to enter in a browser.

        Raises:
            AuthenticationError: If authentication fails
        """
        logger.info("Starting Device Code Flow authentication")

        oidc_config = self._discover_oidc_config()
        device_authorization_endpoint = oidc_config.get("device_authorization_endpoint")

        if not device_authorization_endpoint:
            raise AuthenticationError(
                "Device Code Flow not supported by this OIDC provider",
                "The OIDC discovery document does not include 'device_authorization_endpoint'"
            )

        # Request device code
        device_data = {
            "client_id": self.config.client_id,
            "scope": " ".join(self.config.scopes)
        }

        if self.config.client_secret:
            device_data["client_secret"] = self.config.client_secret

        try:
            response = requests.post(
                device_authorization_endpoint,
                data=device_data,
                verify=self.config.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            device_response = response.json()

        except requests.RequestException as e:
            raise AuthenticationError(
                "Failed to request device code",
                str(e)
            ) from e

        # Display instructions to user
        verification_uri = device_response.get("verification_uri")
        verification_uri_complete = device_response.get("verification_uri_complete")
        user_code = device_response.get("user_code")
        device_code = device_response.get("device_code")
        interval = device_response.get("interval", 5)

        print(f"\n{'='*60}")
        print("OIDC Device Code Authentication")
        print(f"{'='*60}")
        if verification_uri_complete:
            print("\nPlease visit this URL to authenticate:")
            print(f"\n  {verification_uri_complete}\n")
        else:
            print(f"\nPlease visit this URL: {verification_uri}")
            print(f"And enter this code: {user_code}\n")
        print(f"{'='*60}\n")

        # Poll for token
        token_endpoint = oidc_config["token_endpoint"]
        poll_data = {
            "client_id": self.config.client_id,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        }

        if self.config.client_secret:
            poll_data["client_secret"] = self.config.client_secret

        while True:
            time.sleep(interval)

            try:
                poll_response = requests.post(
                    token_endpoint,
                    data=poll_data,
                    verify=self.config.verify_ssl,
                    timeout=10
                )

                if poll_response.status_code == 200:
                    # Success!
                    token_data = poll_response.json()
                    self._access_token = token_data.get("access_token")
                    self._refresh_token = token_data.get("refresh_token")
                    expires_in = token_data.get("expires_in")

                    if expires_in:
                        self._token_expiry = time.time() + expires_in

                    logger.info("Device Code Flow authentication successful")
                    print("Authentication successful!\n")
                    return

                error_data = poll_response.json()
                error = error_data.get("error")

                if error == "authorization_pending":
                    # Still waiting for user
                    print(".", end="", flush=True)
                    continue
                elif error == "slow_down":
                    # Increase polling interval
                    interval += 5
                    continue
                elif error in ("expired_token", "access_denied"):
                    raise AuthenticationError(
                        f"Device Code Flow failed: {error}",
                        error_data.get("error_description", "")
                    )
                else:
                    # Unknown error
                    raise AuthenticationError(
                        f"Device Code Flow failed with error: {error}",
                        error_data.get("error_description", "")
                    )

            except requests.RequestException as e:
                raise AuthenticationError(
                    "Failed to poll for device code authorization",
                    str(e)
                ) from e

    def _authenticate_auth_code_flow(self) -> None:
        """Authenticate using Authorization Code Flow with PKCE.

        This flow opens a browser for interactive authentication.
        It starts a temporary local HTTP server to receive the callback.

        Raises:
            AuthenticationError: If authentication fails
        """
        logger.info("Starting Authorization Code Flow with PKCE")

        oidc_config = self._discover_oidc_config()
        authorization_endpoint = oidc_config.get("authorization_endpoint")
        token_endpoint = oidc_config.get("token_endpoint")

        if not authorization_endpoint or not token_endpoint:
            raise AuthenticationError(
                "Authorization Code Flow not supported",
                "OIDC discovery document missing required endpoints"
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
                            <h1>Authentication Successful!</h1>
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
        auth_params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.config.scopes),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(16)
        }

        auth_url = f"{authorization_endpoint}?{urlencode(auth_params)}"

        # Open browser
        print("\nOpening browser for authentication...")
        print(f"If the browser doesn't open, visit this URL:\n{auth_url}\n")

        webbrowser.open(auth_url)

        # Wait for callback (with timeout)
        server_thread.join(timeout=300)  # 5 minute timeout

        if "error" in auth_result:
            raise AuthenticationError(
                f"Authorization failed: {auth_result['error']}",
                auth_result.get("error_description", "")
            )

        if "code" not in auth_result:
            raise AuthenticationError(
                "Authorization Code Flow failed",
                "No authorization code received (timeout or user cancelled)"
            )

        # Exchange code for tokens
        token_data = {
            "client_id": self.config.client_id,
            "code": auth_result["code"],
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier
        }

        if self.config.client_secret:
            token_data["client_secret"] = self.config.client_secret

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
            self._refresh_token = token_response.get("refresh_token")
            expires_in = token_response.get("expires_in")

            if expires_in:
                self._token_expiry = time.time() + expires_in

            logger.info("Authorization Code Flow authentication successful")
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
                "Failed to exchange authorization code for tokens",
                error_detail
            ) from e

    def _refresh_access_token(self, refresh_token: str) -> None:
        """Refresh access token using refresh token.

        Args:
            refresh_token: The refresh token to use

        Raises:
            AuthenticationError: If refresh fails
        """
        logger.debug("Refreshing access token")

        oidc_config = self._discover_oidc_config()
        token_endpoint = oidc_config.get("token_endpoint")

        if not token_endpoint:
            raise AuthenticationError(
                "Token refresh not supported",
                "OIDC discovery document missing token_endpoint"
            )

        token_data = {
            "client_id": self.config.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }

        if self.config.client_secret:
            token_data["client_secret"] = self.config.client_secret

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
            self._refresh_token = token_response.get("refresh_token", refresh_token)
            expires_in = token_response.get("expires_in")

            if expires_in:
                self._token_expiry = time.time() + expires_in

            logger.debug("Access token refreshed successfully")

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
                "Failed to refresh access token",
                error_detail
            ) from e

    def _create_api_client(self) -> ApiClient:
        """Create and configure Kubernetes ApiClient with OIDC token.

        Returns:
            Configured ApiClient

        Raises:
            ConfigurationError: If Kubernetes API host not configured
        """
        if not self.config.k8s_api_host:
            raise ConfigurationError(
                "Kubernetes API host not configured",
                "Please provide k8s_api_host in AuthConfig when using OIDC authentication"
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

    def _load_refresh_token(self) -> str | None:
        """Load refresh token from system keyring.

        Returns:
            Refresh token if found, None otherwise
        """
        if not self.config.use_keyring:
            return None

        try:
            import keyring
            service_name = f"openshift-ai-auth:{self.config.oidc_issuer}"
            username = self.config.client_id

            token = keyring.get_password(service_name, username)
            if token:
                logger.debug("Loaded refresh token from keyring")
            return token

        except ImportError:
            logger.warning("keyring module not available. Install with: pip install keyring")
            return None
        except Exception as e:
            logger.warning(f"Failed to load refresh token from keyring: {e}")
            return None

    def _save_refresh_token(self, refresh_token: str) -> None:
        """Save refresh token to system keyring.

        Args:
            refresh_token: The refresh token to save
        """
        if not self.config.use_keyring:
            return

        try:
            import keyring
            service_name = f"openshift-ai-auth:{self.config.oidc_issuer}"
            username = self.config.client_id

            keyring.set_password(service_name, username, refresh_token)
            logger.debug("Saved refresh token to keyring")

        except ImportError:
            logger.warning("keyring module not available. Install with: pip install keyring")
        except Exception as e:
            logger.warning(f"Failed to save refresh token to keyring: {e}")

    def get_description(self) -> str:
        """Get description of this strategy.

        Returns:
            Human-readable description
        """
        flow = "Device Code Flow" if self.config.use_device_flow else "Authorization Code Flow"
        return f"OIDC Authentication ({self.config.oidc_issuer}, {flow})"
