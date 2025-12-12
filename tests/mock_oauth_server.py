"""
Mock OAuth/OIDC server for integration testing.

This mock server implements the minimum OAuth/OIDC endpoints needed for testing:
- /.well-known/openid-configuration (discovery)
- /authorize (authorization endpoint)
- /token (token endpoint)
- /device/code (device authorization endpoint)

It can run as a fixture in pytest for automated testing.
"""

import base64
import hashlib
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse


class MockOAuthServer:
    """Mock OAuth/OIDC server for testing."""

    def __init__(self, host: str = "localhost", port: int = 9999):
        """Initialize mock server.

        Args:
            host: Host to bind to
            port: Port to bind to
        """
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.base_url = f"http://{host}:{port}"

        # Storage for active flows
        self.auth_codes: dict[str, dict[str, Any]] = {}
        self.device_codes: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, dict[str, Any]] = {}

        # Configuration
        self.issuer = self.base_url
        self.client_id = "test-client"
        self.client_secret = "test-secret"
        self.auto_approve = True  # Auto-approve auth requests for testing

    def start(self):
        """Start the mock server in a background thread."""
        handler = self._create_handler()
        self.server = HTTPServer((self.host, self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # Give server time to start
        time.sleep(0.1)

    def stop(self):
        """Stop the mock server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)

    def _create_handler(self):
        """Create request handler with access to server state."""
        server = self

        class MockOAuthHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                """Suppress request logs."""
                pass

            def do_GET(self):
                """Handle GET requests."""
                parsed = urlparse(self.path)
                path = parsed.path
                params = parse_qs(parsed.query)

                if path == "/.well-known/openid-configuration":
                    self._handle_discovery()
                elif path == "/authorize":
                    self._handle_authorize(params)
                elif path == "/.well-known/oauth-authorization-server":
                    # OpenShift-style discovery
                    self._handle_openshift_discovery()
                else:
                    self._send_error(404, "Not Found")

            def do_POST(self):
                """Handle POST requests."""
                parsed = urlparse(self.path)
                path = parsed.path

                # Parse form data
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8')
                params = parse_qs(body)

                if path == "/token":
                    self._handle_token(params)
                elif path == "/device/code":
                    self._handle_device_code(params)
                else:
                    self._send_error(404, "Not Found")

            def _handle_discovery(self):
                """Handle OIDC discovery request."""
                discovery = {
                    "issuer": server.issuer,
                    "authorization_endpoint": f"{server.base_url}/authorize",
                    "token_endpoint": f"{server.base_url}/token",
                    "device_authorization_endpoint": f"{server.base_url}/device/code",
                    "userinfo_endpoint": f"{server.base_url}/userinfo",
                    "jwks_uri": f"{server.base_url}/jwks",
                    "response_types_supported": ["code", "token"],
                    "grant_types_supported": [
                        "authorization_code",
                        "refresh_token",
                        "urn:ietf:params:oauth:grant-type:device_code"
                    ],
                    "code_challenge_methods_supported": ["S256"],
                }
                self._send_json(200, discovery)

            def _handle_openshift_discovery(self):
                """Handle OpenShift OAuth discovery request."""
                discovery = {
                    "issuer": server.issuer,
                    "authorization_endpoint": f"{server.base_url}/authorize",
                    "token_endpoint": f"{server.base_url}/token",
                }
                self._send_json(200, discovery)

            def _handle_authorize(self, params: dict[str, list]):
                """Handle authorization request."""
                client_id = params.get("client_id", [""])[0]
                redirect_uri = params.get("redirect_uri", [""])[0]
                state = params.get("state", [""])[0]
                code_challenge = params.get("code_challenge", [""])[0]
                code_challenge_method = params.get("code_challenge_method", ["S256"])[0]

                if not client_id or not redirect_uri:
                    self._send_error(400, "Missing required parameters")
                    return

                if server.auto_approve:
                    # Auto-approve and generate auth code
                    auth_code = secrets.token_urlsafe(32)
                    server.auth_codes[auth_code] = {
                        "client_id": client_id,
                        "redirect_uri": redirect_uri,
                        "code_challenge": code_challenge,
                        "code_challenge_method": code_challenge_method,
                        "expires": time.time() + 600  # 10 minutes
                    }

                    # Redirect back with code
                    redirect_params = {"code": auth_code}
                    if state:
                        redirect_params["state"] = state

                    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
                    self.send_response(302)
                    self.send_header("Location", redirect_url)
                    self.end_headers()
                else:
                    # Return approval page (for manual testing)
                    self._send_html(200, "<h1>Approval Page</h1><p>Auto-approve is disabled</p>")

            def _handle_token(self, params: dict[str, list]):
                """Handle token endpoint requests."""
                grant_type = params.get("grant_type", [""])[0]
                client_id = params.get("client_id", [""])[0]

                if grant_type == "authorization_code":
                    self._handle_token_auth_code(params, client_id)
                elif grant_type == "refresh_token":
                    self._handle_token_refresh(params, client_id)
                elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
                    self._handle_token_device_code(params, client_id)
                else:
                    self._send_json(400, {
                        "error": "unsupported_grant_type",
                        "error_description": f"Grant type '{grant_type}' is not supported"
                    })

            def _handle_token_auth_code(self, params: dict[str, list], client_id: str):
                """Handle authorization code grant."""
                code = params.get("code", [""])[0]
                params.get("redirect_uri", [""])[0]
                code_verifier = params.get("code_verifier", [""])[0]

                # Validate auth code
                if code not in server.auth_codes:
                    self._send_json(401, {
                        "error": "invalid_grant",
                        "error_description": "Authorization code is invalid or expired"
                    })
                    return

                auth_data = server.auth_codes[code]

                # Check expiration
                if time.time() > auth_data["expires"]:
                    del server.auth_codes[code]
                    self._send_json(401, {
                        "error": "invalid_grant",
                        "error_description": "Authorization code has expired"
                    })
                    return

                # Validate PKCE if present
                if auth_data.get("code_challenge"):
                    if not code_verifier:
                        self._send_json(401, {
                            "error": "invalid_request",
                            "error_description": "code_verifier is required for PKCE"
                        })
                        return

                    # Verify PKCE challenge
                    challenge = base64.urlsafe_b64encode(
                        hashlib.sha256(code_verifier.encode('utf-8')).digest()
                    ).decode('utf-8').rstrip('=')

                    if challenge != auth_data["code_challenge"]:
                        self._send_json(401, {
                            "error": "invalid_grant",
                            "error_description": "PKCE verification failed"
                        })
                        return

                # Generate tokens
                access_token = f"access_{secrets.token_urlsafe(32)}"
                refresh_token = f"refresh_{secrets.token_urlsafe(32)}"

                server.tokens[access_token] = {
                    "client_id": client_id,
                    "expires": time.time() + 3600  # 1 hour
                }
                server.tokens[refresh_token] = {
                    "client_id": client_id,
                    "type": "refresh"
                }

                # Clean up used auth code
                del server.auth_codes[code]

                # Return tokens
                self._send_json(200, {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": refresh_token,
                    "scope": "openid profile email"
                })

            def _handle_token_refresh(self, params: dict[str, list], client_id: str):
                """Handle refresh token grant."""
                refresh_token = params.get("refresh_token", [""])[0]

                if refresh_token not in server.tokens:
                    self._send_json(401, {
                        "error": "invalid_grant",
                        "error_description": "Refresh token is invalid"
                    })
                    return

                # Generate new access token
                access_token = f"access_{secrets.token_urlsafe(32)}"
                server.tokens[access_token] = {
                    "client_id": client_id,
                    "expires": time.time() + 3600
                }

                self._send_json(200, {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": refresh_token,
                    "scope": "openid profile email"
                })

            def _handle_device_code(self, params: dict[str, list]):
                """Handle device code request."""
                client_id = params.get("client_id", [""])[0]

                device_code = f"device_{secrets.token_urlsafe(32)}"
                user_code = secrets.token_hex(4).upper()

                server.device_codes[device_code] = {
                    "client_id": client_id,
                    "user_code": user_code,
                    "status": "pending" if not server.auto_approve else "approved",
                    "expires": time.time() + 600
                }

                self._send_json(200, {
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_uri": f"{server.base_url}/device",
                    "verification_uri_complete": f"{server.base_url}/device?user_code={user_code}",
                    "expires_in": 600,
                    "interval": 1  # Fast polling for tests
                })

            def _handle_token_device_code(self, params: dict[str, list], client_id: str):
                """Handle device code token request (polling)."""
                device_code = params.get("device_code", [""])[0]

                if device_code not in server.device_codes:
                    self._send_json(400, {
                        "error": "invalid_grant",
                        "error_description": "Device code is invalid"
                    })
                    return

                device_data = server.device_codes[device_code]

                # Check expiration
                if time.time() > device_data["expires"]:
                    del server.device_codes[device_code]
                    self._send_json(400, {
                        "error": "expired_token",
                        "error_description": "Device code has expired"
                    })
                    return

                # Check status
                if device_data["status"] == "pending":
                    self._send_json(400, {
                        "error": "authorization_pending",
                        "error_description": "User has not yet approved the request"
                    })
                    return
                elif device_data["status"] == "denied":
                    self._send_json(400, {
                        "error": "access_denied",
                        "error_description": "User denied the request"
                    })
                    return

                # Approved - generate tokens
                access_token = f"access_{secrets.token_urlsafe(32)}"
                refresh_token = f"refresh_{secrets.token_urlsafe(32)}"

                server.tokens[access_token] = {
                    "client_id": client_id,
                    "expires": time.time() + 3600
                }
                server.tokens[refresh_token] = {
                    "client_id": client_id,
                    "type": "refresh"
                }

                # Clean up device code
                del server.device_codes[device_code]

                self._send_json(200, {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": refresh_token,
                    "scope": "openid profile email"
                })

            def _send_json(self, status: int, data: dict):
                """Send JSON response."""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def _send_html(self, status: int, html: str):
                """Send HTML response."""
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html.encode())

            def _send_error(self, status: int, message: str):
                """Send error response."""
                self.send_response(status)
                self.end_headers()
                self.wfile.write(message.encode())

        return MockOAuthHandler
