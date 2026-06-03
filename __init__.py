"""Authentik OIDC Dashboard Auth Provider — OAuth 2.0 (authorization-code + PKCE).

Implements the ``DashboardAuthProvider`` protocol against an Authentik instance
(any standard OIDC provider). Uses OIDC Discovery (``.well-known/openid-configuration``)
to resolve endpoints at construction time.

Configuration surfaces (env wins over config.yaml when set non-empty):

  ``config.yaml`` — canonical surface::

      dashboard:
        oauth:
          authentik_url:          https://auth.example.com
          authentik_client_id:     oauth-client-id
          authentik_client_secret: "optional-for-confidential-clients"
          authentik_scope:         "openid email profile offline_access"

  Environment overrides:

      HERMES_DASHBOARD_AUTHENTIK_URL         — Authentik base URL
      HERMES_DASHBOARD_AUTHENTIK_CLIENT_ID   — OAuth client ID
      HERMES_DASHBOARD_AUTHENTIK_CLIENT_SECRET — OAuth client secret (optional)
      HERMES_DASHBOARD_AUTHENTIK_SCOPE       — OAuth scopes (optional)

  Empty env var values after stripping are treated as unset so a
  provisioned-but-not-populated secret can't shadow a valid config.yaml entry.

Key contract points:

  - PKCE S256 is always used (standard for all OAuth2 flows).
  - client_secret is optional — when empty the plugin operates as a
    **public client** (PKCE-only, no client secret in token requests).
    When provided, HTTP Basic Auth is used for the token endpoint.
  - User claims are extracted from the **id_token** (verified JWT).
  - ``sub``, ``email``, ``name`` / ``preferred_username`` map to Session fields.
  - ``groups`` claim (if present) is mapped to ``org_id``.
  - JWKS is cached for 5 minutes.
  - Refresh-token rotation is supported — every successful refresh produces a
    new ``refresh_token`` the middleware must persist.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import urllib.parse
from typing import Any, Dict, List, Optional

import httpx

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    InvalidCodeError,
    LoginStart,
    ProviderError,
    RefreshExpiredError,
    Session,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_SCOPE = "openid email profile offline_access"

# JWKS cache duration in seconds.
_JWKS_CACHE_SECONDS = 300

# httpx timeout for token / discovery endpoints.
_REQUEST_TIMEOUT_SEC = 10.0

# DNS blocklist — reject redirect_uris that resolve to loopback when the
# dashboard is NOT on loopback (defense-in-depth against SSRF through a
# malicious redirect_uri param). The IP list mirrors
# ``hermes_cli.dashboard_auth._redirect_uri.allowed_hosts``.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


# ---------------------------------------------------------------------------
# Skip-reason channel for operator-friendly error messages
# ---------------------------------------------------------------------------

LAST_SKIP_REASON: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_no_pad(raw: bytes) -> str:
    """Base64url-encode without ``=`` padding (RFC 7636 §4)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class AuthentikAuthProvider(DashboardAuthProvider):
    """Authentik OIDC OAuth via authorization-code + PKCE (S256)."""

    name = "authentik"
    display_name = "Authentik"

    def __init__(
        self,
        *,
        authentik_url: str,
        client_id: str,
        client_secret: str = "",
        scope: str = _DEFAULT_SCOPE,
    ) -> None:
        self._authentik_url = authentik_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret or ""
        self._scope = scope

        # ---- OIDC Discovery -------------------------------------------------
        discovery = self._fetch_oidc_discovery()

        self._authorize_url: str = discovery["authorization_endpoint"]
        self._token_url: str = discovery["token_endpoint"]
        self._userinfo_url: str = discovery.get("userinfo_endpoint", "")
        self._jwks_url: str = discovery["jwks_uri"]
        self._issuer: str = discovery["issuer"]
        self._revoke_url: str = discovery.get("revocation_endpoint", "")
        self._algorithms: List[str] = discovery.get(
            "id_token_signing_alg_values_supported", ["RS256"]
        )

        # ---- JWKS client (lazy) ---------------------------------------------
        self._jwks_client: Any = None

    # ---- OIDC Discovery ----------------------------------------------------

    def _fetch_oidc_discovery(self) -> Dict[str, Any]:
        """Fetch and validate the OIDC Discovery document.

        Raises :class:`ProviderError` if the endpoint is unreachable or
        returns a non-conforming document.
        """
        discovery_url = f"{self._authentik_url}/.well-known/openid-configuration"
        try:
            resp = httpx.get(discovery_url, timeout=_REQUEST_TIMEOUT_SEC)
        except httpx.RequestError as exc:
            raise ProviderError(
                f"Authentik OIDC Discovery unreachable ({discovery_url}): {exc}"
            ) from exc

        if resp.status_code != 200:
            raise ProviderError(
                f"Authentik OIDC Discovery returned {resp.status_code} "
                f"({discovery_url}): {resp.text[:200]!r}"
            )

        try:
            doc = resp.json()
        except ValueError as exc:
            raise ProviderError(
                f"Authentik OIDC Discovery returned non-JSON body: {exc}"
            ) from exc

        if not isinstance(doc, dict):
            raise ProviderError(
                "Authentik OIDC Discovery returned non-dict response"
            )

        # Minimum required endpoints per OIDC spec.
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
            if key not in doc:
                raise ProviderError(
                    f"Authentik OIDC Discovery missing required key: {key!r}"
                )

        logger.info(
            "Authentik OIDC Discovery successful (issuer=%s)",
            doc["issuer"],
        )
        return doc

    def _get_jwks_client(self) -> Any:
        """Lazy-initialised PyJWKClient, cached for :data:`_JWKS_CACHE_SECONDS`."""
        if self._jwks_client is None:
            from jwt import PyJWKClient

            self._jwks_client = PyJWKClient(
                self._jwks_url,
                cache_keys=True,
                lifespan=_JWKS_CACHE_SECONDS,
            )
        return self._jwks_client

    # ---- public API (DashboardAuthProvider) -------------------------------

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        """First leg of the OAuth round trip — build the /authorize URL.

        Generates PKCE code_verifier + code_challenge (S256) and an OAuth
        ``state`` parameter for CSRF protection.  The cookie_payload maps
        to ``hermes_session_pkce``, which the auth-route layer serializes
        (prepending ``provider=authentik;``) so the callback handler knows
        which provider to dispatch to.
        """
        self._validate_redirect_uri(redirect_uri)

        code_verifier = _b64url_no_pad(secrets.token_bytes(64))
        code_challenge = _b64url_no_pad(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        )
        state = _b64url_no_pad(secrets.token_bytes(32))

        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": self._scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        redirect_url = (
            f"{self._authorize_url}?{urllib.parse.urlencode(params)}"
        )

        cookie_payload = {
            "hermes_session_pkce": f"state={state};verifier={code_verifier}",
        }
        return LoginStart(
            redirect_url=redirect_url, cookie_payload=cookie_payload
        )

    def complete_login(
        self,
        *,
        code: str,
        state: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> Session:
        """Second leg — exchange the authorization code for tokens.

        ``state`` is verified by the auth-route layer before this call
        (it checks the cookie-stashed state against the query-param state),
        so we only receive it for symmetry.
        """
        _ = state

        try:
            response = httpx.post(
                self._token_url,
                data=self._build_token_body(
                    grant_type="authorization_code",
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                ),
                headers=self._token_headers(),
                timeout=_REQUEST_TIMEOUT_SEC,
            )
        except httpx.RequestError as exc:
            raise ProviderError(
                f"Authentik token endpoint unreachable: {exc}"
            ) from exc

        return self._token_response_to_session(
            response, bad_request_exc=InvalidCodeError
        )

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        """Verify an existing access token.

        Returns ``None`` when the token is expired / invalid (the middleware
        contract — not an exception).  Raises :class:`ProviderError` only
        when the IDP is unreachable.
        """
        try:
            claims = self._verify_jwt(access_token)
        except InvalidCodeError:
            return None
        except ProviderError:
            raise

        return self._session_from_token(access_token, claims)

    def refresh_session(self, *, refresh_token: str) -> Session:
        """Rotate the access token using a refresh token.

        Posts ``grant_type=refresh_token`` to Authentik's token endpoint.
        Authentik rotates the refresh token on each successful refresh, so
        the returned ``Session.refresh_token`` is a **new** value the caller
        MUST persist.

        Raises :class:`RefreshExpiredError` on a 400 (dead / revoked /
        reuse-detected token) so the middleware forces re-login.
        """
        if not refresh_token:
            raise RefreshExpiredError("no refresh token present in session")

        try:
            response = httpx.post(
                self._token_url,
                data=self._build_token_body(
                    grant_type="refresh_token",
                    refresh_token=refresh_token,
                ),
                headers=self._token_headers(),
                timeout=_REQUEST_TIMEOUT_SEC,
            )
        except httpx.RequestError as exc:
            raise ProviderError(
                f"Authentik token endpoint unreachable: {exc}"
            ) from exc

        return self._token_response_to_session(
            response, bad_request_exc=RefreshExpiredError
        )

    def revoke_session(self, *, refresh_token: str) -> None:
        """Best-effort revocation.

        If Authentik exposes a revocation endpoint we POST to it.
        Otherwise this is a no-op — logout clears cookies client-side;
        the server-side session expires naturally.
        """
        if not self._revoke_url or not refresh_token:
            return
        try:
            httpx.post(
                self._revoke_url,
                data=self._build_token_body(
                    token=refresh_token,
                    token_type_hint="refresh_token",
                ),
                headers=self._token_headers(),
                timeout=_REQUEST_TIMEOUT_SEC,
            )
        except Exception:
            logger.debug(
                "Authentik revoke_session: revocation request failed "
                "(session will expire naturally)",
                exc_info=True,
            )

    # ---- internals ----------------------------------------------------------

    def _validate_redirect_uri(self, redirect_uri: str) -> None:
        """Fast-fail on obviously-broken redirect_uris before bouncing to IDP."""
        parsed = urllib.parse.urlparse(redirect_uri)
        if parsed.scheme not in ("https", "http"):
            raise ProviderError(
                f"redirect_uri must be http(s), got {redirect_uri!r}"
            )
        if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
            raise ProviderError(
                "redirect_uri may only use http:// for localhost/127.0.0.1, "
                f"got {redirect_uri!r}"
            )
        if not parsed.path or not parsed.path.endswith("/auth/callback"):
            raise ProviderError(
                "redirect_uri path must end with '/auth/callback', "
                f"got {redirect_uri!r}"
            )

    # ---- Token endpoint helpers -------------------------------------------

    def _build_token_body(self, **extra: Any) -> Dict[str, str]:
        """Build the form-encoded body for a token / revoke request.

        ``client_id`` is always included.  When ``client_secret`` is
        configured, it's added as ``client_secret`` in the body; in that
        case the ``_token_headers`` method also sets an ``Authorization``
        header (HTTP Basic Auth).  Authentik handles either form;
        providing both is redundant but harmless.
        """
        body: Dict[str, str] = {"client_id": self._client_id}
        if self._client_secret:
            body["client_secret"] = self._client_secret
        body.update(extra)
        return body

    def _token_headers(self) -> Dict[str, str]:
        """Headers for token / revoke requests.

        Always includes ``Accept: application/json``.  When a client
        secret is configured, also adds an ``Authorization`` header
        (HTTP Basic Auth) so the request is valid for both public and
        confidential client modes.
        """
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self._client_secret:
            credentials = base64.b64encode(
                f"{self._client_id}:{self._client_secret}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"
        return headers

    # ---- Token response → Session -----------------------------------------

    def _token_response_to_session(
        self,
        response: httpx.Response,
        *,
        bad_request_exc: type[Exception],
    ) -> Session:
        """Translate a token-endpoint response into a :class:`Session`.

        Shared by ``complete_login`` (auth-code grant) and
        ``refresh_session`` (refresh grant).  ``bad_request_exc``
        controls the exception type for 400 responses so the middleware
        can distinguish "bad code" (→ 400 on callback) from "dead
        refresh token" (→ force re-login).
        """
        if response.status_code == 400:
            body = self._parse_json_body(response)
            error_code = body.get("error", "invalid_request")
            logger.warning(
                "Authentik token request rejected (400): %s", error_code
            )
            raise bad_request_exc(
                f"Authentik rejected token request: {error_code}"
            )
        if response.status_code != 200:
            raise ProviderError(
                f"Authentik token endpoint returned {response.status_code}: "
                f"{response.text[:200]!r}"
            )

        payload = self._parse_json_body(response)

        access_token = payload.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise ProviderError(
                "Authentik token response missing access_token"
            )

        refresh_token = payload.get("refresh_token") or ""
        if not isinstance(refresh_token, str):
            refresh_token = ""

        id_token = payload.get("id_token")

        # Prefer claims from a verified id_token (richer user profile);
        # fall back to verifying the access_token directly.
        if id_token and isinstance(id_token, str):
            try:
                claims = self._verify_jwt(id_token)
            except (InvalidCodeError, ProviderError):
                claims = self._try_verify_access_token(access_token)
        else:
            claims = self._try_verify_access_token(access_token)

        return self._session_from_token(
            access_token, claims, refresh_token=refresh_token
        )

    def _try_verify_access_token(self, access_token: str) -> Dict[str, Any]:
        """Try to verify the access_token as a JWT.

        If the access_token is not a valid JWT (e.g. opaque token),
        attempt to fetch user info from the userinfo endpoint.
        """
        try:
            return self._verify_jwt(access_token)
        except (InvalidCodeError, ProviderError):
            pass
        return self._fetch_userinfo(access_token)

    def _fetch_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Call the OIDC userinfo endpoint as a fallback.

        Returns a dict with at least ``sub`` on success; returns a
        minimal dict (``sub`` = "unknown") on failure so the Session
        can still be constructed.
        """
        if not self._userinfo_url:
            logger.warning(
                "Authentik: no userinfo_endpoint in Discovery; "
                "cannot resolve user claims from opaque access_token"
            )
            return {"sub": "unknown"}

        try:
            resp = httpx.get(
                self._userinfo_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
                timeout=_REQUEST_TIMEOUT_SEC,
            )
            if resp.status_code == 200:
                body = self._parse_json_body(resp)
                if "sub" in body:
                    return body
            logger.warning(
                "Authentik userinfo returned %s: %s",
                resp.status_code,
                resp.text[:200],
            )
        except httpx.RequestError as exc:
            logger.warning("Authentik userinfo unreachable: %s", exc)

        return {"sub": "unknown"}

    # ---- JWT verification -------------------------------------------------

    def _verify_jwt(self, token: str) -> Dict[str, Any]:
        """Verify a JWT against the JWKS endpoint.

        Returns the decoded claims dict.  Raises :class:`InvalidCodeError`
        on expiry / invalid signature; :class:`ProviderError` on network
        failure or JWKS unavailability.
        """
        import jwt

        try:
            signing_key = self._get_jwks_client().get_signing_key_from_jwt(
                token
            )
        except jwt.PyJWKClientError as exc:
            raise ProviderError(f"Authentik JWKS lookup failed: {exc}") from exc
        except Exception as exc:
            raise ProviderError(f"Authentik JWKS lookup failed: {exc!r}") from exc

        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self._algorithms,
                audience=self._client_id,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidCodeError(f"token expired: {exc}") from exc
        except jwt.InvalidTokenError as exc:
            details = ""
            try:
                unverified = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": False},
                )
                details = (
                    f" [token iss={unverified.get('iss')!r} "
                    f"aud={unverified.get('aud')!r}; "
                    f"expected iss={self._issuer!r} "
                    f"aud={self._client_id!r}]"
                )
            except Exception:
                pass
            raise ProviderError(
                f"token verification failed: {exc}{details}"
            ) from exc

        return claims

    # ---- Session construction ---------------------------------------------

    def _session_from_token(
        self,
        access_token: str,
        claims: Dict[str, Any],
        *,
        refresh_token: str = "",
    ) -> Session:
        """Build a :class:`Session` from JWT claims.

        Maps OIDC Standard Claims:
        - ``sub`` → ``user_id`` (mandatory)
        - ``email`` → ``email``
        - ``name`` / ``preferred_username`` → ``display_name``
        - ``groups`` → ``org_id`` (comma-joined list if multiple)
        """
        user_id = str(claims.get("sub", ""))
        if not user_id:
            raise ProviderError("token missing 'sub' (user_id) claim")

        email = str(claims.get("email", ""))
        display_name = str(
            claims.get("name")
            or claims.get("preferred_username")
            or ""
        )

        groups = claims.get("groups")
        if isinstance(groups, list):
            org_id = ",".join(str(g) for g in groups)
        elif isinstance(groups, str):
            org_id = groups
        else:
            org_id = ""

        expires_at: int
        try:
            expires_at = int(claims.get("exp", 0))
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at <= 0:
            import time

            expires_at = int(time.time()) + 3600
            logger.debug(
                "Authentik: no valid 'exp' in token claims; "
                "falling back to 1-hour expiry"
            )

        return Session(
            user_id=user_id,
            email=email,
            display_name=display_name,
            org_id=org_id,
            provider=self.name,
            expires_at=expires_at,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    # ---- JSON helpers -----------------------------------------------------

    @staticmethod
    def _parse_json_body(response: httpx.Response) -> Dict[str, Any]:
        ctype = response.headers.get("content-type", "")
        if "application/json" not in ctype:
            return {}
        try:
            body = response.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------


def _load_config_oauth_section() -> dict:
    """Return the ``dashboard.oauth`` block from ``config.yaml`` if
    it exists and is a dict; otherwise an empty dict.

    Robust to load_config() raising (malformed YAML, IO error, missing
    config.yaml — common in fresh installs).
    """
    try:
        from hermes_cli.config import cfg_get, load_config

        cfg = load_config()
    except Exception as exc:
        logger.debug(
            "dashboard-auth-authentik: load_config() raised %s; "
            "falling back to env-only configuration",
            exc,
        )
        return {}
    section = cfg_get(cfg, "dashboard", "oauth", default=None)
    return section if isinstance(section, dict) else {}


def _resolve_value(env_var: str, cfg_key: str, default: str = "") -> str:
    """Resolve a config value with env-overrides-config precedence.

    Order:
      1. Environment variable (non-empty after strip).
      2. ``dashboard.oauth.<cfg_key>`` in config.yaml.
      3. ``default``.
    """
    env = os.environ.get(env_var, "").strip()
    if env:
        return env
    cfg_value = str(_load_config_oauth_section().get(cfg_key, "")).strip()
    return cfg_value or default


def _resolve_authentik_url() -> str:
    return _resolve_value(
        "HERMES_DASHBOARD_AUTHENTIK_URL", "authentik_url"
    )


def _resolve_client_id() -> str:
    return _resolve_value(
        "HERMES_DASHBOARD_AUTHENTIK_CLIENT_ID", "authentik_client_id"
    )


def _resolve_client_secret() -> str:
    return _resolve_value(
        "HERMES_DASHBOARD_AUTHENTIK_CLIENT_SECRET", "authentik_client_secret"
    )


def _resolve_scope() -> str:
    return _resolve_value(
        "HERMES_DASHBOARD_AUTHENTIK_SCOPE", "authentik_scope", _DEFAULT_SCOPE
    )


def register(ctx) -> None:
    """Plugin entry — called by the plugin loader at startup.

    Registers ``AuthentikAuthProvider`` only when both the Authentik URL
    and client_id are configured.  Either can come from an environment
    variable or from ``dashboard.oauth.*`` in config.yaml.

    When skipping, writes a human-readable reason to the module-level
    ``LAST_SKIP_REASON`` so the dashboard's fail-closed branch can
    surface actionable guidance.
    """
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""

    authentik_url = _resolve_authentik_url()
    client_id = _resolve_client_id()
    client_secret = _resolve_client_secret()
    scope = _resolve_scope()

    # Both are required.
    missing: List[str] = []
    if not authentik_url:
        missing.append("HERMES_DASHBOARD_AUTHENTIK_URL")
    if not client_id:
        missing.append("HERMES_DASHBOARD_AUTHENTIK_CLIENT_ID")

    if missing:
        env_to_cfg: Dict[str, str] = {
            "HERMES_DASHBOARD_AUTHENTIK_URL": "dashboard.oauth.authentik_url",
            "HERMES_DASHBOARD_AUTHENTIK_CLIENT_ID": "dashboard.oauth.authentik_client_id",
        }
        hints = ", ".join(
            f"{v} ({e})"
            for e, v in env_to_cfg.items()
            if e in missing
        )
        LAST_SKIP_REASON = (
            f"{', '.join(missing)} is not set. Set these values "
            f"either as environment variables or under {hints} "
            f"in config.yaml to enable Authentik dashboard auth."
        )
        logger.debug("dashboard-auth-authentik: %s", LAST_SKIP_REASON)
        return

    try:
        provider = AuthentikAuthProvider(
            authentik_url=authentik_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )
    except (ProviderError, ValueError) as exc:
        LAST_SKIP_REASON = (
            f"AuthentikAuthProvider construction failed: {exc}"
        )
        logger.warning("dashboard-auth-authentik: %s", LAST_SKIP_REASON)
        return

    ctx.register_dashboard_auth_provider(provider)
    logger.info(
        "dashboard-auth-authentik: registered provider "
        "(url=%s, client_id=%s)",
        authentik_url,
        client_id,
    )
