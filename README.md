# Hermes Agent - Authentik OIDC Dashboard Auth Plugin

[中文说明](./README_ZH.md)

Provides [Authentik](https://goauthentik.io/) based OIDC OAuth 2.0 authentication for the Hermes Agent Web Dashboard.

When the Dashboard binds to a non-loopback address, Hermes automatically enables the auth gate. The login page then shows a `Sign in with Authentik` button and uses the authorization-code + PKCE (S256) flow.

## Installation

### Option 1: Directory plugin (manual copy)

```bash
mkdir -p ~/.hermes/plugins/dashboard_auth/authentik
cp __init__.py plugin.yaml ~/.hermes/plugins/dashboard_auth/authentik/
```

Install dependencies:

```bash
# The injection target depends on how hermes was installed
pipx inject hermes-agent httpx "PyJWT[crypto]>=2.8"
# Or, if you use a venv install:
pip install httpx "PyJWT[crypto]>=2.8"
```

Enable the plugin:

```bash
hermes plugins enable dashboard_auth/authentik
```

### Option 2: pip distribution

```bash
pip install hermes-authentik-oauth-plugin
hermes plugins enable dashboard_auth/authentik
```

## Configuration

Two configuration surfaces are supported. **Environment variables take precedence** over `config.yaml` when they are non-empty.

### Environment variables

| Variable | Required | Description |
|------|------|------|
| `HERMES_DASHBOARD_AUTHENTIK_URL` | Yes | Full Authentik application URL, including `/application/o/<slug>` |
| `HERMES_DASHBOARD_AUTHENTIK_CLIENT_ID` | Yes | OAuth2 client ID |
| `HERMES_DASHBOARD_AUTHENTIK_CLIENT_SECRET` | No | Client secret, required for confidential clients |
| `HERMES_DASHBOARD_AUTHENTIK_SCOPE` | No | OAuth2 scopes, defaults to `openid email profile offline_access` |

### `config.yaml`

```yaml
dashboard:
  oauth:
    authentik_url: https://sso.example.com/application/o/hermes-dashboard
    authentik_client_id: your-client-id
    authentik_client_secret: your-client-secret   # required for confidential clients
    authentik_scope: openid email profile offline_access
  public_url: http://your.domain:port
```

## Authentik setup

1. Create an **OAuth2/OpenID Provider** in the Authentik admin console:
   - Client type: **Confidential** or **Public**
   - Redirect URIs: `http://your.domain:port/auth/callback`
   - Scopes: enable `openid`, `email`, `profile`, and `offline_access`
   - Signing algorithm: `RS256`

2. Record the provider **Client ID** and **Client Secret**.

3. Set `authentik_url` to the full provider path, for example:

   ```text
   https://sso.example.com/application/o/hermes-dashboard
   ```

## Start Hermes Dashboard

```bash
hermes dashboard --host 0.0.0.0
```

Once the Dashboard is bound to a non-loopback address, the auth gate activates automatically and the login page shows the `Sign in with Authentik` button.

## How it works

```text
Browser                     Hermes Dashboard              Authentik
  │                              │                            │
  │  GET /login                  │                            │
  │ ───────────────────────────> │                            │
  │  Render login page           │                            │
  │                              │                            │
  │  GET /auth/login?            │                            │
  │     provider=authentik       │                            │
  │ ───────────────────────────> │                            │
  │                              │  start_login() -> PKCE     │
  │  302 + Set-Cookie            │                            │
  │ <─────────────────────────── │                            │
  │                              │                            │
  │  GET /authorize?code_challenge=...&state=...              │
  │ ───────────────────────────────────────────────────────> │
  │  User authenticates                                          │
  │                              │                            │
  │  302 /auth/callback?code=...&state=...                     │
  │ <─────────────────────────────────────────────────────── │
  │                              │                            │
  │  GET /auth/callback?code=...                              │
  │  Cookie: pkce={state;verifier}                            │
  │ ───────────────────────────> │                            │
  │                              │  complete_login()          │
  │                              │  |- Exchange token         │
  │                              │  |- Verify id_token JWT    │
  │                              │  `- Build session          │
  │  302 + Set-Cookie(AT, RT)    │                            │
  │ <─────────────────────────── │                            │
```

- **Access Token** (short-lived) and **Refresh Token** (long-lived) are stored in `HttpOnly` cookies.
- When the Access Token expires, middleware transparently refreshes it with the Refresh Token.
- `PKCE S256` mitigates interception risks, and JWT signatures are verified through Authentik's `JWKS` endpoint.

## Dependencies

| Package | Purpose |
|---|---|
| `httpx` | HTTP requests for OIDC discovery, token exchange, and the userinfo endpoint |
| `PyJWT[crypto]` | JWT signature verification (RS256/ES256 and others) and JWKS client support |

## License

MIT
