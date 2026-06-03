# Hermes Agent — Authentik OIDC Dashboard Auth Plugin

为 Hermes Agent 的 Web Dashboard 提供基于 [Authentik](https://goauthentik.io/) 的 OIDC OAuth 2.0 登录认证。

当 Dashboard 绑定到非 loopback 地址时，自动启用 auth gate；登录页出现「Sign in with Authentik」按钮，支持 authorization-code + PKCE (S256) 流程。

## 安装

### 方式一：目录插件（手动复制）

```bash
mkdir -p ~/.hermes/plugins/dashboard_auth/authentik
cp __init__.py plugin.yaml ~/.hermes/plugins/dashboard_auth/authentik/
```

安装依赖：

```bash
# hermes 安装方式决定注入路径
pipx inject hermes-agent httpx "PyJWT[crypto]>=2.8"
# 或 venv 安装：
pip install httpx "PyJWT[crypto]>=2.8"
```

启用：

```bash
hermes plugins enable dashboard_auth/authentik
```

### 方式二：pip 分发

```bash
pip install hermes-authentik-oauth-plugin
hermes plugins enable dashboard_auth/authentik
```

## 配置

支持两种配置表面，**环境变量优先**（非空时覆盖 config.yaml）：

### 环境变量

| 变量 | 必填 | 说明 |
|------|------|------|
| `HERMES_DASHBOARD_AUTHENTIK_URL` | 是 | Authentik 实例的应用完整 URL（含 `/application/o/<slug>`） |
| `HERMES_DASHBOARD_AUTHENTIK_CLIENT_ID` | 是 | OAuth2 客户端 ID |
| `HERMES_DASHBOARD_AUTHENTIK_CLIENT_SECRET` | 否 | 客户端密钥（confidential client 必填） |
| `HERMES_DASHBOARD_AUTHENTIK_SCOPE` | 否 | OAuth2 scopes（默认 `openid email profile offline_access`） |

### config.yaml

```yaml
dashboard:
  oauth:
    authentik_url: https://sso.example.com/application/o/hermes-dashboard
    authentik_client_id: your-client-id
    authentik_client_secret: your-client-secret   # confidential client 必填
    authentik_scope: openid email profile offline_access
  public_url: http://your.domain:port
```

## Authentik 端设置

1. 在 Authentik 管理后台创建 **OAuth2/OpenID Provider**：
   - Client type：**Confidential** 或 **Public**
   - Redirect URIs：`http://your.domain:port/auth/callback`
   - Scopes：勾选 `openid`、`email`、`profile`、`offline_access`
   - Signing algorithm：RS256

2. 记录 Provider 的 **Client ID** 和 **Client Secret**。

3. 配置 `authentik_url` 为 Provider 的完整路径，例如：
   ```
   https://sso.example.com/application/o/hermes-dashboard
   ```

## 启动

```bash
hermes dashboard --host 0.0.0.0
```

Dashboard 绑定到非 loopback 地址后，auth gate 自动触发，登录页出现「Sign in with Authentik」按钮。

## 工作原理

```
浏览器                    Hermes Dashboard              Authentik
  │                            │                            │
  │  GET /login                │                            │
  │ ─────────────────────────→ │                            │
  │  显示登录页                  │                            │
  │                            │                            │
  │  GET /auth/login?           │                            │
  │     provider=authentik      │                            │
  │ ─────────────────────────→ │                            │
  │                            │  start_login() → PKCE      │
  │  302 + Set-Cookie          │                            │
  │ ←───────────────────────── │                            │
  │                            │                            │
  │  GET /authorize?code_challenge=...&state=...             │
  │ ─────────────────────────────────────────────────────→  │
  │  用户认证                                                  │
  │                            │                            │
  │  302 /auth/callback?code=...&state=...                    │
  │ ←─────────────────────────────────────────────────────  │
  │                            │                            │
  │  GET /auth/callback?code=...                             │
  │  Cookie: pkce={state;verifier}                           │
  │ ─────────────────────────→ │                            │
  │                            │  complete_login()           │
  │                            │ ├─ Token 交换               │
  │                            │ ├─ id_token JWT 验证        │
  │                            │ └─ Session 生成             │
  │  302 + Set-Cookie(AT, RT)  │                            │
  │ ←───────────────────────── │                            │
```

- **Access Token** (短期) + **Refresh Token** (长期) → HttpOnly cookie
- Access Token 过期后中间件自动用 Refresh Token 透明续期
- PKCE S256 防截获；JWT 通过 Authentik 的 JWKS 端点验证签名

## 依赖

| 包 | 用途 |
|---|---|
| `httpx` | OIDC Discovery、Token 端点、Userinfo 端点 HTTP 请求 |
| `PyJWT[crypto]` | JWT 签名验证（RS256/ES256 等）+ JWKS 客户端 |

## License

MIT
