# AGENTS.md

## 项目概述

这是一个 Hermes Agent 的 Dashboard Auth Provider 插件，对接 Authentik OIDC OAuth 2.0 认证。

## 文件结构

```
├── __init__.py      # 核心实现（AuthentikAuthProvider + register 入口）
├── plugin.yaml      # 插件清单（kind: backend）
├── pyproject.toml   # pip 分发配置
├── README.md        # 用户文档
├── AGENTS.md        # 本文件
└── .gitignore
```

## 核心接口

插件实现 `hermes_cli.dashboard_auth.DashboardAuthProvider` (ABC)，必须提供：

| 方法 | 说明 |
|------|------|
| `name` / `display_name` | 类属性，provider 标识 |
| `start_login(redirect_uri)` → `LoginStart` | OAuth 第一跳，生成 PKCE + state |
| `complete_login(code, state, code_verifier, redirect_uri)` → `Session` | 交换 code 为 token |
| `verify_session(access_token)` → `Session \| None` | 每次请求验证 access token |
| `refresh_session(refresh_token)` → `Session` | 透明续期 |
| `revoke_session(refresh_token)` → `None` | 登出时撤销 token |

参考上游实现：`/Users/bytedance/.hermes/hermes-agent/plugins/dashboard_auth/nous/__init__.py`

## 数据流

```
config.yaml + env var → register(ctx) → AuthentikAuthProvider 构造
  └─ OIDC Discovery (/.well-known/openid-configuration)
  └─ ctx.register_dashboard_auth_provider(provider)
```

Token 验证链（访问 token）：

```
access_token → _verify_jwt_strict(aud=client_id)
             → _verify_jwt_lenient(跳过 aud，仅验签名+issuer+exp)
             → _fetch_userinfo(OIDC userinfo 端点)
```

Token 验证链（ID token）：

```
id_token → _verify_jwt_strict(aud=client_id)  # OIDC 规范要求
```

## 配置解析

环境变量优先于 config.yaml。命名空间为 `dashboard.oauth.authentik_*`，与 Nous 插件互不冲突。

## 验证

```bash
# 协议合规校验
python3 -c "
import sys
sys.path.insert(0, '/path/to/hermes-agent')
sys.path.insert(0, '.')
from hermes_cli.dashboard_auth import assert_protocol_compliance
from __init__ import AuthentikAuthProvider
assert_protocol_compliance(AuthentikAuthProvider)
print('OK')
"

# 插件注册验证（需 hermes venv）
hermes plugins list | grep authentik
```

## 依赖

- `httpx>=0.24`：HTTP 客户端
- `PyJWT[crypto]>=2.8,<3`：JWT + JWKS

## 代码约定

- 遵循 Nous 官方的 `NousDashboardAuthProvider` 代码风格
- 工具 handler 始终返回 JSON 字符串
- 异常分类：`ProviderError`（IDP 不可达）、`InvalidCodeError`（code/state 校验失败）、`RefreshExpiredError`（refresh token 失效）
- 配置解析函数命名：`_resolve_<name>()`
- Lazy import：`jwt` 模块仅在需要时导入
- 日志前缀：`dashboard-auth-authentik:`
