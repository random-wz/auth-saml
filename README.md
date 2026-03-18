# SAML 2.0 认证服务

基于 Go 语言实现的 SAML 2.0 Service Provider（SP）认证服务，支持对接 Azure AD、Google Workspace、SimpleSAMLphp 等主流 Identity Provider（IdP）。

---

## 目录

- [SAML 2.0 协议简介](#saml-20-协议简介)
- [项目功能](#项目功能)
- [架构设计](#架构设计)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [API 端点](#api-端点)
- [对接主流 IdP](#对接主流-idp)
- [Docker 部署](#docker-部署)
- [项目结构](#项目结构)

---

## SAML 2.0 协议简介

**SAML**（Security Assertion Markup Language）是一种基于 XML 的开放标准，用于在身份提供方（IdP）和服务提供方（SP）之间安全地交换认证和授权数据。

### 核心概念

| 概念 | 说明 |
|------|------|
| **IdP**（Identity Provider）| 负责验证用户身份，如 Azure AD、Okta、Google |
| **SP**（Service Provider） | 提供应用服务，依赖 IdP 完成用户认证（即本项目） |
| **Assertion** | IdP 签名的 XML 文档，包含用户身份和属性信息 |
| **ACS**（Assertion Consumer Service）| SP 接收并处理 IdP 断言的端点 |
| **SLO**（Single Logout）| 单点登出，注销后同步销毁 IdP 和所有 SP 的会话 |
| **Metadata** | SP/IdP 互相发布的描述文件，包含公钥、端点地址等信息 |

### SP-Initiated SSO 流程

```
用户浏览器            SP（本服务）               IdP
    |                     |                       |
    |-- GET /            -->|                       |
    |                     |-- 检查 session，未登录  |
    |<-- 302 /saml/acs  --|                       |
    |                     |                       |
    |-- GET /saml/acs   -->|                       |
    |                     |-- 生成 AuthnRequest  -->|
    |<-- 302 IdP SSO URL--|                       |
    |                     |                       |
    |-- POST IdP SSO URL ----------------------->|
    |                     |                       |-- 验证用户凭证
    |                     |                       |-- 生成 SAMLResponse
    |<-- POST /saml/acs (SAMLResponse) ----------|
    |                     |                       |
    |-- POST /saml/acs  -->|                       |
    |                     |-- 验证签名/断言         |
    |                     |-- 建立本地 session     |
    |<-- 302 /          --|                       |
    |                     |                       |
    |-- GET /           -->|                       |
    |<-- 200 首页       --|                       |
```

### SP-Initiated SLO 流程

```
用户浏览器            SP（本服务）               IdP
    |                     |                       |
    |-- GET /logout     -->|                       |
    |                     |-- 清除本地 session     |
    |                     |-- 构建 LogoutRequest -->|
    |<-- 302 IdP SLO URL--|                       |
    |                     |                       |
    |-- GET IdP SLO URL ----------------------->|
    |                     |                       |-- 销毁 IdP session
    |                     |                       |-- 返回 LogoutResponse
    |<-- POST /saml/slo (LogoutResponse) --------|
    |                     |                       |
    |-- POST /saml/slo  -->|                       |
    |                     |-- 验证 LogoutResponse  |
    |<-- 302 /logged-out--|                       |
```

---

## 项目功能

- **SP-Initiated SSO**：用户访问受保护资源时自动发起 SAML 认证
- **IdP-Initiated SSO**：支持 IdP 主动推送断言（可配置开关）
- **SP-Initiated SLO**：登出时向 IdP 发起单点登出请求
- **自动证书管理**：首次启动自动生成 RSA 2048 自签名证书，也支持加载已有证书
- **灵活的元数据加载**：支持通过 URL 在线获取或本地文件加载 IdP 元数据
- **属性映射**：可配置 SAML 属性名到本地字段名的映射，兼容 OID URN、Azure AD Claim、Google Workspace 等多种格式
- **安全 Cookie Session**：使用 gorilla/sessions 实现 HMAC 签名 + AES 加密的 Cookie Session
- **优雅关闭**：监听 SIGINT/SIGTERM，等待请求处理完毕后关闭
- **健康检查端点**：`/health` 供容器编排系统探活
- **Docker 支持**：提供多阶段构建 Dockerfile 和 docker-compose（含内置 SimpleSAMLphp IdP）

---

## 架构设计

### 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         saml-auth 服务                           │
│                                                                  │
│  ┌──────────┐    ┌────────────────────────────────────────────┐ │
│  │          │    │              gorilla/mux 路由               │ │
│  │  config  │    │                                            │ │
│  │ (YAML +  │    │  公开路由          受保护路由               │ │
│  │  env)    │    │  /health           /                       │ │
│  │          │    │  /login            /api/userinfo           │ │
│  └──────────┘    │  /logout                                   │ │
│                  │  /logged-out       ↑                       │ │
│  ┌──────────┐    │  /saml/*           samlProtected           │ │
│  │  certs   │    │                    中间件链                 │ │
│  │ (自动生成 │    │                    ┌──────────────────────┐│ │
│  │  RSA2048)│    │                    │samlMiddle.RequireAcct││ │
│  └──────────┘    │                    │  ↓                   ││ │
│                  │                    │samlSessionBridge     ││ │
│  ┌──────────┐    │                    │  ↓                   ││ │
│  │ crewjam/ │    │                    │RequireAuth(cookie)   ││ │
│  │   saml   │◄───┤                    └──────────────────────┘│ │
│  │middleware│    │                                            │ │
│  └──────────┘    └────────────────────────────────────────────┘ │
│                                    │                             │
│  ┌──────────────────────────────────▼──────────────────────────┐ │
│  │                         handlers                             │ │
│  │  Home  Login  Logout  SLOCallback  UserInfo  Health         │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                    │                             │
│  ┌─────────────────────────────────▼──────────────────────────┐ │
│  │                    session.Store                            │ │
│  │   gorilla/sessions Cookie (HMAC-SHA256 + AES-256-CBC)      │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │ SAML 2.0 协议
                              ▼
                    ┌─────────────────┐
                    │   IdP（外部）    │
                    │ Azure AD / Google│
                    │ / SimpleSAMLphp  │
                    └─────────────────┘
```

### 中间件层次

受保护路由的请求依次经过以下中间件：

```
Request
  │
  ▼
Recovery（panic 恢复）
  │
  ▼
Logger（请求日志）
  │
  ▼
samlMiddle.RequireAccount（crewjam/saml：验证 JWT token cookie）
  │  未认证 → 发起 AuthnRequest，重定向到 IdP
  │  已认证 ↓
  ▼
samlSessionBridge（桥接层）
  │  将 crewjam JWT session → 自定义 Cookie session
  │  (仅首次，后续从自定义 session 直接读取)
  │
  ▼
RequireAuth（自定义 session 校验 + context 注入）
  │  session 不存在/过期 → 重定向到 /login
  │  有效 ↓
  ▼
Handler（业务逻辑，从 context 读取用户信息）
```

### Session 双层设计

本项目采用双层 Session 设计以解耦 SAML 协议层与业务层：

```
┌─────────────────────────────────────────────────┐
│ Layer 1: crewjam/saml JWT Cookie（名称: "token"）│
│   • 由 crewjam/saml 中间件管理                   │
│   • 包含 SAML Subject、Attributes、过期时间       │
│   • 仅用于 SAML 协议握手和断言验证               │
└────────────────────┬────────────────────────────┘
                     │ samlSessionBridge 同步
┌────────────────────▼────────────────────────────┐
│ Layer 2: 自定义 Cookie Session（名称: 可配置）    │
│   • 由 gorilla/sessions 管理                     │
│   • HMAC 签名 + AES 加密，防篡改防泄露            │
│   • 包含结构化 UserInfo（NameID、属性、过期）      │
│   • 业务层直接使用此 session，与 SAML 解耦        │
└─────────────────────────────────────────────────┘
```

---

## 快速开始

### 前置条件

- Go 1.21+
- 一个已有的 SAML IdP，或使用内置 SimpleSAMLphp（Docker）

### 本地运行（含测试 IdP）

```bash
# 1. 克隆项目
git clone <repo-url>
cd saml-auth

# 2. 使用 Docker Compose 一键启动（含 SimpleSAMLphp IdP）
docker-compose up

# SP 访问地址：http://localhost:8080
# IdP 管理界面：http://localhost:8086/simplesaml
```

测试账号（SimpleSAMLphp 内置）：
- 用户名：`user1`，密码：`user1pass`
- 用户名：`user2`，密码：`user2pass`

### 直接运行

```bash
# 1. 复制配置文件
cp config.example.yaml config.yaml

# 2. 编辑配置，填入 IdP 元数据地址
vi config.yaml

# 3. 编译并运行
go build -o saml-auth .
./saml-auth

# 或使用环境变量指定配置文件
CONFIG_FILE=config.yaml ./saml-auth
```

首次启动时，如果 `certs/sp.crt` 和 `certs/sp.key` 不存在，服务会自动生成自签名证书。

### 注册 SP 到 IdP

访问 `http://localhost:8080/saml/metadata` 获取 SP 元数据 XML，将其导入到 IdP 完成 SP 注册。

---

## 配置说明

配置文件为 YAML 格式（默认路径 `config.yaml`），所有字段均可通过环境变量覆盖。

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  # 对外暴露的根 URL，必须与 IdP 中注册的 SP 地址一致
  base_url: "http://localhost:8080"

saml:
  cert_file: "certs/sp.crt"   # SP 证书（不存在则自动生成）
  key_file: "certs/sp.key"    # SP 私钥（不存在则自动生成）

  # IdP 元数据（二选一）
  idp_metadata_url: ""        # 通过 URL 在线获取（推荐）
  idp_metadata_file: ""       # 本地文件路径

  entity_id: ""               # SP 实体 ID，留空默认为 base_url/saml/metadata
  allow_idp_initiated: true   # 是否允许 IdP-Initiated SSO

  # SAML 属性到本地字段的映射
  attribute_map:
    "uid": "uid"
    "email": "email"
    "displayName": "displayName"
    # 更多映射见 config.example.yaml

cookie:
  name: "saml_session"
  max_age: "8h"
  secure: false               # 生产环境需设为 true（要求 HTTPS）
  http_only: true
  # 生产环境必须更换！可用 openssl rand -hex 32 生成
  hash_key: "your-32-byte-hash-key"
  block_key: "your-32-byte-block-key"
```

### 环境变量覆盖

| 环境变量 | 对应配置项 |
|----------|-----------|
| `CONFIG_FILE` | 配置文件路径 |
| `SERVER_HOST` | `server.host` |
| `SERVER_PORT` | `server.port` |
| `SERVER_BASE_URL` | `server.base_url` |
| `SAML_CERT_FILE` | `saml.cert_file` |
| `SAML_KEY_FILE` | `saml.key_file` |
| `SAML_IDP_METADATA_URL` | `saml.idp_metadata_url` |
| `SAML_IDP_METADATA_FILE` | `saml.idp_metadata_file` |
| `SAML_ENTITY_ID` | `saml.entity_id` |
| `COOKIE_HASH_KEY` | `cookie.hash_key` |
| `COOKIE_BLOCK_KEY` | `cookie.block_key` |
| `COOKIE_SECURE` | `cookie.secure` |

---

## API 端点

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/saml/metadata` | GET | 无 | SP 元数据 XML，用于在 IdP 注册 SP |
| `/saml/acs` | POST | 无 | Assertion Consumer Service，接收 IdP 返回的断言 |
| `/saml/slo` | GET/POST | 无 | Single Logout，处理 IdP 返回的 LogoutResponse |
| `/health` | GET | 无 | 健康检查，返回 `{"status":"ok","time":"..."}` |
| `/login` | GET | 无 | 发起 SSO，支持 `?return_to=` 参数指定登录后跳转地址 |
| `/logout` | GET/POST | 无 | 登出，清除本地 session 并向 IdP 发起 SLO |
| `/logged-out` | GET | 无 | 登出成功页面 |
| `/` | GET | **需要** | 首页，展示用户信息和 SAML 属性 |
| `/api/userinfo` | GET | **需要** | 返回当前用户信息 JSON |

### `/api/userinfo` 响应示例

```json
{
  "name_id": "user@example.com",
  "session_index": "",
  "attributes": {
    "email": "user@example.com",
    "displayName": "张三",
    "uid": "zhangsan"
  },
  "raw_attributes": {
    "email": ["user@example.com"],
    "groups": ["admins", "developers"]
  },
  "issued_at": "2024-01-01T10:00:00Z",
  "expires_at": "2024-01-01T18:00:00Z"
}
```

---

## 对接主流 IdP

### Azure AD / Microsoft Entra ID

```yaml
saml:
  idp_metadata_url: "https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml"
  attribute_map:
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email"
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "displayName"
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": "groups"
```

在 Azure AD 中：创建企业应用 → 单点登录 → SAML → 上传 `/saml/metadata` XML。

### Google Workspace

```yaml
saml:
  idp_metadata_url: "https://accounts.google.com/o/saml2/idp?idpid={IDP_ID}"
  attribute_map:
    "http://schemas.xmlsoap.org/claims/EmailAddress": "email"
```

在 Google Admin 中：应用 → 网络和移动应用 → 添加应用 → 自定义 SAML 应用。

### SimpleSAMLphp（本地测试）

```yaml
saml:
  idp_metadata_url: "http://localhost:8086/simplesaml/saml2/idp/metadata.php"
```

---

## Docker 部署

### 仅部署 SP

```bash
docker build -t saml-auth .
docker run -d \
  -p 8080:8080 \
  -e SERVER_BASE_URL=https://sp.example.com \
  -e SAML_IDP_METADATA_URL=https://idp.example.com/saml/metadata \
  -e COOKIE_HASH_KEY=$(openssl rand -hex 32) \
  -e COOKIE_BLOCK_KEY=$(openssl rand -hex 32) \
  -v $(pwd)/certs:/app/certs \
  saml-auth
```

### 含测试 IdP（本地开发）

```bash
docker-compose up
```

- SP：`http://localhost:8080`
- IdP 管理界面：`http://localhost:8086/simplesaml`

### 生产环境注意事项

1. **HTTPS**：生产环境必须启用 HTTPS，并将 `cookie.secure` 设为 `true`
2. **密钥安全**：`COOKIE_HASH_KEY` 和 `COOKIE_BLOCK_KEY` 必须使用强随机密钥
3. **证书管理**：建议使用 CA 签名证书替代自签名证书，提高 IdP 互信度
4. **Base URL**：`server.base_url` 必须与 IdP 配置中的 SP 地址完全一致

---

## 项目结构

```
saml-auth/
├── main.go                 # 服务入口：路由构建、中间件初始化、优雅关闭
├── config/
│   └── config.go           # 配置结构体、YAML 加载、环境变量覆盖
├── certs/
│   └── certs.go            # SP 证书自动生成（RSA 2048）与加载
├── session/
│   └── session.go          # Cookie Session 存储（gorilla/sessions）、UserInfo 结构
├── middleware/
│   └── middleware.go       # RequireAuth、Logger、Recovery 中间件
├── handlers/
│   └── handlers.go         # HTTP 处理器、SAML session 桥接、HTML 模板
├── config.example.yaml     # 配置示例（含 Azure AD / Google / SimpleSAMLphp 注释）
├── docker-compose.yml      # 含内置 SimpleSAMLphp IdP 的本地测试环境
├── Dockerfile              # 多阶段构建
└── go.mod                  # 依赖声明（Go 1.21）
```

### 核心依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `github.com/crewjam/saml` | v0.4.14 | SAML 2.0 SP 核心实现（AuthnRequest、断言验证、SLO） |
| `github.com/gorilla/mux` | v1.8.1 | HTTP 路由 |
| `github.com/gorilla/sessions` | v1.2.2 | 安全 Cookie Session |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML 配置解析 |
