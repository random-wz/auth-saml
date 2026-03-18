// Package handlers 实现 HTTP 处理器
package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/example/saml-auth/config"
	"github.com/example/saml-auth/session"
)

// Handler 持有所有依赖
type Handler struct {
	cfg          *config.Config
	sp           *saml.ServiceProvider // 用于构建 SLO LogoutRequest
	sessionStore *session.Store
}

// New 创建 Handler
func New(cfg *config.Config, sp *saml.ServiceProvider, store *session.Store) *Handler {
	return &Handler{cfg: cfg, sp: sp, sessionStore: store}
}

// ---- SAML 回调处理 ----

// ACSCallback 在 SAML 中间件成功验证断言后，由 samlsp.Middleware 内部调用，
// 这里我们通过自定义 RequestTracker 拦截来实现。
// 实际使用时通过 OnError/AfterAuth 回调注入。

// BuildAttributeMap 将 SAML 断言属性映射到本地字段
func BuildAttributeMap(assertion *saml.Assertion, attrMap map[string]string) (map[string]string, map[string][]string) {
	flat := make(map[string]string)
	raw := make(map[string][]string)

	if assertion == nil {
		return flat, raw
	}

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			// 收集所有值
			var values []string
			for _, v := range attr.Values {
				if v.Value != "" {
					values = append(values, v.Value)
				}
			}
			if len(values) == 0 {
				continue
			}

			// 同时用 Name 和 FriendlyName 建索引
			for _, name := range []string{attr.Name, attr.FriendlyName} {
				if name == "" {
					continue
				}
				raw[name] = values
				// 映射到本地字段名
				if localKey, ok := attrMap[name]; ok {
					flat[localKey] = values[0]
				} else {
					// 未配置映射，直接用原名（取最后一段）
					parts := strings.Split(name, "/")
					key := parts[len(parts)-1]
					if _, exists := flat[key]; !exists {
						flat[key] = values[0]
					}
				}
			}
		}
	}
	return flat, raw
}

// ---- 公开页面 ----

// Home 首页（受保护）
func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	user := session.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	renderHTML(w, homeTmpl, map[string]interface{}{
		"User": user,
	})
}

// Login 发起 SSO：重定向到目标页，由受保护路由上的 SAML 中间件发起认证。
// 不在此直接调用 HandleStartAuthFlow，避免 ACS 回调后重定向回 /login 导致死循环。
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || returnTo == "/login" {
		returnTo = "/"
	}
	// 如果已登录直接跳转
	user, _ := h.sessionStore.Get(r)
	if user != nil {
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	// 重定向到目标页，samlMiddle.RequireAccount 会在那里发起认证，
	// ACS 完成后 RelayState 指向 returnTo 而非 /login
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// Logout 登出：清除本地 cookie，并向 IdP 发起 SLO（如果 IdP 支持）。
// SLO 完成后 IdP 会回调 /saml/slo，最终跳到 /logged-out。
// 若 IdP 不支持 SLO，则直接跳到 /logged-out（IdP session 仍存活，
// 下次登录时 IdP 仍会自动认证——这是无 SLO 支持时的已知限制）。
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	user, _ := h.sessionStore.Get(r)

	// 1. 清除本地 session cookie
	if err := h.sessionStore.Delete(w, r); err != nil {
		log.Printf("[logout] 清除 session 失败: %v", err)
	}
	// 2. 清除 crewjam/saml 的 JWT cookie（名为 "token"）
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// 3. 若 IdP 有 SLO 端点且用户 NameID 可知，发起 SP-Initiated SLO
	sloURL := h.sp.GetSLOBindingLocation(saml.HTTPRedirectBinding)
	if sloURL != "" && user != nil && user.NameID != "" {
		redirectURL, err := h.sp.MakeRedirectLogoutRequest(user.NameID, "/logged-out")
		if err == nil {
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return
		}
		log.Printf("[logout] SLO 请求构建失败: %v", err)
	}

	http.Redirect(w, r, "/logged-out", http.StatusFound)
}

// SLOCallback 处理 IdP 回传的 LogoutResponse（SP-Initiated SLO 的最后一步）。
// 验证响应后跳转至 RelayState（即 /logged-out）。
func (h *Handler) SLOCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/logged-out", http.StatusFound)
		return
	}
	if err := h.sp.ValidateLogoutResponseRequest(r); err != nil {
		// 验证失败时记录日志，但仍跳转到登出页，避免卡死
		log.Printf("[slo] LogoutResponse 验证失败: %v", err)
	}
	relayState := r.Form.Get("RelayState")
	if relayState == "" {
		relayState = "/logged-out"
	}
	http.Redirect(w, r, relayState, http.StatusFound)
}

// ---- API 接口 ----

// UserInfo 返回当前用户信息（JSON）
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	user := session.UserFromContext(r.Context())
	if user == nil {
		jsonError(w, "未登录", http.StatusUnauthorized)
		return
	}
	jsonResponse(w, user)
}

// LoggedOut 显示登出成功页面（公开，无需认证）
func (h *Handler) LoggedOut(w http.ResponseWriter, r *http.Request) {
	renderHTML(w, loggedOutTmpl, nil)
}
// Health 健康检查
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// ---- 辅助函数 ----

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func renderHTML(w http.ResponseWriter, tmplStr string, data interface{}) {
	tmpl, err := template.New("").Parse(tmplStr)
	if err != nil {
		http.Error(w, "模板解析错误", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("[template] 渲染失败: %v", err)
	}
}

// ---- HTML 模板 ----

var homeTmpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>SAML 2.0 认证服务</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 800px; margin: 60px auto; padding: 0 20px; color: #333; }
  h1 { color: #1a73e8; }
  .card { background: #f8f9fa; border-radius: 8px; padding: 24px; margin: 20px 0; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #dee2e6; }
  th { background: #e9ecef; }
  .btn { display: inline-block; padding: 8px 20px; background: #dc3545;
         color: white; border-radius: 4px; text-decoration: none; }
  .btn:hover { background: #c82333; }
</style>
</head>
<body>
<h1>SAML 2.0 认证服务</h1>
<div class="card">
  <h2>登录成功</h2>
  <p><strong>NameID：</strong>{{.User.NameID}}</p>
  <p><strong>显示名称：</strong>{{.User.DisplayName}}</p>
  <p><strong>邮箱：</strong>{{.User.Email}}</p>
  <p><strong>登录时间：</strong>{{.User.IssuedAt.Format "2006-01-02 15:04:05"}}</p>
  <p><strong>过期时间：</strong>{{.User.ExpiresAt.Format "2006-01-02 15:04:05"}}</p>
</div>
<div class="card">
  <h2>SAML 属性</h2>
  <table>
    <tr><th>属性名</th><th>属性值</th></tr>
    {{range $k, $v := .User.Attributes}}
    <tr><td>{{$k}}</td><td>{{$v}}</td></tr>
    {{end}}
  </table>
</div>
<p><a href="/logout" class="btn">退出登录</a></p>
<p><small>
  <a href="/saml/metadata">SP 元数据 (XML)</a> |
  <a href="/api/userinfo">用户信息 (JSON)</a> |
  <a href="/health">健康检查</a>
</small></p>
</body>
</html>`

// BuildSessionFromSAMLSession 从 crewjam/saml 的 session 提取用户信息
func BuildSessionFromSAMLSession(s samlsp.Session) *session.UserInfo {
	jwtSession, ok := s.(samlsp.JWTSessionClaims)
	if !ok {
		return &session.UserInfo{
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(8 * time.Hour),
		}
	}

	attrs := make(map[string]string)
	rawAttrs := make(map[string][]string)

	for name, values := range jwtSession.Attributes {
		if len(values) > 0 {
			attrs[name] = values[0]
		}
		rawAttrs[name] = values
	}

	expiresAt := time.Now().Add(8 * time.Hour)
	if jwtSession.StandardClaims.ExpiresAt != 0 {
		expiresAt = time.Unix(jwtSession.StandardClaims.ExpiresAt, 0)
	}

	return &session.UserInfo{
		NameID:        jwtSession.Subject,
		Attributes:    attrs,
		RawAttributes: rawAttrs,
		IssuedAt:      time.Now(),
		ExpiresAt:     expiresAt,
	}
}

// FormatSAMLError 格式化 SAML 错误响应页面
func FormatSAMLError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>认证失败</title>
<style>body{font-family:sans-serif;max-width:600px;margin:60px auto;color:#333}
.err{background:#fdecea;border:1px solid #f5c6cb;border-radius:4px;padding:16px;color:#721c24}
a{color:#1a73e8}</style>
</head><body>
<h1>认证失败</h1>
<div class="err"><strong>错误：</strong>%v</div>
<p><a href="/login">重新登录</a></p>
</body></html>`, template.HTMLEscapeString(err.Error()))
}

var loggedOutTmpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>已退出登录</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 480px; margin: 120px auto; padding: 0 20px; color: #333; text-align: center; }
  h1 { color: #333; }
  .card { background: #f8f9fa; border-radius: 8px; padding: 32px; margin: 24px 0; }
  .btn { display: inline-block; padding: 10px 28px; background: #1a73e8;
         color: white; border-radius: 4px; text-decoration: none; }
  .btn:hover { background: #1558b0; }
</style>
</head>
<body>
<div class="card">
  <h1>已退出登录</h1>
  <p>您已成功退出，感谢使用。</p>
  <a href="/login" class="btn">重新登录</a>
</div>
</body>
</html>`
