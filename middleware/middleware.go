// Package middleware 提供 HTTP 中间件
package middleware

import (
	"net/http"

	"github.com/example/saml-auth/session"
)

// RequireAuth 验证请求是否有有效 session，未登录时重定向到 /login
func RequireAuth(store *session.Store, loginURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := store.Get(r)
			if err != nil || user == nil {
				// 保存原始请求路径，登录后跳回
				redirect := r.URL.RequestURI()
				http.Redirect(w, r, loginURL+"?return_to="+redirect, http.StatusFound)
				return
			}
			// 将用户信息注入 context
			ctx := session.WithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Logger 简单的请求日志中间件
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Recovery 恢复 panic 防止服务崩溃
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
