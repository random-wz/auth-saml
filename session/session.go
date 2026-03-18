// Package session 提供基于安全 Cookie 的会话管理
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

// contextKey 会话 context key
type contextKey string

const sessionContextKey contextKey = "saml_user"

// UserInfo 从 SAML 断言中提取的用户信息
type UserInfo struct {
	NameID     string            `json:"name_id"`
	SessionIdx string            `json:"session_index"`
	Attributes map[string]string `json:"attributes"`
	// 原始属性（多值）
	RawAttributes map[string][]string `json:"raw_attributes"`
	IssuedAt      time.Time           `json:"issued_at"`
	ExpiresAt     time.Time           `json:"expires_at"`
}

// Email 便捷方法
func (u *UserInfo) Email() string {
	return u.Attributes["email"]
}

// DisplayName 便捷方法
func (u *UserInfo) DisplayName() string {
	if n := u.Attributes["displayName"]; n != "" {
		return n
	}
	return u.NameID
}

// Groups 便捷方法
func (u *UserInfo) Groups() []string {
	return u.RawAttributes["groups"]
}

// Store 封装了 gorilla/sessions 的会话存储
type Store struct {
	store      *sessions.CookieStore
	cookieName string
	maxAge     time.Duration
	secure     bool
}

// NewStore 创建会话存储
func NewStore(hashKey, blockKey, cookieName string, maxAge time.Duration, secure bool) *Store {
	cs := sessions.NewCookieStore([]byte(hashKey), []byte(blockKey))
	cs.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	return &Store{
		store:      cs,
		cookieName: cookieName,
		maxAge:     maxAge,
		secure:     secure,
	}
}

// Save 将用户信息写入 session cookie
func (s *Store) Save(w http.ResponseWriter, r *http.Request, user *UserInfo) error {
	sess, err := s.store.Get(r, s.cookieName)
	if err != nil {
		// session 损坏时新建
		sess, err = s.store.New(r, s.cookieName)
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}
	}

	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal user: %w", err)
	}
	sess.Values["user"] = string(data)
	return sess.Save(r, w)
}

// Get 从 session cookie 读取用户信息，未登录时返回 (nil, nil)
func (s *Store) Get(r *http.Request) (*UserInfo, error) {
	sess, err := s.store.Get(r, s.cookieName)
	if err != nil || sess.IsNew {
		return nil, nil
	}

	raw, ok := sess.Values["user"].(string)
	if !ok || raw == "" {
		return nil, nil
	}

	var user UserInfo
	if err := json.Unmarshal([]byte(raw), &user); err != nil {
		return nil, fmt.Errorf("unmarshal user: %w", err)
	}

	// 检查是否过期
	if !user.ExpiresAt.IsZero() && time.Now().After(user.ExpiresAt) {
		return nil, nil
	}

	return &user, nil
}

// Delete 清除 session cookie
func (s *Store) Delete(w http.ResponseWriter, r *http.Request) error {
	sess, _ := s.store.Get(r, s.cookieName)
	sess.Options.MaxAge = -1
	sess.Values = map[interface{}]interface{}{}
	return sess.Save(r, w)
}

// WithUser 将用户信息注入 context
func WithUser(ctx context.Context, user *UserInfo) context.Context {
	return context.WithValue(ctx, sessionContextKey, user)
}

// UserFromContext 从 context 中取出用户信息
func UserFromContext(ctx context.Context) *UserInfo {
	user, _ := ctx.Value(sessionContextKey).(*UserInfo)
	return user
}
