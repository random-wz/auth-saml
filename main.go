package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/mux"

	"github.com/example/saml-auth/certs"
	"github.com/example/saml-auth/config"
	"github.com/example/saml-auth/handlers"
	"github.com/example/saml-auth/middleware"
	"github.com/example/saml-auth/session"
)

func main() {
	// ---- 1. 加载配置 ----
	cfgFile := os.Getenv("CONFIG_FILE")
	cfg, err := config.Load(cfgFile)
	if err != nil {
		log.Fatalf("[main] 加载配置失败: %v", err)
	}

	// ---- 2. 加载/生成 SP 证书 ----
	privateKey, cert, err := certs.LoadOrGenerate(cfg.SAML.CertFile, cfg.SAML.KeyFile, cfg.Server.BaseURL)
	if err != nil {
		log.Fatalf("[main] 证书加载/生成失败: %v", err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	// ---- 3. 加载 IdP 元数据 ----
	idpMeta, err := loadIDPMetadata(cfg)
	if err != nil {
		log.Fatalf("[main] 加载 IdP 元数据失败: %v", err)
	}

	// ---- 4. 构建 SP 根 URL ----
	rootURL, err := url.Parse(cfg.Server.BaseURL)
	if err != nil {
		log.Fatalf("[main] 解析 BaseURL 失败: %v", err)
	}

	// ---- 5. 初始化 SAML 中间件 ----
	samlOpts := samlsp.Options{
		URL:               *rootURL,
		Key:               privateKey,
		Certificate:       cert,
		IDPMetadata:       idpMeta,
		AllowIDPInitiated: cfg.SAML.AllowIDPInitiated,
	}
	if cfg.SAML.EntityID != "" {
		samlOpts.EntityID = cfg.SAML.EntityID
	}

	samlMiddle, err := samlsp.New(samlOpts)
	if err != nil {
		log.Fatalf("[main] 初始化 SAML 中间件失败: %v", err)
	}
	// 使用 tls.Certificate（包含完整证书链）
	_ = tlsCert

	// ---- 6. 初始化 Session 存储 ----
	sessionStore := session.NewStore(
		cfg.Cookie.HashKey,
		cfg.Cookie.BlockKey,
		cfg.Cookie.Name,
		cfg.Cookie.MaxAge,
		cfg.Cookie.Secure,
	)

	// ---- 7. 自定义 SAML 认证成功后的回调 ----
	// 覆盖默认的 OnError，让错误显示更友好
	samlMiddle.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[saml] 认证错误: %v", err)
		handlers.FormatSAMLError(w, err)
	}

	// ---- 8. 构建处理器 ----
	h := handlers.New(cfg, &samlMiddle.ServiceProvider, sessionStore)

	// ---- 9. 构建路由 ----
	router := buildRouter(cfg, samlMiddle, sessionStore, h)

	// ---- 10. 启动 HTTP 服务器 ----
	srv := &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("[main] SAML SP 认证服务启动: %s  (BaseURL: %s)", cfg.Server.Addr(), cfg.Server.BaseURL)
		log.Printf("[main] SP 元数据地址: %s/saml/metadata", cfg.Server.BaseURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[main] 服务启动失败: %v", err)
		}
	}()

	<-quit
	log.Println("[main] 正在优雅关闭服务器...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[main] 强制关闭服务器: %v", err)
	}
	log.Println("[main] 服务器已关闭")
}

// buildRouter 配置所有路由
func buildRouter(
	cfg *config.Config,
	samlMiddle *samlsp.Middleware,
	store *session.Store,
	h *handlers.Handler,
) http.Handler {
	r := mux.NewRouter()

	// 全局中间件
	r.Use(middleware.Recovery)
	r.Use(middleware.Logger)

	// ---- SAML 协议端点 ----
	// /saml/slo 需要先于 PathPrefix 注册，由我们自己处理 LogoutResponse
	r.HandleFunc("/saml/slo", h.SLOCallback).Methods(http.MethodGet, http.MethodPost)
	// /saml/metadata、/saml/acs 由 crewjam/saml 中间件处理
	r.PathPrefix("/saml/").Handler(samlMiddle)

	// ---- 公开端点 ----
	r.HandleFunc("/health", h.Health).Methods(http.MethodGet)
	r.HandleFunc("/login", h.Login).Methods(http.MethodGet)
	r.HandleFunc("/logout", h.Logout).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/logged-out", h.LoggedOut).Methods(http.MethodGet)

	// ---- 受保护端点：需要 SAML 认证 ----
	// 使用 crewjam/saml 中间件做 SAML 检查，再用自定义 session 中间件注入 context
	authRequired := middleware.RequireAuth(store, "/login")

	// 将 SAML session 同步到自定义 session（桥接中间件）
	samlProtected := func(next http.Handler) http.Handler {
		return samlMiddle.RequireAccount(samlSessionBridge(store, next))
	}

	protected := r.NewRoute().Subrouter()
	protected.Use(samlProtected)
	protected.Use(authRequired)

	protected.HandleFunc("/", h.Home).Methods(http.MethodGet)
	protected.HandleFunc("/api/userinfo", h.UserInfo).Methods(http.MethodGet)

	// 静态资源（示例）
	r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	return r
}

// samlSessionBridge 在 SAML 认证成功后，将 crewjam session 数据同步写入自定义 session cookie
func samlSessionBridge(store *session.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查自定义 session 是否已存在
		existing, _ := store.Get(r)
		if existing != nil {
			// 已有 session，直接注入 context
			ctx := session.WithUser(r.Context(), existing)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 从 crewjam/saml session 中构建用户信息
		samlSession := samlsp.SessionFromContext(r.Context())
		if samlSession == nil {
			next.ServeHTTP(w, r)
			return
		}

		userInfo := handlers.BuildSessionFromSAMLSession(samlSession)
		if err := store.Save(w, r, userInfo); err != nil {
			log.Printf("[bridge] 保存 session 失败: %v", err)
		}
		ctx := session.WithUser(r.Context(), userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loadIDPMetadata 从 URL 或本地文件加载 IdP 元数据
func loadIDPMetadata(cfg *config.Config) (*saml.EntityDescriptor, error) {
	sc := cfg.SAML

	switch {
	case sc.IDPMetadataURL != "":
		metaURL, err := url.Parse(sc.IDPMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("解析 IdP 元数据 URL 失败: %w", err)
		}
		log.Printf("[main] 正在从 URL 加载 IdP 元数据: %s", sc.IDPMetadataURL)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		meta, err := samlsp.FetchMetadata(ctx, http.DefaultClient, *metaURL)
		if err != nil {
			return nil, fmt.Errorf("获取 IdP 元数据失败: %w", err)
		}
		return meta, nil

	case sc.IDPMetadataFile != "":
		log.Printf("[main] 正在从文件加载 IdP 元数据: %s", sc.IDPMetadataFile)
		data, err := os.ReadFile(sc.IDPMetadataFile)
		if err != nil {
			return nil, fmt.Errorf("读取 IdP 元数据文件失败: %w", err)
		}
		meta, err := samlsp.ParseMetadata(data)
		if err != nil {
			return nil, fmt.Errorf("解析 IdP 元数据失败: %w", err)
		}
		return meta, nil

	default:
		// 开发模式：不配置 IdP 时使用空元数据（仅用于测试）
		log.Println("[main] 警告：未配置 IdP 元数据，服务将以仅展示元数据模式运行")
		// 返回一个最小的空元数据
		meta := &saml.EntityDescriptor{}
		return meta, nil
	}
}
