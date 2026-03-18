package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 服务全局配置
type Config struct {
	Server ServerConfig `yaml:"server"`
	SAML   SAMLConfig   `yaml:"saml"`
	Cookie CookieConfig `yaml:"cookie"`
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// 对外暴露的根 URL，如 https://sp.example.com
	BaseURL string `yaml:"base_url"`
}

type SAMLConfig struct {
	// 本 SP 证书和私钥路径（PEM 格式）；不存在则自动生成
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// IdP 元数据 URL 或本地文件路径（二选一）
	IDPMetadataURL  string `yaml:"idp_metadata_url"`
	IDPMetadataFile string `yaml:"idp_metadata_file"`

	// SP 实体 ID，留空则默认使用 BaseURL + /saml/metadata
	EntityID string `yaml:"entity_id"`

	// 是否要求签名断言
	AllowIDPInitiated bool `yaml:"allow_idp_initiated"`

	// 属性映射：SAML 属性名 -> 本地字段名
	AttributeMap map[string]string `yaml:"attribute_map"`
}

type CookieConfig struct {
	Name     string        `yaml:"name"`
	MaxAge   time.Duration `yaml:"max_age"`
	Secure   bool          `yaml:"secure"`
	HttpOnly bool          `yaml:"http_only"`
	// 用于签名/加密 session 的密钥（至少32字节）
	HashKey  string `yaml:"hash_key"`
	BlockKey string `yaml:"block_key"`
}

// DefaultConfig 返回带默认值的配置
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:    "0.0.0.0",
			Port:    8000,
			BaseURL: "http://localhost:8000",
		},
		SAML: SAMLConfig{
			CertFile:          "certs/sp.crt",
			KeyFile:           "certs/sp.key",
			AllowIDPInitiated: true,
			AttributeMap: map[string]string{
				"uid":                                                    "uid",
				"email":                                                  "email",
				"urn:oid:0.9.2342.19200300.100.1.1":                    "uid",
				"urn:oid:1.2.840.113549.1.9.1":                         "email",
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":        "displayName",
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups":    "groups",
			},
		},
		Cookie: CookieConfig{
			Name:     "saml_session",
			MaxAge:   8 * time.Hour,
			Secure:   false,
			HttpOnly: true,
			HashKey:  "please-change-this-secret-key-32b",
			BlockKey: "please-change-block-key-32bytess",
		},
	}
}

// Load 从 YAML 文件加载配置，并用环境变量覆盖
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parse config file: %w", err)
			}
		}
	}

	// 环境变量覆盖（优先级最高）
	overrideFromEnv(cfg)

	return cfg, nil
}

func overrideFromEnv(cfg *Config) {
	if v := os.Getenv("SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
		}
	}
	if v := os.Getenv("SERVER_BASE_URL"); v != "" {
		cfg.Server.BaseURL = v
	}
	if v := os.Getenv("SAML_CERT_FILE"); v != "" {
		cfg.SAML.CertFile = v
	}
	if v := os.Getenv("SAML_KEY_FILE"); v != "" {
		cfg.SAML.KeyFile = v
	}
	if v := os.Getenv("SAML_IDP_METADATA_URL"); v != "" {
		cfg.SAML.IDPMetadataURL = v
	}
	if v := os.Getenv("SAML_IDP_METADATA_FILE"); v != "" {
		cfg.SAML.IDPMetadataFile = v
	}
	if v := os.Getenv("SAML_ENTITY_ID"); v != "" {
		cfg.SAML.EntityID = v
	}
	if v := os.Getenv("COOKIE_HASH_KEY"); v != "" {
		cfg.Cookie.HashKey = v
	}
	if v := os.Getenv("COOKIE_BLOCK_KEY"); v != "" {
		cfg.Cookie.BlockKey = v
	}
	if v := os.Getenv("COOKIE_SECURE"); v == "true" {
		cfg.Cookie.Secure = true
	}
}

func (c *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}
