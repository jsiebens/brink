package config

import (
	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

const (
	listenAddrKey                   = "BRINK_LISTEN_ADDR"
	tlsDisableKey                   = "BRINK_TLS_DISABLE"
	tlsCertFileKey                  = "BRINK_TLS_CERT_FILE"
	tlsKeyFileKey                   = "BRINK_TLS_KEY_FILE"
	cacheTypeKey                    = "BRINK_CACHE_TYPE"
	cacheRedisAddrKey               = "BRINK_CACHE_REDIS_ADDR"
	cacheRedisDBKey                 = "BRINK_CACHE_REDIS_DB"
	cacheRedisPasswordKey           = "BRINK_CACHE_REDIS_PASSWORD"
	authUrlPrefixKey                = "BRINK_AUTH_URL_PREFIX"
	authRemoteServerKey             = "BRINK_AUTH_REMOTE_SERVER"
	authRemotePublicKeyKey          = "BRINK_AUTH_REMOTE_PUBLIC_KEY"
	authRemotePrivateKeyKey         = "BRINK_AUTH_PRIVATE_KEY"
	authProviderTypeKey             = "BRINK_AUTH_PROVIDER_TYPE"
	authProviderIssuerKey           = "BRINK_AUTH_PROVIDER_ISSUER"
	authProviderClientIdKey         = "BRINK_AUTH_PROVIDER_CLIENT_ID"
	authProviderClientSecretKey     = "BRINK_AUTH_PROVIDER_CLIENT_SECRET"
	authProviderAdditionalScopesKey = "BRINK_AUTH_ADDITIONAL_SCOPES"
)

func LoadConfig(path string) (*Config, error) {
	config := defaultConfig()

	if len(path) != 0 {
		expandedPath, err := homedir.Expand(path)
		if err != nil {
			return nil, err
		}
		b, err := ioutil.ReadFile(expandedPath)
		if err != nil {
			return nil, err
		}

		if err := yaml.Unmarshal(b, config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

func defaultConfig() *Config {
	return &Config{
		ListenAddr: getString(listenAddrKey, ":7000"),
		Tls: Tls{
			Disable:  getBool(tlsDisableKey, false),
			CertFile: getString(tlsCertFileKey, ""),
			KeyFile:  getString(tlsKeyFileKey, ""),
		},
		Cache: Cache{
			Type:          getString(cacheTypeKey, "inmemory"),
			RedisAddr:     getString(cacheRedisAddrKey, ""),
			RedisDB:       getInt(cacheRedisDBKey, 0),
			RedisPassword: getString(cacheRedisPasswordKey, ""),
		},
		Auth: Auth{
			UrlPrefix:       getString(authUrlPrefixKey, ""),
			RemoteServer:    getString(authRemoteServerKey, ""),
			RemotePublicKey: getString(authRemotePublicKeyKey, ""),
			PrivateKey:      getString(authRemotePrivateKeyKey, ""),
			Provider: Provider{
				Type:         getString(authProviderTypeKey, "oidc"),
				Issuer:       getString(authProviderIssuerKey, ""),
				ClientID:     getString(authProviderClientIdKey, ""),
				ClientSecret: getString(authProviderClientSecretKey, ""),
				Scopes:       getStringArray(authProviderAdditionalScopesKey, []string{}),
			},
		},
		Proxy: Proxy{},
	}
}

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	Tls        Tls    `yaml:"tls"`
	Cache      Cache  `yaml:"cache"`
	Auth       Auth   `yaml:"auth"`
	Proxy      Proxy  `yaml:"proxy"`
}

type Cache struct {
	Type          string `yaml:"type"`
	RedisAddr     string `yaml:"redis_addr"`
	RedisDB       int    `yaml:"redis_db"`
	RedisPassword string `yaml:"redis_password"`
}

type Tls struct {
	Disable  bool   `yaml:"disable"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type Auth struct {
	RemoteServer    string   `yaml:"remote_server"`
	RemotePublicKey string   `yaml:"remote_public_key"`
	PrivateKey      string   `yaml:"private_key"`
	UrlPrefix       string   `yaml:"url_prefix"`
	Provider        Provider `yaml:"provider"`
}

type Provider struct {
	Type         string   `yaml:"type"`
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"additional_scopes"`
}

type Proxy struct {
	PrivateKey string            `yaml:"private_key"`
	Policies   map[string]Policy `yaml:"policies"`
}

type Policy struct {
	Subs    []string `yaml:"subs"`
	Emails  []string `yaml:"emails"`
	Filters []string `yaml:"filters"`
	Targets []string `yaml:"targets"`
}
