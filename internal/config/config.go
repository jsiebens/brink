package config

import (
	"github.com/iamolegga/enviper"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

func LoadConfig(path string) (*Config, error) {
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return nil, err
	}

	v := enviper.New(viper.New())
	v.SetEnvPrefix("brink")
	v.AutomaticEnv()

	if len(path) != 0 {
		v.SetConfigFile(expandedPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	}

	config := defaultConfig()
	if err := v.Unmarshal(config); err != nil {
		return nil, err
	}

	return config, nil
}

func defaultConfig() *Config {
	return &Config{
		ListenAddr: ":7000",
		Auth: Auth{
			Oidc: Oidc{
				UrlPrefix: "https://localhost:7000",
			},
		},
		Cache: Cache{
			Type: "inmemory",
		},
	}
}

type Config struct {
	ListenAddr string `mapstructure:"listen_addr"`
	Tls        Tls    `mapstructure:"tls"`
	Cache      Cache  `mapstructure:"cache"`
	Auth       Auth   `mapstructure:"auth"`
	Proxy      Proxy  `mapstructure:"proxy"`
}

type Cache struct {
	Type          string `mapstructure:"type"`
	RedisAddr     string `mapstructure:"redis_addr"`
	RedisDB       int    `mapstructure:"redis_db"`
	RedisPassword string `mapstructure:"redis_password"`
}

type Tls struct {
	Disable  bool   `mapstructure:"disable"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type Auth struct {
	RemoteServer string `mapstructure:"remote_server"`
	EnableApi    bool   `mapstructure:"enable_api"`
	Key          string `mapstructure:"key"`
	Oidc         Oidc   `mapstructure:"oidc"`
}

type Oidc struct {
	UrlPrefix    string   `mapstructure:"url_prefix"`
	Issuer       string   `mapstructure:"issuer"`
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Scopes       []string `mapstructure:"additional_scopes"`
}

type Proxy struct {
	Disable bool   `mapstructure:"disable"`
	Policy  Policy `mapstructure:"policy"`
}

type Policy struct {
	Subs    []string `mapstructure:"subs"`
	Emails  []string `mapstructure:"emails"`
	Filters []string `mapstructure:"filters"`
	Targets []string `mapstructure:"targets"`
}
