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
		ServerUrl:  "http://localhost:7000",
		Tls:        Tls{},
		Oidc:       Oidc{},
		Policy:     Policy{},
		Cache: Cache{
			Type: "inmemory",
		},
	}
}

type Config struct {
	ListenAddr string `mapstructure:"listen_addr"`
	ServerUrl  string `mapstructure:"server_url"`
	AuthServer string `mapstructure:"auth_server"`
	Key        string `mapstructure:"key"`
	Cache      Cache  `mapstructure:"cache"`
	Tls        Tls    `mapstructure:"tls"`
	Oidc       Oidc   `mapstructure:"oidc"`
	Policy     Policy `mapstructure:"policy"`
}

type Tls struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type Oidc struct {
	Issuer       string   `mapstructure:"issuer"`
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	Scopes       []string `mapstructure:"additional_scopes"`
}

type Policy struct {
	Subs    []string `mapstructure:"subs"`
	Emails  []string `mapstructure:"emails"`
	Filters []string `mapstructure:"filters"`
	Targets []string `mapstructure:"targets"`
}

type Cache struct {
	Type          string `mapstructure:"type"`
	RedisAddr     string `mapstructure:"redis_addr"`
	RedisDB       int    `mapstructure:"redis_db"`
	RedisPassword string `mapstructure:"redis_password"`
}
