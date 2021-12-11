package auth

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
	v.SetEnvPrefix("proxiro")
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
	}
}

type Config struct {
	ListenAddr string `mapstructure:"listen_addr"`
	ServerUrl  string `mapstructure:"server_url"`
	Tls        Tls    `mapstructure:"tls"`
	Oidc       Oidc   `mapstructure:"oidc"`
}

type Tls struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type Oidc struct {
	Issuer       string `mapstructure:"issuer"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}
