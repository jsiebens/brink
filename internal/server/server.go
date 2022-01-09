package server

import (
	"github.com/jsiebens/brink/internal/auth"
	"github.com/jsiebens/brink/internal/auth/templates"
	"github.com/jsiebens/brink/internal/cache"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/proxy"
	"github.com/jsiebens/brink/internal/version"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

const authCachePrefix = "a_"
const proxyCachePrefix = "p_"

func StartServer(config *config.Config) error {

	c, err := cache.NewCache(config.Cache)
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Renderer = templates.NewTemplates()

	version.RegisterRoutes(e)

	var registrar proxy.SessionRegistrar

	if config.AuthServer == "" {
		authServer, err := auth.NewServer(config, cache.Prefixed(c, authCachePrefix))
		if err != nil {
			return err
		}
		authServer.RegisterRoutes(e)
		registrar = authServer
	}

	proxyServer, err := proxy.NewServer(config, cache.Prefixed(c, proxyCachePrefix), registrar)
	if err != nil {
		return err
	}
	proxyServer.RegisterRoutes(e)

	logrus.Infof("Server listening on %s", config.ListenAddr)

	if config.Tls.KeyFile == "" {
		return e.Start(config.ListenAddr)
	} else {
		return e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile)
	}
}
