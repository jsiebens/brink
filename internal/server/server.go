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

	if config.Proxy.AuthServer == "" {
		logrus.Info("registering auth endpoints")

		authServer, err := auth.NewServer(config.Auth, cache.Prefixed(c, authCachePrefix))
		if err != nil {
			return err
		}
		authServer.RegisterRoutes(e)
		registrar = authServer
	} else {
		logrus.Info("proxy has an auth_server configured, skipping auth endpoints")
	}

	if !config.Proxy.Disable {
		logrus.Info("registering proxy endpoints")

		proxyServer, err := proxy.NewServer(config.Proxy, cache.Prefixed(c, proxyCachePrefix), registrar)
		if err != nil {
			return err
		}
		proxyServer.RegisterRoutes(e)
	} else {
		logrus.Info("proxy is explicitly disabled, skipping proxy endpoints")
	}

	logrus.Infof("server listening on %s", config.ListenAddr)

	if config.Tls.Disable {
		return e.Start(config.ListenAddr)
	} else {
		return e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile)
	}
}
