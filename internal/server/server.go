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
	"net/http"
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

	if config.Auth.RemoteServer == "" {
		logrus.Info("registering oidc routes")

		if config.Auth.EnableApi {
			logrus.Info("registering auth routes")
		}

		authServer, err := auth.NewServer(config.Auth, cache.Prefixed(c, authCachePrefix))
		if err != nil {
			return err
		}
		authServer.RegisterRoutes(e, config.Auth.EnableApi)
		registrar = authServer
	} else {
		logrus.Info("configuring remote auth server, skipping oidc and auth routes")
		remoteSessionRegistrar, err := proxy.NewRemoteSessionRegistrar(config.Auth)
		if err != nil {
			return err
		}
		registrar = remoteSessionRegistrar
	}

	if !config.Proxy.Disable {
		logrus.Info("registering proxy routes")

		proxyServer, err := proxy.NewServer(config.Proxy, cache.Prefixed(c, proxyCachePrefix), registrar)
		if err != nil {
			return err
		}
		proxyServer.RegisterRoutes(e)
	} else {
		logrus.Info("proxy is explicitly disabled, skipping proxy routes")
	}

	registerDefaultRoutes(e)

	logrus.Infof("server listening on %s", config.ListenAddr)

	if config.Tls.Disable {
		return e.Start(config.ListenAddr)
	} else {
		return e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile)
	}
}

func registerDefaultRoutes(e *echo.Echo) {
	e.Any("/*", func(c echo.Context) error {
		return c.Render(http.StatusOK, "index.html", nil)
	})
}
