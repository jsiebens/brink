package server

import (
	"github.com/jsiebens/proxiro/internal/auth"
	"github.com/jsiebens/proxiro/internal/auth/templates"
	"github.com/jsiebens/proxiro/internal/config"
	"github.com/jsiebens/proxiro/internal/proxy"
	"github.com/jsiebens/proxiro/internal/version"
	"github.com/labstack/echo/v4"
)

func StartServer(config *config.Config) error {
	authServer, err := auth.NewServer(config)
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Renderer = templates.NewTemplates()

	version.RegisterRoutes(e)
	authServer.RegisterRoutes(e)

	if len(config.ACLPolicy.Identity) != 0 && len(config.ACLPolicy.Targets) != 0 {
		proxyServer, err := proxy.NewServer(config, authServer)
		if err != nil {
			return err
		}

		proxyServer.RegisterRoutes(e)
	}

	if config.Tls.KeyFile == "" {
		return e.Start(config.ListenAddr)
	} else {
		return e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile)
	}
}

func StartProxy(config *config.Config) error {
	server, err := proxy.NewServer(config, nil)
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	version.RegisterRoutes(e)
	server.RegisterRoutes(e)

	if config.Tls.KeyFile == "" {
		return e.Start(config.ListenAddr)
	} else {
		return e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile)
	}
}
