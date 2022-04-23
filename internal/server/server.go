package server

import (
	"context"
	"errors"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/mon"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Start(config *config.Config, e *echo.Echo) error {
	m := mon.Echo()

	registerDefaultRoutes(e)
	e.Use(mon.Middleware())

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Shutdown(ctx)
		_ = m.Shutdown(ctx)
	}()

	logrus.Infof("server listening on %s", config.ListenAddr)
	logrus.Infof("metrics listening on %s", config.Metrics.ListenAddr)

	return serve(e, m, config)
}

func serve(e *echo.Echo, p *echo.Echo, config *config.Config) error {
	g := new(errgroup.Group)
	g.Go(func() error {
		if config.Tls.Disable {
			if err := e.Start(config.ListenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		} else {
			if err := e.StartTLS(config.ListenAddr, config.Tls.CertFile, config.Tls.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		}
		return nil
	})
	g.Go(func() error {
		if err := p.Start(config.Metrics.ListenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	return g.Wait()
}

func registerDefaultRoutes(e *echo.Echo) {
	e.Any("/*", func(c echo.Context) error {
		return c.Render(http.StatusOK, "index.html", nil)
	})
}
