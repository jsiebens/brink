package server

import (
	"context"
	"errors"
	"github.com/jsiebens/brink/internal/config"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Start(config *config.Config, e *echo.Echo) error {
	registerDefaultRoutes(e)

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Shutdown(ctx)
	}()

	logrus.Infof("server listening on %s", config.ListenAddr)

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
}

func registerDefaultRoutes(e *echo.Echo) {
	e.Any("/*", func(c echo.Context) error {
		return c.Render(http.StatusOK, "index.html", nil)
	})
}
