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

func Start(ctx context.Context, config *config.Config, e *echo.Echo) error {
	m := mon.Echo()

	registerDefaultRoutes(e)
	e.Use(mon.Middleware())

	return serve(contextWithSigterm(ctx), e, m, config)
}

func serve(ctx context.Context, e *echo.Echo, p *echo.Echo, config *config.Config) error {
	g, gCtx := errgroup.WithContext(ctx)

	go func() {
		<-gCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = e.Shutdown(shutdownCtx)
		_ = p.Shutdown(shutdownCtx)
	}()

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

	logrus.Infof("server listening on %s", config.ListenAddr)
	logrus.Infof("metrics listening on %s", config.Metrics.ListenAddr)

	return g.Wait()
}

func registerDefaultRoutes(e *echo.Echo) {
	e.Any("/*", func(c echo.Context) error {
		return c.Render(http.StatusOK, "index.html", nil)
	})
}

func contextWithSigterm(ctx context.Context) context.Context {
	ctxWithCancel, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()

		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

		select {
		case <-signalCh:
		case <-ctx.Done():
		}
	}()

	return ctxWithCancel
}
