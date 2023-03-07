package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/jsiebens/brink/internal/config"
	"github.com/jsiebens/brink/internal/mon"
	"github.com/jsiebens/brink/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var errDisconnectedFromRelay = fmt.Errorf("disconnected from relay")

func Start(ctx context.Context, config *config.Config, e *echo.Echo) error {
	m := mon.Echo()

	registerDefaultRoutes(e)
	e.Use(mon.Middleware())

	sCtx := contextWithSigterm(ctx)

	if config.Relay.RemoteServer != "" {
		return serveThroughRelay(sCtx, e, m, config)
	}

	return serve(sCtx, e, m, config)
}

func serve(ctx context.Context, e *echo.Echo, p *echo.Echo, config *config.Config) error {
	logrus.Infof("server listening on %s", config.ListenAddr)
	logrus.Infof("metrics listening on %s", config.Metrics.ListenAddr)

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

	return g.Wait()
}

func serveThroughRelay(ctx context.Context, e *echo.Echo, p *echo.Echo, config *config.Config) error {
	remotePublicKey := config.Relay.RemotePublicKey
	remoteUrl, err := util.NormalizeHttpUrl(config.Relay.RemoteServer)
	if err != nil {
		return err
	}

	g, gCtx := errgroup.WithContext(ctx)
	go func() {
		<-gCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Shutdown(shutdownCtx)
	}()

	g.Go(func() error {
		for {
			err := startThroughRelay(ctx, e, remoteUrl, remotePublicKey)
			if err != nil {
				select {
				case <-gCtx.Done():
					return nil
				default:
					logrus.WithField("err", err).Error("disconnected from relay, retrying in 5 seconds...")
					select {
					case <-gCtx.Done():
						return nil
					case <-time.After(5 * time.Second):
						// retry
					}
				}
			}
		}
	})

	g.Go(func() error {
		if err := p.Start(config.Metrics.ListenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	logrus.Infof("server relayed to %s", config.Relay.RemoteServer)
	logrus.Infof("metrics listening on %s", config.Metrics.ListenAddr)

	return g.Wait()
}

func startThroughRelay(ctx context.Context, e *echo.Echo, remoteUrl, remotePublicKey string) error {
	conn, err := util.NewConnection(ctx, remoteUrl, remotePublicKey, &tls.Config{})
	if err != nil {
		return err
	}

	listen, err := yamux.Server(conn, nil)
	if err != nil {
		return err
	}

	e.Listener = listen

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		select {
		case <-gCtx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = e.Shutdown(shutdownCtx)
			return nil
		case <-listen.CloseChan():
			return errDisconnectedFromRelay
		}
	})

	g.Go(func() error {
		if err := e.Start(""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})

	logrus.Info("connected to relay")

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
