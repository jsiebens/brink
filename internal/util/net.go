package util

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/key"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"
)

func NewAltReadWriteCloserConn(rwc io.ReadWriteCloser, c net.Conn) net.Conn {
	return wrappedConn{c, rwc}
}

type wrappedConn struct {
	net.Conn
	rwc io.ReadWriteCloser
}

func (w wrappedConn) Read(bs []byte) (int, error) {
	return w.rwc.Read(bs)
}

func (w wrappedConn) Write(bs []byte) (int, error) {
	return w.rwc.Write(bs)
}

func (w wrappedConn) Close() error {
	return w.rwc.Close()
}

func NewConnection(ctx context.Context, remoteUrl, remotePublicKey string, tlsConfig *tls.Config) (net.Conn, error) {
	publicKey, err := key.ParsePublicKey(remotePublicKey)
	if err != nil {
		return nil, err
	}
	privateKey, err := key.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	token, err := privateKey.SealBase58(*publicKey, &api.Token{ExpirationTime: time.Now().UTC().Add(5 * time.Minute)})
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(remoteUrl)
	if err != nil {
		return nil, err
	}

	u.Path = "/r/connect"

	tr := &http.Transport{
		ForceAttemptHTTP2: false,
		TLSClientConfig:   tlsConfig,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}

	connCh := make(chan net.Conn, 1)
	trace := httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			connCh <- info.Conn
		},
	}
	traceCtx := httptrace.WithClientTrace(ctx, &trace)
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: http.Header{
			api.KeyHeader:   []string{privateKey.Public().String()},
			api.TokenHeader: []string{token},
			"Upgrade":       []string{api.UpgradeHeaderValue},
			"Connection":    []string{"upgrade"},
		},
	}
	req = req.WithContext(traceCtx)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("unexpected HTTP response: %s", resp.Status)
	}

	var switchedConn net.Conn
	select {
	case switchedConn = <-connCh:
	default:
	}
	if switchedConn == nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("httptrace didn't provide a connection")
	}

	if next := resp.Header.Get("Upgrade"); next != api.UpgradeHeaderValue {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("server switched to unexpected protocol %q", next)
	}

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		_ = resp.Body.Close()
		return nil, errors.New("http Transport did not provide a writable body")
	}

	return NewAltReadWriteCloserConn(rwc, switchedConn), err
}
