package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/util"
	stream "github.com/nknorg/encrypted-stream"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
)

func NewDialer(proxyPublicKey key.PublicKey, clientPrivateKey key.PrivateKey, target string, tlsConfig *tls.Config) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		u, err := url.Parse(target)
		if err != nil {
			return nil, err
		}

		u.Path = "/p/upgrade"

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
				"Upgrade":               []string{api.UpgradeHeaderValue},
				"Connection":            []string{"upgrade"},
				api.HandshakeHeaderName: []string{clientPrivateKey.Public().String()},
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

		return stream.NewEncryptedStream(util.NewAltReadWriteCloserConn(rwc, switchedConn), &stream.Config{
			Cipher:          key.NewBoxCipher(clientPrivateKey, proxyPublicKey),
			SequentialNonce: false, // only when key is unique for every stream
			Initiator:       true,  // only on the dialer side
		})
	}
}
