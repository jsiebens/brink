package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"github.com/jsiebens/proxiro/internal/api"
	"github.com/jsiebens/proxiro/internal/proxy"
	"github.com/jsiebens/proxiro/internal/util"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

func StartClient(ctx context.Context, proxy string, listenPort uint64, target string, caFile string, insecureSkipVerify bool, onConnect OnConnect) error {
	targetBaseUrl, err := util.NormalizeProxyUrl(proxy)
	if err != nil {
		return err
	}

	connectUrl, err := util.NormalizeConnectUrl(proxy)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{}

	if caFile != "" {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.RootCAs = caCertPool
	}

	if insecureSkipVerify {
		tlsConfig.InsecureSkipVerify = insecureSkipVerify
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: remotedialer.HandshakeTimeOut,
		TLSClientConfig:  tlsConfig,
	}

	forwarder, err := NewForwarder(listenPort, target, onConnect)
	if err != nil {
		return err
	}

	c := &Client{
		httpClient:    resty.NewWithClient(client),
		dialer:        dialer,
		forwarder:     forwarder,
		targetBaseUrl: targetBaseUrl.String(),
		connectUrl:    connectUrl.String(),
	}

	return c.Start(ctx)
}

type Client struct {
	httpClient    *resty.Client
	dialer        *websocket.Dialer
	forwarder     *Forwarder
	targetBaseUrl string
	connectUrl    string
}

func (c *Client) Start(ctx context.Context) error {
	if err := c.forwarder.Start(); err != nil {
		return err
	}

	sn, err := c.createSession(ctx)
	if err != nil {
		return err
	}

	authenticate, err := c.authenticate(ctx, "start", sn.SessionAuthUrl, sn.SessionId)
	if err != nil {
		return err
	}

	err = util.OpenURL(authenticate.AuthUrl)
	if err != nil {
		fmt.Println()
		fmt.Println(authenticate.AuthUrl)
		fmt.Println()
	}

	token, err := c.pollSessionToken(ctx, sn.SessionAuthUrl, sn.SessionId)
	if err != nil {
		return err
	}

	if err := c.connect(ctx, sn.SessionId, token, c.forwarder.OnTunnelConnect); err != nil {
		return err
	}

	return nil
}

func (c *Client) createSession(ctx context.Context) (*api.SessionResponse, error) {
	var result api.SessionResponse
	var errMsg api.MessageResponse

	resp, err := c.httpClient.R().
		SetResult(&result).
		SetError(&errMsg).
		SetContext(ctx).
		Post(c.targetBaseUrl + "/p/session")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d - %s", resp.StatusCode(), errMsg.Message)
	}

	return &result, nil
}

func (c *Client) authenticate(ctx context.Context, command, url, sessionId string) (*api.AuthenticationResponse, error) {
	var result api.AuthenticationResponse
	var errMsg api.MessageResponse

	resp, err := c.httpClient.R().
		SetBody(&api.AuthenticationRequest{Command: command, SessionId: sessionId}).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(ctx).
		Post(url)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d - %s", resp.StatusCode(), errMsg.Message)
	}

	return &result, nil
}

func (c *Client) pollSessionToken(ctx context.Context, url, sessionId string) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(1500 * time.Millisecond):
			resp, err := c.authenticate(ctx, "token", url, sessionId)
			if err != nil {
				return "", err
			}

			if resp.Token == "" {
				continue
			}

			return resp.Token, nil
		}
	}
}

func (c *Client) connect(ctx context.Context, id, token string, onConnect func(context.Context, *remotedialer.Session) error) error {
	headers := http.Header{}
	headers.Add(proxy.IdHeader, id)
	headers.Add(proxy.AuthHeader, token)

	return remotedialer.ClientConnect(ctx, c.connectUrl+"/p/connect", headers, c.dialer, c.declineAll, onConnect)
}

func (c *Client) declineAll(network, address string) bool {
	logrus.WithField("network", network).WithField("addr", address).Info("Connection declined")
	return false
}
