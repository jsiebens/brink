package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/proxy"
	"github.com/jsiebens/brink/internal/util"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

func Authenticate(ctx context.Context, proxy string, caFile string, insecureSkipVerify bool) error {
	clt, err := createClient(proxy, caFile, insecureSkipVerify)
	if err != nil {
		return err
	}
	return clt.authenticate(ctx)
}

func StartClient(ctx context.Context, proxy string, listenPort uint64, target string, caFile string, insecureSkipVerify bool, onConnect OnConnect) error {
	clt, err := createClient(proxy, caFile, insecureSkipVerify)
	if err != nil {
		return err
	}

	forwarder, err := NewForwarder(listenPort, target, onConnect)
	if err != nil {
		return err
	}

	clt.forwarder = forwarder

	return clt.start(ctx)
}

func createClient(proxy, caFile string, insecureSkipVerify bool) (*Client, error) {
	var caCertPool *x509.CertPool

	targetBaseUrl, err := util.NormalizeHttpUrl(proxy)
	if err != nil {
		return nil, err
	}

	websocketBaseUrl, err := util.NormalizeWsUrl(proxy)
	if err != nil {
		return nil, err
	}

	if caFile != "" {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		caCertPool, err = x509.SystemCertPool()
		if err != nil {
			caCertPool = x509.NewCertPool()
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: insecureSkipVerify,
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: remotedialer.HandshakeTimeOut,
		TLSClientConfig:  tlsConfig,
	}

	c := &Client{
		httpClient:       resty.NewWithClient(client),
		dialer:           dialer,
		httpBaseUrl:      targetBaseUrl.String(),
		websocketBaseUrl: websocketBaseUrl.String(),
	}

	return c, nil
}

type Client struct {
	httpClient       *resty.Client
	dialer           *websocket.Dialer
	forwarder        *Forwarder
	httpBaseUrl      string
	websocketBaseUrl string
}

func (c *Client) authenticate(ctx context.Context) error {
	_ = DeleteAuthToken(c.httpBaseUrl)

	sn, err := c.createSession(ctx)
	if err != nil {
		return err
	}

	authenticate, err := c.startAuthentication(ctx, "start", sn.SessionId)
	if err != nil {
		return err
	}

	var authToken string

	if authenticate.AuthUrl != "" {
		err = util.OpenURL(authenticate.AuthUrl)
		if err != nil {
			fmt.Println()
			fmt.Println("To authenticate, visit:")
			fmt.Println()
			fmt.Printf("  %s", authenticate.AuthUrl)
			fmt.Println()
			fmt.Println()
		}

		authToken, _, err = c.pollSessionToken(ctx, sn.SessionId)
		if err != nil {
			return err
		}
		fmt.Println("Success.")
	} else {
		authToken = authenticate.AuthToken
	}

	_ = StoreAuthToken(c.httpBaseUrl, authToken)

	return nil
}

func (c *Client) start(ctx context.Context) error {
	if err := c.forwarder.Start(); err != nil {
		return err
	}

	sn, err := c.createSession(ctx)
	if err != nil {
		return err
	}

	authenticate, err := c.startAuthentication(ctx, "start", sn.SessionId)
	if err != nil {
		return err
	}

	var sessionToken string
	var authToken string

	if authenticate.AuthUrl != "" {
		err = util.OpenURL(authenticate.AuthUrl)
		if err != nil {
			fmt.Println()
			fmt.Println("To authenticate, visit:")
			fmt.Println()
			fmt.Printf("  %s", authenticate.AuthUrl)
			fmt.Println()
			fmt.Println()
		}

		authToken, sessionToken, err = c.pollSessionToken(ctx, sn.SessionId)
		if err != nil {
			return err
		}
	} else {
		authToken = authenticate.AuthToken
		sessionToken = authenticate.SessionToken
	}

	_ = StoreAuthToken(c.httpBaseUrl, authToken)

	if err := c.connect(ctx, sn.SessionId, sessionToken, c.forwarder.OnTunnelConnect); err != nil {
		return err
	}

	return nil
}

func (c *Client) createSession(ctx context.Context) (*api.SessionResponse, error) {
	var result api.SessionResponse
	var errMsg api.MessageResponse

	var req = api.CreateSessionRequest{}

	if c.forwarder != nil {
		req.Target = c.forwarder.remoteAddr
	}

	resp, err := c.httpClient.R().
		SetBody(&req).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(ctx).
		Post(c.httpBaseUrl + "/p/session")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d - %s", resp.StatusCode(), errMsg.Message)
	}

	return &result, nil
}

func (c *Client) startAuthentication(ctx context.Context, command, sessionId string) (*api.AuthenticationResponse, error) {
	var result api.AuthenticationResponse
	var errMsg api.MessageResponse

	token, _ := LoadAuthToken(c.httpBaseUrl)

	resp, err := c.httpClient.R().
		SetHeader(proxy.AuthHeader, token).
		SetBody(&api.AuthenticationRequest{Command: command, SessionId: sessionId}).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(ctx).
		Post(c.httpBaseUrl + "/p/auth")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d - %s", resp.StatusCode(), errMsg.Message)
	}

	return &result, nil
}

func (c *Client) pollSessionToken(ctx context.Context, sessionId string) (string, string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(1500 * time.Millisecond):
			resp, err := c.startAuthentication(ctx, "token", sessionId)
			if err != nil {
				return "", "", err
			}

			if resp.SessionToken == "" {
				continue
			}

			return resp.AuthToken, resp.SessionToken, nil
		}
	}
}

func (c *Client) connect(ctx context.Context, id, token string, onConnect func(context.Context, *remotedialer.Session) error) error {
	headers := http.Header{}
	headers.Add(proxy.IdHeader, id)
	headers.Add(proxy.AuthHeader, token)

	return remotedialer.ClientConnect(ctx, c.websocketBaseUrl+"/p/connect", headers, c.dialer, c.declineAll, onConnect)
}

func (c *Client) declineAll(network, address string) bool {
	logrus.WithField("network", network).WithField("addr", address).Info("Connection declined")
	return false
}
