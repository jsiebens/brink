package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/util"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
	"io/ioutil"
	"net/http"
	"time"
)

func Authenticate(ctx context.Context, proxy string, caFile string, insecureSkipVerify bool, noBrowser, showQR bool) error {
	clt, err := createClient(proxy, caFile, insecureSkipVerify, noBrowser, showQR)
	if err != nil {
		return err
	}
	return clt.authenticate(ctx)
}

func StartClient(ctx context.Context, proxy string, listenPort uint64, target string, caFile string, insecureSkipVerify bool, noBrowser, showQR bool, onConnect OnConnect) error {
	clt, err := createClient(proxy, caFile, insecureSkipVerify, noBrowser, showQR)
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

func createClient(proxy, caFile string, insecureSkipVerify bool, noBrowser, showQR bool) (*Client, error) {
	var caCertPool *x509.CertPool

	targetBaseUrl, err := util.NormalizeHttpUrl(proxy)
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

	proxyPublicKey, err := getProxyPublicKey(context.Background(), resty.NewWithClient(&http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}), targetBaseUrl)
	if err != nil {
		return nil, err
	}

	clientPrivateKey, err := key.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	dialer := NewDialer(*proxyPublicKey, *clientPrivateKey, targetBaseUrl, tlsConfig)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:     dialer,
			TLSClientConfig: tlsConfig,
		},
	}

	websocketDialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: remotedialer.HandshakeTimeOut,
		TLSClientConfig:  tlsConfig,
		NetDialContext:   dialer,
	}

	c := &Client{
		httpClient: resty.NewWithClient(client),
		dialer:     websocketDialer,
		noBrowser:  noBrowser,
		showQR:     showQR,
	}

	return c, nil
}

type Client struct {
	httpClient *resty.Client
	dialer     *websocket.Dialer
	forwarder  *Forwarder
	target     string
	noBrowser  bool
	showQR     bool
}

func (c *Client) authenticate(ctx context.Context) error {
	_ = DeleteAuthToken(c.target)

	sn, err := c.createSession(ctx, "")
	if err != nil {
		return err
	}

	var authToken string

	if sn.AuthUrl != "" {
		c.openOrShowAuthUrl(sn)
		authToken, _, err = c.pollSessionToken(ctx, sn.SessionId)
		if err != nil {
			return err
		}
		fmt.Println("Success.")
	} else {
		authToken = sn.AuthToken
	}

	err = StoreAuthToken(c.target, authToken)
	if err != nil {
		fmt.Println()
		fmt.Printf("  Unable to store auth token in your system credential store: %s\n", err)
		fmt.Println("  You can use this token via BRINK_AUTH_TOKEN env var")
		fmt.Printf("  Token: %s\n", authToken)
		fmt.Println()
	}

	return nil
}

func (c *Client) start(ctx context.Context) error {
	if err := c.forwarder.Start(); err != nil {
		return err
	}

	currentAuthToken, storeAuthToken, _ := LoadAuthToken(c.target)

	sn, err := c.createSession(ctx, currentAuthToken)
	if err != nil {
		return err
	}

	var sessionToken string
	var authToken string

	if sn.AuthUrl != "" {
		c.openOrShowAuthUrl(sn)
		authToken, sessionToken, err = c.pollSessionToken(ctx, sn.SessionId)
		if err != nil {
			return err
		}
	} else {
		authToken = sn.AuthToken
		sessionToken = sn.SessionToken
	}

	_ = storeAuthToken(c.target, authToken)

	if err := c.connect(ctx, sn.SessionId, sessionToken); err != nil {
		return err
	}

	return nil
}

func (c *Client) createSession(ctx context.Context, authToken string) (*api.SessionTokenResponse, error) {
	var result api.SessionTokenResponse
	var errMsg api.MessageResponse

	var req = api.CreateSessionRequest{
		AuthToken: authToken,
	}

	if c.forwarder != nil {
		req.Target = c.forwarder.remoteAddr
	}

	resp, err := c.httpClient.R().
		SetBody(&req).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(ctx).
		Post("http://internal/p/session")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, &serverError{resp.StatusCode(), errMsg.Message}
	}

	return &result, nil
}

func (c *Client) pollSessionToken(ctx context.Context, sessionId string) (string, string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(1500 * time.Millisecond):
			resp, err := c.checkSessionToken(ctx, sessionId)
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

func (c *Client) checkSessionToken(ctx context.Context, sessionId string) (*api.SessionTokenResponse, error) {
	var result api.SessionTokenResponse
	var errMsg api.MessageResponse

	resp, err := c.httpClient.R().
		SetBody(&api.SessionTokenRequest{SessionId: sessionId}).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(ctx).
		Post("http://internal/p/token")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, &serverError{resp.StatusCode(), errMsg.Message}
	}

	return &result, nil
}

func (c *Client) connect(ctx context.Context, id, token string) error {
	headers := http.Header{}
	headers.Add(api.IdHeader, id)
	headers.Add(api.AuthHeader, token)

	return c.connectToProxy(ctx, "ws://internal/p/connect", headers)
}

func (c *Client) connectToProxy(rootCtx context.Context, proxyURL string, headers http.Header) error {
	ws, resp, err := c.dialer.DialContext(rootCtx, proxyURL, headers)
	if err != nil {
		if resp != nil {
			rb, err2 := ioutil.ReadAll(resp.Body)
			if err2 != nil {
				return &serverError{resp.StatusCode, resp.Status}
			} else {
				return &serverError{resp.StatusCode, string(rb)}
			}
		}
		return err
	}
	defer ws.Close()

	result := make(chan error, 2)

	ctx, cancel := context.WithCancel(rootCtx)
	defer cancel()

	session := remotedialer.NewClientSession(c.declineAll, ws)
	defer session.Close()

	go func() {
		if err := c.forwarder.OnTunnelConnect(ctx, session); err != nil {
			result <- err
		}
	}()

	go func() {
		_, err = session.Serve(ctx)
		result <- err
	}()

	select {
	case <-ctx.Done():
		logrus.WithField("url", proxyURL).WithField("err", ctx.Err()).Info("Proxy done")
		return nil
	case err := <-result:
		return err
	}
}

func (c *Client) openOrShowAuthUrl(sn *api.SessionTokenResponse) {
	if c.noBrowser || c.showQR || util.OpenURL(sn.AuthUrl) != nil {
		fmt.Println()
		fmt.Println("To authenticate, visit:")
		fmt.Println()
		fmt.Printf("  %s", sn.AuthUrl)
		fmt.Println()

		if c.showQR {
			fmt.Println()
			code, err := qrcode.New(sn.AuthUrl, qrcode.Medium)
			if err != nil {
				fmt.Printf("  QR code error: %v", err)
			} else {
				fmt.Println(code.ToString(false))
			}
		}

		fmt.Println()
	}
}

func (c *Client) declineAll(network, address string) bool {
	logrus.WithField("network", network).WithField("addr", address).Info("Connection declined")
	return false
}

type serverError struct {
	code    int
	message string
}

func (e serverError) Error() string {
	return fmt.Sprintf("unexpected status code: %d - %s", e.code, e.message)
}

func getProxyPublicKey(ctx context.Context, client *resty.Client, httpBaseUrl string) (*key.PublicKey, error) {
	resp, err := client.R().
		SetContext(ctx).
		Get(httpBaseUrl + "/p/key")

	if err != nil {
		return nil, err
	}

	return key.ParsePublicKey(resp.String())
}
