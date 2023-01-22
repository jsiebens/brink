package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/yamux"
	"github.com/jsiebens/brink/internal/api"
	"github.com/jsiebens/brink/internal/key"
	"github.com/jsiebens/brink/internal/util"
	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

type OnConnect func(ctx context.Context, addr, ip, port string) error

func Authenticate(ctx context.Context, proxy string, caFile string, insecureSkipVerify bool, noBrowser, showQR bool) error {
	clt, err := createClient(proxy, caFile, insecureSkipVerify, noBrowser, showQR)
	if err != nil {
		return err
	}
	return clt.authenticate(ctx)
}

func StartClient(ctx context.Context, proxy string, localAddr string, remoteAddr string, caFile string, insecureSkipVerify bool, noBrowser, showQR bool, onConnect OnConnect) error {
	clt, err := createClient(proxy, caFile, insecureSkipVerify, noBrowser, showQR)
	if err != nil {
		return err
	}

	clt.localAddr = localAddr
	clt.remoteAddr = remoteAddr
	clt.onConnect = onConnect

	return clt.start(ctx)
}

func createClient(proxy, caFile string, insecureSkipVerify bool, noBrowser, showQR bool) (*Client, error) {
	var caCertPool *x509.CertPool

	proxyBaseUrl, err := util.NormalizeHttpUrl(proxy)
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

	proxyPublicKey, err := getProxyPublicKey(context.Background(), resty.NewWithClient(&http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}), proxyBaseUrl)
	if err != nil {
		return nil, err
	}

	clientPrivateKey, err := key.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	dialer := NewDialer(*proxyPublicKey, *clientPrivateKey, proxyBaseUrl+"/p/connect", tlsConfig)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	c := &Client{
		httpClient:   resty.NewWithClient(client),
		proxyBaseUrl: proxyBaseUrl,
		dialer:       dialer,
		noBrowser:    noBrowser,
		showQR:       showQR,
	}

	return c, nil
}

type Client struct {
	httpClient   *resty.Client
	dialer       func(context.Context, string, string) (net.Conn, error)
	proxyBaseUrl string
	localAddr    string
	remoteAddr   string
	noBrowser    bool
	showQR       bool
	onConnect    OnConnect
}

func (c *Client) authenticate(ctx context.Context) error {
	_ = DeleteAuthToken(c.proxyBaseUrl)

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

	err = StoreAuthToken(c.proxyBaseUrl, authToken)
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
	currentAuthToken, storeAuthToken, _ := LoadAuthToken(c.proxyBaseUrl)

	sn, err := c.createSession(ctx, currentAuthToken)
	if err != nil {
		return err
	}

	var sessionToken string
	var authToken string

	if sn.AuthUrl == "" {
		authToken = sn.AuthToken
		sessionToken = sn.SessionToken
	} else {
		c.openOrShowAuthUrl(sn)
		authToken, sessionToken, err = c.pollSessionToken(ctx, sn.SessionId)
		if err != nil {
			return err
		}
	}

	_ = storeAuthToken(c.proxyBaseUrl, authToken)

	conn, err := c.dialer(ctx, sn.SessionId, sessionToken)
	if err != nil {
		return err
	}

	// Setup client side of yamux
	session, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}

	if c.localAddr == "-" {
		dst, err := session.Open()
		if err != nil {
			return fmt.Errorf("error dialing %s %s", c.remoteAddr, err.Error())
		}

		util.PipeStdInOut(dst)

		return nil
	}

	listen, err := net.Listen("tcp", c.localAddr)
	if err != nil {
		return err
	}

	quit := make(chan interface{})

	go func() {
		select {
		case <-session.CloseChan():
		case <-ctx.Done():
		}
		close(quit)
		_ = listen.Close()
		_ = session.Close()
	}()

	g := new(errgroup.Group)

	g.Go(func() error {
		for {
			src, err := listen.Accept()
			if err != nil {
				select {
				case <-quit:
					return nil
				default:
					return fmt.Errorf("error accepting connection %s", err.Error())
				}
			}

			go func(src net.Conn) {
				defer src.Close()
				dst, err := session.Open()
				if err != nil {
					logrus.Errorf("error dialing %s %s", c.remoteAddr, err.Error())
					return
				}
				defer dst.Close()
				util.Pipe(src, dst)
			}(src)
		}
	})

	if c.onConnect != nil {
		g.Go(func() error {
			host, port, err := net.SplitHostPort(listen.Addr().String())
			if err != nil {
				return err
			}
			return c.onConnect(ctx, listen.Addr().String(), host, port)
		})
	}

	return g.Wait()
}

func (c *Client) createSession(ctx context.Context, authToken string) (*api.SessionTokenResponse, error) {
	var result api.SessionTokenResponse
	var errMsg api.MessageResponse

	var req = api.CreateSessionRequest{
		AuthToken: authToken,
		Target:    c.remoteAddr,
	}

	resp, err := c.httpClient.R().
		SetBody(&req).
		SetResult(&result).
		SetError(&errMsg).
		SetContext(ctx).
		Post(c.proxyBaseUrl + "/p/session")

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
		Post(c.proxyBaseUrl + "/p/token")

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, &serverError{resp.StatusCode(), errMsg.Message}
	}

	return &result, nil
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
