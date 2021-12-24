package client

import (
	"context"
	"fmt"
	"github.com/rancher/remotedialer"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
)

type OnConnect func(ctx context.Context, addr, ip, port string) error

type Forwarder struct {
	sync.Mutex

	localAddr string
	onConnect OnConnect

	remoteAddr string
	listener   net.Listener
	session    *remotedialer.Session
}

func NewForwarder(port uint64, target string, onConnect OnConnect) (*Forwarder, error) {
	f := &Forwarder{
		localAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		remoteAddr: target,
		onConnect:  onConnect,
	}

	return f, nil
}

func (f *Forwarder) Start() error {
	listen, err := net.Listen("tcp", f.localAddr)
	if err != nil {
		return err
	}
	f.listener = listen
	go f.startTarget(listen)

	return nil
}

func (f *Forwarder) startTarget(listen net.Listener) {
	logrus.WithField("addr", listen.Addr()).WithField("target", f.remoteAddr).Info("Listener started")
	for {
		conn, err := listen.Accept()
		logrus.WithField("addr", f.localAddr).Trace("New connection")
		if err != nil {
			continue
		}
		go func(source net.Conn, addr string) {
			defer source.Close()
			target, err := f.dial(context.Background(), "tcp", addr)
			if err != nil {
				return
			}
			defer target.Close()
			closer := make(chan struct{}, 2)
			go pipe(closer, target, source)
			go pipe(closer, source, target)
			<-closer
			logrus.WithField("addr", target.LocalAddr).Trace("Connection completed")
		}(conn, f.remoteAddr)
	}
}

func (f *Forwarder) OnTunnelConnect(ctx context.Context, session *remotedialer.Session) error {
	f.Lock()
	f.session = session
	f.Unlock()

	go func() {
		<-ctx.Done()
		f.Lock()
		defer f.Unlock()
		f.session = nil
	}()

	if f.onConnect != nil {
		host, port, err := net.SplitHostPort(f.listener.Addr().String())
		if err != nil {
			panic(err)
		}
		return f.onConnect(ctx, f.listener.Addr().String(), host, port)
	}

	return nil
}

func (f *Forwarder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	var s *remotedialer.Session

	f.Lock()
	s = f.session
	f.Unlock()

	if s == nil {
		return nil, fmt.Errorf("no active connection")
	}

	return s.Dial(ctx, network, address)
}

func pipe(closer chan struct{}, dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
	closer <- struct{}{}
}
