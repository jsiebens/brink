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

type Forwarder struct {
	sync.Mutex

	target  Target
	session *remotedialer.Session
}

type Target struct {
	LocalAddr  string
	RemoteAddr string
}

func NewForwarder(port uint64, target string) (*Forwarder, error) {
	f := &Forwarder{}

	f.target = Target{
		LocalAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		RemoteAddr: target,
	}

	return f, nil
}

func (f *Forwarder) Start() error {
	listen, err := net.Listen("tcp", f.target.LocalAddr)
	if err != nil {
		return err
	}
	go f.startTarget(listen)

	return nil
}

func (f *Forwarder) startTarget(listen net.Listener) {
	logrus.WithField("addr", listen.Addr()).WithField("target", f.target.RemoteAddr).Info("Listener started")
	for {
		conn, err := listen.Accept()
		logrus.WithField("addr", f.target.LocalAddr).Trace("New connection")
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
		}(conn, f.target.RemoteAddr)
	}
}

func (f *Forwarder) OnTunnelConnect(ctx context.Context, session *remotedialer.Session) error {
	f.Lock()
	defer f.Unlock()
	f.session = session

	go func() {
		<-ctx.Done()
		f.Lock()
		defer f.Unlock()
		f.session = nil
	}()
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
