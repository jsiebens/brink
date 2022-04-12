package util

import (
	"io"
	"net"
	"sync"
)

func NewOneConnListener(c net.Conn, addr net.Addr) net.Listener {
	if addr == nil {
		addr = dummyAddr("one-conn-listener")
	}
	return &oneConnListener{
		addr: addr,
		conn: c,
	}
}

type oneConnListener struct {
	addr net.Addr

	mu   sync.Mutex
	conn net.Conn
}

func (ln *oneConnListener) Accept() (c net.Conn, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	c = ln.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	ln.conn = nil
	return
}

func (ln *oneConnListener) Addr() net.Addr { return ln.addr }

func (ln *oneConnListener) Close() error {
	ln.Accept() // guarantee future call returns io.EOF
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

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
