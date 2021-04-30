package inbound

import (
	"errors"
	"github.com/DeepAQ/mut/router"
	"io"
	"net"
	"net/url"
	"sync/atomic"
)

type Inbound interface {
	Name() string
	ServeConn(conn net.Conn, handleTcpStream StreamHandler) error
}

func CreateInbound(u *url.URL, rt router.Router) (Inbound, error) {
	switch u.Scheme {
	case "http":
		return Http(u, rt)
	case "https", "h2":
		return Https(u, rt)
	case "socks", "socks5":
		return Socks(u)
	case "mix":
		return Mix(u, rt)
	case "forward":
		return Forward(u)
	default:
		return nil, errors.New("unsupported inbound type " + u.Scheme)
	}
}

type TcpStream struct {
	Conn       io.ReadWriteCloser
	Protocol   string
	ClientAddr string
	TargetAddr string
}

type StreamHandler func(*TcpStream)

type connListener struct {
	conn     net.Conn
	consumed uint32
}

func (c *connListener) Accept() (net.Conn, error) {
	if atomic.CompareAndSwapUint32(&c.consumed, 0, 1) {
		return c.conn, nil
	} else {
		return nil, net.ErrClosed
	}
}

func (c *connListener) Close() error {
	atomic.StoreUint32(&c.consumed, 1)
	return nil
}

func (c *connListener) Addr() net.Addr {
	return c.conn.LocalAddr()
}
