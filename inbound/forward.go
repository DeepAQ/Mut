package inbound

import (
	"errors"
	"github.com/DeepAQ/mut/router"
	"net"
	"net/url"
)

var (
	errNoTarget = errors.New("no target specified")
)

type forwardProtocol struct {
	target string
}

func NewForwardProtocol(u *url.URL) *forwardProtocol {
	target := u.Query().Get("target")
	return &forwardProtocol{
		target: target,
	}
}

func (f *forwardProtocol) Serve(l net.Listener, r router.Router) error {
	if len(f.target) == 0 {
		return errNoTarget
	}
	return serveListenerWithConnHandler("forward", l, r, f.ServeConn)
}

func (f *forwardProtocol) ServeConn(conn net.Conn, r router.Router) error {
	r.HandleTcpStream("forward", conn, conn.RemoteAddr().String(), f.target)
	return nil
}
