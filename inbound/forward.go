package inbound

import (
	"errors"
	"net"
	"net/url"
)

var (
	errNoTarget = errors.New("no target specified")
)

type forwardInbound struct {
	target string
}

func Forward(u *url.URL) (*forwardInbound, error) {
	target := u.Query().Get("target")
	if len(target) == 0 {
		return nil, errNoTarget
	}
	return &forwardInbound{
		target: target,
	}, nil
}

func (f *forwardInbound) Name() string {
	return "forward"
}

func (f *forwardInbound) ServeConn(conn net.Conn, handleTcpStream StreamHandler) error {
	handleTcpStream(&TcpStream{
		Conn:       conn,
		Protocol:   "forward",
		ClientAddr: conn.RemoteAddr().String(),
		TargetAddr: f.target,
	})
	return nil
}
