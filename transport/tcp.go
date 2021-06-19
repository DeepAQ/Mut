package transport

import (
	"errors"
	"net"
	"net/url"
)

const (
	tcpTransportName = "tcp"
)

var (
	errInnerNotTcp = errors.New("requires a tcp-supported inner transport")
)

func RequireTcpInboundTransport(u *url.URL, inner InboundTransport) (TcpInboundTransport, error) {
	if inner != nil {
		tInner, ok := inner.(TcpInboundTransport)
		if !ok {
			return nil, errInnerNotTcp
		}
		return tInner, nil
	}
	return NewDefaultTcpInboundTransport(u)
}

func RequireTcpOutboundTransport(u *url.URL, inner OutboundTransport) (TcpOutboundTransport, error) {
	if inner != nil {
		tInner, ok := inner.(TcpOutboundTransport)
		if !ok {
			return nil, errInnerNotTcp
		}
		return tInner, nil
	}
	return NewDefaultTcpOutboundTransport(u)
}

type defaultTcpInboundTransport struct {
	*net.TCPListener
}

func NewDefaultTcpInboundTransport(u *url.URL) (TcpInboundTransport, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	return defaultTcpInboundTransport{
		TCPListener: l,
	}, nil
}

func (t defaultTcpInboundTransport) InboundTransportName() string {
	return tcpTransportName
}

type defaultTcpOutboundTransport struct {
	targetAddr *net.TCPAddr
}

func NewDefaultTcpOutboundTransport(u *url.URL) (TcpOutboundTransport, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	return defaultTcpOutboundTransport{
		targetAddr: tcpAddr,
	}, nil
}

func (d defaultTcpOutboundTransport) OutboundTransportName() string {
	return tcpTransportName
}

func (d defaultTcpOutboundTransport) OpenConnection() (net.Conn, error) {
	return net.DialTCP("tcp", nil, d.targetAddr)
}
