package transport

import (
	"errors"
	"io"
	"net"
	"net/url"
)

type InboundTransport interface {
	InboundTransportName() string
	io.Closer
}

type TcpInboundTransport interface {
	InboundTransport
	net.Listener
}

type OutboundTransport interface {
	OutboundTransportName() string
}

type TcpOutboundTransport interface {
	OutboundTransport
	OpenConnection() (net.Conn, error)
}

func CreateInboundTransport(name string, u *url.URL, inner InboundTransport) (InboundTransport, error) {
	switch name {
	case "tls":
		return NewTLSInboundTransport(u, inner)
	case "mux":
		return NewMuxInboundTransport(u, inner)
	default:
		return nil, errors.New("unsupported inbound transport type " + name)
	}
}

func CreateOutboundTransport(name string, u *url.URL, inner OutboundTransport) (OutboundTransport, error) {
	switch name {
	case "tls":
		return NewTLSOutboundTransport(u, inner)
	case "mux":
		return NewMuxOutboundTransport(u, inner)
	default:
		return nil, errors.New("unsupported outbound transport type " + name)
	}
}
