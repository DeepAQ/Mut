package inbound

import (
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/router"
	"github.com/DeepAQ/mut/transport"
	"net"
	"net/url"
)

type TcpProtocol interface {
	Serve(l net.Listener, r router.Router) error
}

type tcpInboundWrapper struct {
	protocol  TcpProtocol
	transport transport.TcpInboundTransport
	name      string
}

func NewTcpInbound(u *url.URL, protocol TcpProtocol, tp transport.InboundTransport) (*tcpInboundWrapper, error) {
	tcpTransport, err := transport.RequireTcpInboundTransport(u, tp)
	if err != nil {
		return nil, err
	}
	return &tcpInboundWrapper{
		name:      u.Scheme,
		protocol:  protocol,
		transport: tcpTransport,
	}, nil
}

func (t *tcpInboundWrapper) Name() string {
	return t.name
}

func (t *tcpInboundWrapper) Serve(r router.Router) error {
	global.Stdout.Println("[" + t.Name() + "] serving on " + t.transport.Addr().String())
	return t.protocol.Serve(t.transport, r)
}

type connHandler func(conn net.Conn, r router.Router) error

func serveListenerWithConnHandler(protocolName string, l net.Listener, r router.Router, handler connHandler) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := handler(conn, r); err != nil && err != net.ErrClosed {
				global.Stderr.Println("[" + protocolName + "] failed to serve conn from " + conn.RemoteAddr().String() + ": " + err.Error())
			}
		}()
	}
}
