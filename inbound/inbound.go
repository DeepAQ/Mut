package inbound

import (
	"errors"
	"github.com/DeepAQ/mut/router"
	"github.com/DeepAQ/mut/transport"
	"net/url"
	"strings"
)

var (
	errNoProtocol = errors.New("no inbound protocol provided")
)

type Inbound interface {
	Name() string
	Serve(r router.Router) error
}

func CreateInbound(u *url.URL) (Inbound, error) {
	var tp transport.InboundTransport
	var schemeParts []string
	switch u.Scheme {
	case "https", "h2":
		schemeParts = []string{"http", "tls"}
	default:
		schemeParts = strings.Split(u.Scheme, "+")
	}

	if len(schemeParts) == 0 {
		return nil, errNoProtocol
	}
	protocol := schemeParts[0]
	for i := len(schemeParts) - 1; i > 0; i-- {
		newTp, err := transport.CreateInboundTransport(schemeParts[i], u, tp)
		if err != nil {
			if tp != nil {
				tp.Close()
			}
			return nil, err
		}
		tp = newTp
	}

	switch protocol {
	case "http":
		return NewTcpInbound(u, NewHttpProtocol(u), tp)
	case "h3":
		return NewH3Inbound(u), nil
	case "socks", "socks5":
		return NewTcpInbound(u, NewSocksProtocol(u), tp)
	case "mix":
		return NewTcpInbound(u, NewMixProtocol(u), tp)
	case "forward":
		return NewTcpInbound(u, NewForwardProtocol(u), tp)
	case "tun":
		return NewTunInbound(u)
	default:
		return nil, errors.New("unsupported inbound protocol " + protocol)
	}
}
