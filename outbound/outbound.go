package outbound

import (
	"errors"
	"github.com/DeepAQ/mut/dns"
	"github.com/DeepAQ/mut/transport"
	"net"
	"net/url"
	"strings"
)

type Outbound interface {
	Name() string
	DialTcp(targetAddr string) (net.Conn, error)
}

func CreateOutbound(u *url.URL, resolver dns.Resolver) (Outbound, error) {
	var tp transport.OutboundTransport
	var schemeParts []string
	switch u.Scheme {
	case "https":
		schemeParts = []string{"http", "tls"}
	case "h2":
		schemeParts = []string{"h2", "tls"}
	default:
		schemeParts = strings.Split(u.Scheme, "+")
	}

	protocol := schemeParts[0]
	for i := len(schemeParts) - 1; i > 0; i-- {
		newTp, err := transport.CreateOutboundTransport(schemeParts[i], u, tp)
		if err != nil {
			return nil, err
		}
		tp = newTp
	}

	switch protocol {
	case "http":
		return NewHttpOutbound(u, tp)
	case "h2":
		return NewHttp2Outbound(u, tp)
	case "h3":
		return NewHttp3Outbound(u)
	case "socks", "socks5":
		return NewSocksOutbound(u, tp)
	case "direct", "":
		return NewDirectOutbound(resolver), nil
	default:
		return nil, errors.New("unsupported outbound protocol " + u.Scheme)
	}
}
