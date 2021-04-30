package outbound

import (
	"errors"
	"github.com/DeepAQ/mut/dns"
	"net"
	"net/url"
)

type Outbound interface {
	Name() string
	DialTcp(targetAddr string) (net.Conn, error)
}

func CreateOutbound(u *url.URL, resolver dns.Resolver) (Outbound, error) {
	switch u.Scheme {
	case "http":
		return Http(u)
	case "https":
		return Https(u)
	case "h2":
		return Http2(u)
	case "socks", "socks5":
		return Socks(u)
	case "direct", "":
		return Direct(resolver), nil
	default:
		return nil, errors.New("unsupported outbound type " + u.Scheme)
	}
}
