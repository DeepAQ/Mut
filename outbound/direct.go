package outbound

import (
	"github.com/DeepAQ/mut/dns"
	"net"
)

type directOutbound struct {
	resolver dns.Resolver
}

func NewDirectOutbound(resolver dns.Resolver) *directOutbound {
	return &directOutbound{
		resolver: resolver,
	}
}

func (d *directOutbound) Name() string {
	return "direct"
}

func (d *directOutbound) RemoteDNS() bool {
	return false
}

func (d *directOutbound) DialTcp(targetAddr string) (net.Conn, error) {
	if d.resolver != nil {
		host, port, err := net.SplitHostPort(targetAddr)
		if err != nil {
			return nil, err
		}
		ip, err := d.resolver.Lookup(host)
		if err != nil {
			return nil, err
		}
		return net.Dial("tcp", ip.String()+":"+port)
	}
	return net.Dial("tcp", targetAddr)
}
