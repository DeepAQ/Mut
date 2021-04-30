package dns

import (
	"context"
	"net"
)

type systemResolver struct {
}

var System = systemResolver{}

func (systemResolver) Start(_ context.Context) {
}

func (systemResolver) ResolveFakeIP(net.IP) string {
	return ""
}

func (systemResolver) Lookup(host string) (net.IP, error) {
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, err
	}
	return ipAddr.IP, nil
}

func (systemResolver) Debug() string {
	return "systemResolver"
}
