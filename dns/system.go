package dns

import (
	"net"
	"net/netip"
)

type systemResolver struct {
}

var System = systemResolver{}

func (systemResolver) Start() {
}

func (systemResolver) ResolveFakeIP(netip.Addr) string {
	return ""
}

func (systemResolver) Lookup(host string) (netip.Addr, error) {
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}

	ip, _ := netip.AddrFromSlice(ipAddr.IP)
	return ip, nil
}

func (systemResolver) Debug() string {
	return "systemResolver"
}
