package dns

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"time"
)

const (
	udpPacketSize = 1024
	dohPacketSize = 2048
)

type Resolver interface {
	ResolveFakeIP(ip net.IP) string
	Lookup(host string) (net.IP, error)
	Debug() string
}

type Client interface {
	RoundTrip(req []byte) ([]byte, error)
}

func CreateResolver(u *url.URL) (*customResolver, error) {
	var r *customResolver
	timeoutSetting, err := strconv.Atoi(u.Query().Get("timeout"))
	if timeoutSetting <= 0 || err != nil {
		timeoutSetting = 1
	}
	timeout := time.Duration(timeoutSetting) * time.Second
	switch u.Scheme {
	case "udp", "":
		r = NewCustomResolver(udpPacketSize, NewUDPClient(u.Host, timeout))
	case "doh", "https":
		r = NewCustomResolver(dohPacketSize, NewDoHClient(u.Host+u.Path, timeout))
	default:
		return nil, errors.New("unsupported dns type " + u.Scheme)
	}

	r.localAddr = u.Query().Get("local_listen")
	r.useFakeIp = u.Query().Get("fake_ip") == "1"
	return r, nil
}
