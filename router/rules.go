package router

import (
	"github.com/yl2chen/cidranger"
	"net"
	"strings"
)

type Rule interface {
	NeedsIP() bool
	Matches(host string, ip net.IP) bool
}

type domainRule struct {
	suffixes map[string]struct{}
}

func (r *domainRule) NeedsIP() bool {
	return false
}

func (r *domainRule) Matches(host string, ip net.IP) bool {
	i := len(host)
	for {
		i = strings.LastIndexByte(host[:i], '.')
		if _, ok := r.suffixes[host[i+1:]]; ok {
			return true
		}
		if i <= 0 {
			return false
		}
	}
}

type cidrRule struct {
	ranger cidranger.Ranger
}

func (r *cidrRule) NeedsIP() bool {
	return true
}

func (r *cidrRule) Matches(host string, ip net.IP) bool {
	if ok, err := r.ranger.Contains(ip); err != nil {
		return false
	} else {
		return ok
	}
}

//type PortRule struct {
//	port uint16
//}
//
//func (r *PortRule) NeedsIP() bool {
//	return false
//}
//
//func (r *PortRule) Matches(host string, ip net.IP, port uint16) bool {
//	return r.port == port
//}
