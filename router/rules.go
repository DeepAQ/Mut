package router

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Rule interface {
	NeedsIP() bool
	Matches(host string, ip netip.Addr) bool
}

type domainRule struct {
	suffixes map[string]struct{}
}

func NewDomainRule(domains []string) *domainRule {
	suffixes := map[string]struct{}{}
	for _, line := range domains {
		if len(line) > 0 {
			suffixes[line] = struct{}{}
		}
	}
	return &domainRule{suffixes: suffixes}
}

func (r *domainRule) NeedsIP() bool {
	return false
}

func (r *domainRule) Matches(host string, _ netip.Addr) bool {
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
	cidrs     map[uint64]struct{}
	minPrefix int
	maxPrefix int
}

func NewCIDRRule(cidrs []string) *cidrRule {
	cidrRule := &cidrRule{
		cidrs:     map[uint64]struct{}{},
		minPrefix: 32,
		maxPrefix: 0,
	}
	for _, line := range cidrs {
		if ipAndPrefix := strings.Split(line, "/"); len(ipAndPrefix) == 2 {
			if prefix, err := strconv.Atoi(ipAndPrefix[1]); err == nil {
				if ip := net.ParseIP(ipAndPrefix[0]); ip != nil {
					if ip4 := ip.To4(); ip4 != nil {
						ipInt := binary.BigEndian.Uint32(ip4)
						cidrInt := uint64(ipInt>>(32-prefix))<<(64-prefix) + uint64(prefix)
						cidrRule.cidrs[cidrInt] = struct{}{}
						if prefix < cidrRule.minPrefix {
							cidrRule.minPrefix = prefix
						}
						if prefix > cidrRule.maxPrefix {
							cidrRule.maxPrefix = prefix
						}
					}
				}
			}
		}
	}
	return cidrRule
}

func (r *cidrRule) NeedsIP() bool {
	return true
}

func (r *cidrRule) Matches(_ string, ip netip.Addr) bool {
	if ip.Is4() {
		ip4 := ip.As4()
		ipInt := uint32(ip4[3]) | uint32(ip4[2])<<8 | uint32(ip4[1])<<16 | uint32(ip4[0])<<24
		for i := r.minPrefix; i <= r.maxPrefix; i++ {
			if _, ok := r.cidrs[uint64(ipInt>>(32-i))<<(64-i)+uint64(i)]; ok {
				return true
			}
		}
	}
	return false
}
