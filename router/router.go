package router

import (
	"errors"
	"github.com/DeepAQ/mut/dns"
	"github.com/DeepAQ/mut/outbound"
	"github.com/DeepAQ/mut/util"
	"github.com/yl2chen/cidranger"
	"net"
	"os"
	"strings"
	"unsafe"
)

var (
	errRejected  = errors.New("rejected")
	errCosmicRay = errors.New("this device may be affected by cosmic rays")
)

type Router interface {
	DialTcp(targetAddr string) (conn net.Conn, err error, outName, realAddr string)
}

type ruleAction struct {
	rule   Rule
	action Action
}

type router struct {
	ruleSet     []*ruleAction
	finalAction Action
	resolver    dns.Resolver
	defaultOut  outbound.Outbound
	directOut   outbound.Outbound
}

func NewRouter(conf string, resolver dns.Resolver, defaultOut outbound.Outbound) (*router, error) {
	ruleSet := make([]*ruleAction, 0)
	finalAction := ActionDefault
	for _, rule := range strings.Split(conf, ";") {
		if len(rule) == 0 {
			continue
		}

		s := strings.IndexByte(rule, ',')
		var action Action
		switch rule[s+1:] {
		case "direct":
			action = ActionDirect
		case "default":
			action = ActionDefault
		case "reject":
			action = ActionReject
		default:
			return nil, errors.New("unsupported action: " + rule[s+1:])
		}

		r := rule[:s]
		if strings.HasPrefix(r, "domains:") {
			lines, err := readLinesFromFile(r[8:])
			if err != nil {
				return nil, err
			}
			suffixes := map[string]struct{}{}
			for _, line := range lines {
				if len(line) > 0 {
					suffixes[line] = struct{}{}
				}
			}
			ruleSet = append(ruleSet, &ruleAction{
				rule:   &domainRule{suffixes: suffixes},
				action: action,
			})
		} else if strings.HasPrefix(r, "cidr:") {
			lines, err := readLinesFromFile(r[5:])
			if err != nil {
				return nil, err
			}
			ranger := cidranger.NewPCTrieRanger()
			for _, line := range lines {
				if len(line) > 0 {
					if _, cidr, err := net.ParseCIDR(line); err == nil {
						if err := ranger.Insert(cidranger.NewBasicRangerEntry(*cidr)); err != nil {
							return nil, err
						}
					}
				}
			}
			ruleSet = append(ruleSet, &ruleAction{
				rule:   &cidrRule{ranger: ranger},
				action: action,
			})
		} else if r == "final" {
			finalAction = action
		} else {
			return nil, errors.New("unsupported rule definition: " + rule[:s])
		}
	}
	return &router{
		ruleSet:     ruleSet,
		finalAction: finalAction,
		resolver:    resolver,
		defaultOut:  defaultOut,
		directOut:   outbound.Direct(resolver),
	}, nil
}

func (r *router) DialTcp(targetAddr string) (conn net.Conn, err error, outName, realAddr string) {
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	resolved := false
	if ip != nil {
		realHost := r.resolver.ResolveFakeIP(ip)
		if len(realHost) > 0 {
			host = realHost
			ip = nil
		} else {
			resolved = true
		}
	}
	realAddr = host + ":" + port

	action := r.finalAction
	for _, rs := range r.ruleSet {
		if rs.rule.NeedsIP() {
			if !resolved {
				resolved = true
				if ip, err = r.resolver.Lookup(host); err != nil {
					util.Stdout.Println("[router] failed to resolve host: " + err.Error())
				}
			}
			if ip == nil {
				continue
			}
		}
		if rs.rule.Matches(host, ip) {
			action = rs.action
			break
		}
	}

	switch action {
	case ActionReject:
		err = errRejected
	case ActionDirect:
		if ip != nil {
			targetAddr = ip.String() + ":" + port
		}
		conn, err = r.directOut.DialTcp(targetAddr)
		outName = r.directOut.Name()
	case ActionDefault:
		conn, err = r.defaultOut.DialTcp(realAddr)
		outName = r.defaultOut.Name()
	default:
		err = errCosmicRay
	}
	return
}

func readLinesFromFile(filename string) ([]string, error) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(*(*string)(unsafe.Pointer(&fileBytes)), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return lines, nil
}
