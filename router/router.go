package router

import (
	"errors"
	"github.com/DeepAQ/mut/dns"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/outbound"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	errRejected = errors.New("rejected")
)

type UdpPacketReceiver func(remoteAddr net.Addr, data []byte)

type Router interface {
	DialTcp(targetAddr string) (conn net.Conn, err error, outName, realAddr string)
	HandleTcpStream(protocolName string, conn net.Conn, clientAddr, targetAddr string)
	SendUdpPacket(protocolName string, clientAddr, targetAddr string, data []byte, receiver UdpPacketReceiver)
}

type routerRule struct {
	rule   Rule
	outTag string
}

type router struct {
	outbounds map[string]outbound.Outbound
	ruleSet   []*routerRule
	finalOut  string
	resolver  dns.Resolver
	udpNatMap sync.Map //map[string]net.PacketConn
}

func NewRouter(conf string, resolver dns.Resolver, outbounds map[string]outbound.Outbound) (*router, error) {
	if _, ok := outbounds["default"]; !ok {
		outbounds["default"] = outbound.NewDirectOutbound(resolver)
	}
	if _, ok := outbounds["direct"]; !ok {
		outbounds["direct"] = outbound.NewDirectOutbound(resolver)
	}

	ruleSet := make([]*routerRule, 0)
	finalOut := "default"
	for _, rule := range strings.Split(conf, ";") {
		if len(rule) == 0 {
			continue
		}

		s := strings.IndexByte(rule, ',')
		outTag := rule[s+1:]
		if outTag != "reject" {
			if _, ok := outbounds[outTag]; !ok {
				return nil, errors.New("unknown outbound tag: " + outTag)
			}
		}

		ruleStr := rule[:s]
		if strings.HasPrefix(ruleStr, "domains:") {
			lines, err := readLinesFromFile(ruleStr[8:])
			if err != nil {
				return nil, err
			}
			ruleSet = append(ruleSet, &routerRule{
				rule:   NewDomainRule(lines),
				outTag: outTag,
			})
		} else if strings.HasPrefix(ruleStr, "cidr:") {
			lines, err := readLinesFromFile(ruleStr[5:])
			if err != nil {
				return nil, err
			}
			ruleSet = append(ruleSet, &routerRule{
				rule:   NewCIDRRule(lines),
				outTag: outTag,
			})
		} else if ruleStr == "final" {
			finalOut = outTag
		} else {
			return nil, errors.New("unsupported rule definition: " + rule[:s])
		}
	}

	return &router{
		outbounds: outbounds,
		ruleSet:   ruleSet,
		finalOut:  finalOut,
		resolver:  resolver,
	}, nil
}

func (r *router) DialTcp(targetAddr string) (conn net.Conn, err error, outTag, realAddr string) {
	host, port, ip := r.resolveRealAddr(targetAddr)
	realAddr = host + ":" + port
	resolved := ip != nil

	outTag = r.finalOut
	for _, rs := range r.ruleSet {
		if rs.rule.NeedsIP() {
			if !resolved {
				resolved = true
				if ip, err = r.resolver.Lookup(host); err != nil {
					global.Stderr.Println("[router] failed to resolve " + host + ": " + err.Error())
				}
			}
			if ip == nil {
				continue
			}
		}
		if rs.rule.Matches(host, ip) {
			outTag = rs.outTag
			break
		}
	}

	switch outTag {
	case "reject":
		err = errRejected
	default:
		out := r.outbounds[outTag]
		if ip != nil && !out.RemoteDNS() {
			conn, err = out.DialTcp(ip.String() + ":" + port)
		} else {
			conn, err = out.DialTcp(realAddr)
		}
	}
	return
}

func (r *router) HandleTcpStream(protocolName string, conn net.Conn, clientAddr, targetAddr string) {
	if global.FreeMemoryInterval > 0 {
		now := time.Now().Unix()
		last := atomic.LoadInt64(&global.LastMemoryFree)
		if int(now-last) >= global.FreeMemoryInterval && atomic.CompareAndSwapInt64(&global.LastMemoryFree, last, now) {
			global.FreeOSMemory()
		}
	}

	dConn, err, outName, realAddr := r.DialTcp(targetAddr)
	if err != nil {
		conn.Close()
		global.Stderr.Println("[" + protocolName + "] " + clientAddr + " -" + outName + "-> " + realAddr + " error: " + err.Error())
		return
	}

	global.Stdout.Println("[" + protocolName + "] " + clientAddr + " <-" + outName + "-> " + realAddr)
	go relay(conn, dConn)
	relay(dConn, conn)
	global.Stdout.Println("[" + protocolName + "] " + clientAddr + " >-" + outName + "-< " + realAddr)
}

func (r *router) SendUdpPacket(protocolName, natKey, targetAddr string, data []byte, receiver UdpPacketReceiver) {
	host, port, ip := r.resolveRealAddr(targetAddr)
	if ip == nil {
		var err error
		if ip, err = r.resolver.Lookup(host); err != nil {
			global.Stderr.Println("[" + protocolName + "-udp] failed to resolve host: " + err.Error())
			return
		}
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		global.Stderr.Println("[" + protocolName + "-udp] invalid port: " + port)
		return
	}
	dAddr := &net.UDPAddr{
		IP:   ip,
		Port: portInt,
		Zone: "",
	}

	var cConn net.PacketConn
	if conn, ok := r.udpNatMap.Load(natKey); !ok {
		conn, err := net.ListenPacket("udp", "")
		if err != nil {
			global.Stderr.Println("[" + protocolName + "-udp] failed to open connection: " + err.Error())
			return
		}
		global.Stdout.Println("[" + protocolName + "-udp] " + natKey + " <-> " + conn.LocalAddr().String() + " -> " + targetAddr)
		go r.udpReadLoop(protocolName, natKey, conn, receiver)
		r.udpNatMap.Store(natKey, conn)
		cConn = conn
	} else {
		cConn = conn.(net.PacketConn)
	}

	cConn.SetDeadline(time.Now().Add(global.UdpStreamTimeout))
	if _, err := cConn.WriteTo(data, dAddr); err != nil {
		global.Stderr.Println("[" + protocolName + "-udp] " + err.Error())
	}
}

func (r *router) udpReadLoop(protocolName, natKey string, lConn net.PacketConn, receiver UdpPacketReceiver) {
	buf := global.BufPool.Get(global.UdpMaxLength)
	defer global.BufPool.Put(buf)

	for {
		lConn.SetDeadline(time.Now().Add(global.UdpStreamTimeout))
		n, addr, err := lConn.ReadFrom(buf)
		if err != nil {
			break
		}
		receiver(addr, buf[:n])
	}

	global.Stdout.Println("[" + protocolName + "-udp] " + natKey + " >-< " + lConn.LocalAddr().String())
	r.udpNatMap.Delete(natKey)
	lConn.Close()
}

func (r *router) resolveRealAddr(targetAddr string) (host, port string, ip net.IP) {
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return
	}
	ip = net.ParseIP(host)
	if ip != nil {
		realHost := r.resolver.ResolveFakeIP(ip)
		if len(realHost) > 0 {
			host = realHost
			ip = nil
		}
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

func relay(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()
	buf := global.BufPool.Get(global.ConnBufSize)
	defer global.BufPool.Put(buf)

	for {
		src.SetDeadline(time.Now().Add(global.TcpStreamTimeout))
		nr, err := src.Read(buf)
		if err != nil {
			return
		}

		dst.SetDeadline(time.Now().Add(global.TcpStreamTimeout))
		if nw, err := dst.Write(buf[:nr]); nw < nr || err != nil {
			return
		}
	}
}
