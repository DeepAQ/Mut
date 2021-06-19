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
	errRejected  = errors.New("rejected")
	errCosmicRay = errors.New("this device may be affected by cosmic rays")
)

type UdpPacketReceiver interface {
	ReplyUdpPacket(clientAddr, remoteAddr net.Addr, data []byte)
}

type Router interface {
	DialTcp(targetAddr string) (conn net.Conn, err error, outName, realAddr string)
	HandleTcpStream(protocolName string, conn net.Conn, clientAddr, targetAddr string)
	SendUdpPacket(src UdpPacketReceiver, protocol string, clientAddr net.Addr, targetAddr string, data []byte)
}

type Action uint8

var (
	ActionDirect  Action = 0
	ActionDefault Action = 1
	ActionReject  Action = 2
)

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
	udpNatMap   sync.Map //map[string]net.PacketConn
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
			ruleSet = append(ruleSet, &ruleAction{
				rule:   NewDomainRule(lines),
				action: action,
			})
		} else if strings.HasPrefix(r, "cidr:") {
			lines, err := readLinesFromFile(r[5:])
			if err != nil {
				return nil, err
			}
			ruleSet = append(ruleSet, &ruleAction{
				rule:   NewCIDRRule(lines),
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
		directOut:   outbound.NewDirectOutbound(resolver),
	}, nil
}

func (r *router) DialTcp(targetAddr string) (conn net.Conn, err error, outName, realAddr string) {
	host, port, ip := r.resolveRealAddr(targetAddr)
	realAddr = host + ":" + port
	resolved := ip != nil

	action := r.finalAction
	for _, rs := range r.ruleSet {
		if rs.rule.NeedsIP() {
			if !resolved {
				resolved = true
				if ip, err = r.resolver.Lookup(host); err != nil {
					global.Stderr.Println("[router] failed to resolve host: " + err.Error())
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

func (r *router) SendUdpPacket(src UdpPacketReceiver, protocol string, clientAddr net.Addr, targetAddr string, data []byte) {
	host, port, ip := r.resolveRealAddr(targetAddr)
	if ip == nil {
		var err error
		if ip, err = r.resolver.Lookup(host); err != nil {
			global.Stderr.Println("[" + protocol + "] failed to resolve host: " + err.Error())
			return
		}
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		global.Stderr.Println("[" + protocol + "] invalid port: " + port)
		return
	}
	dAddr := &net.UDPAddr{
		IP:   ip,
		Port: portInt,
		Zone: "",
	}

	natKey := clientAddr.String()
	var cConn net.PacketConn
	if conn, ok := r.udpNatMap.Load(natKey); !ok {
		conn, err := net.ListenPacket("udp", "")
		if err != nil {
			global.Stderr.Println("[" + protocol + "] failed to open connection: " + err.Error())
			return
		}
		global.Stdout.Println("[" + protocol + "] " + natKey + " <-> " + conn.LocalAddr().String())
		go r.udpReadLoop(src, protocol, clientAddr, conn)
		r.udpNatMap.Store(natKey, conn)
		cConn = conn
	} else {
		cConn = conn.(net.PacketConn)
	}

	cConn.SetDeadline(time.Now().Add(global.UdpStreamTimeout))
	if _, err := cConn.WriteTo(data, dAddr); err != nil {
		global.Stderr.Println("[" + protocol + "] " + err.Error())
	}
}

func (r *router) udpReadLoop(src UdpPacketReceiver, protocol string, clientAddr net.Addr, lConn net.PacketConn) {
	buf := global.BufPool.Get(global.UdpMaxLength)
	defer global.BufPool.Put(buf)

	for {
		lConn.SetDeadline(time.Now().Add(global.UdpStreamTimeout))
		n, addr, err := lConn.ReadFrom(buf)
		if err != nil {
			break
		}
		src.ReplyUdpPacket(clientAddr, addr, buf[:n])
	}

	natKey := clientAddr.String()
	global.Stdout.Println("[" + protocol + "] " + natKey + " >-< " + lConn.LocalAddr().String())
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
