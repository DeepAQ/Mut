package dns

import (
	"container/list"
	"errors"
	"github.com/DeepAQ/mut/global"
	"golang.org/x/net/dns/dnsmessage"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const (
	maxTTL     = 3600
	fakeIpTTL  = 10
	fakeIpSize = 100
)

var (
	errIPv6NotSupported = errors.New("ipv6 not supported")
	errNoResult         = errors.New("no result in the server response")
)

type cacheEntry struct {
	ip     netip.Addr
	expire time.Time
}

type fakeIpEntry struct {
	host   string
	fakeIp uint32
}

type customResolver struct {
	client          Client
	fakeIpList      *list.List // of fakeIpEntry
	fakeIpToElement map[uint32]*list.Element
	hostToFakeIp    map[string]uint32
	cache           sync.Map // map[string]cacheEntry
	localAddr       string
	bufSize         int
	fakeIpMask      int
	fakeIpMu        sync.Mutex
	fakeIpCurr      uint32
	fakeIpPrefix    uint32
	useFakeIp       bool
}

func NewCustomResolver(bufSize int, client Client) *customResolver {
	r := &customResolver{
		bufSize: bufSize,
		client:  client,
	}
	return r
}

func (r *customResolver) Start() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				r.cache.Range(func(k, v any) bool {
					ce := v.(cacheEntry)
					if ce.expire.Before(now) {
						r.cache.Delete(k)
					}
					return true
				})
			}
		}
	}()

	if len(r.localAddr) > 0 {
		r.listenLocal()
	}
}

func (r *customResolver) ResolveFakeIP(ip netip.Addr) string {
	if r.fakeIpPrefix > 0 {
		if ip.Is4() {
			ip4 := ip.As4()
			ipInt := uint32(ip4[3]) | uint32(ip4[2])<<8 | uint32(ip4[1])<<16 | uint32(ip4[0])<<24
			if ipInt & ^((1<<(32-r.fakeIpMask))-1) == r.fakeIpPrefix {
				r.fakeIpMu.Lock()
				defer r.fakeIpMu.Unlock()
				if element, ok := r.fakeIpToElement[ipInt]; ok {
					r.fakeIpList.MoveToBack(element)
					return element.Value.(fakeIpEntry).host
				}
			}
		}
	}
	return ""
}

func (r *customResolver) Lookup(host string) (netip.Addr, error) {
	ip, _ := netip.ParseAddr(host)
	if ip.IsValid() {
		if ip.Is4() {
			return ip, nil
		}
		return netip.Addr{}, errIPv6NotSupported
	}

	if v, ok := r.cache.Load(host); ok {
		ce := v.(cacheEntry)
		if ce.expire.After(time.Now()) {
			return ce.ip, nil
		}
	}

	buf := global.BufPool.Get(r.bufSize)
	defer global.BufPool.Put(buf)
	buf, err := queryToWire(buf, host, dnsmessage.TypeA)
	if err != nil {
		return netip.Addr{}, err
	}
	buf, err = r.client.RoundTrip(buf)
	if err != nil {
		return netip.Addr{}, err
	}
	ips, ttl, err := ipv4ResultFromWire(buf)
	if err != nil {
		return netip.Addr{}, err
	}

	if len(ips) == 0 {
		return netip.Addr{}, errNoResult
	}

	ip = ips[rand.Intn(len(ips))]
	if ttl > 0 {
		if ttl > maxTTL {
			ttl = maxTTL
		}
		r.cache.Store(host, cacheEntry{
			ip:     ip,
			expire: time.Now().Add(time.Duration(ttl) * time.Second),
		})
	}
	return ip, nil
}

func (r *customResolver) Debug() string {
	sb := strings.Builder{}
	tw := tabwriter.NewWriter(&sb, 0, 0, 1, ' ', 0)
	sb.WriteString("dns cache:\n\n")
	tw.Write([]byte("[host]\t[ip]\t[ttl]\n"))
	now := time.Now()
	r.cache.Range(func(k, v any) bool {
		ce := v.(cacheEntry)
		tw.Write([]byte(k.(string) + "\t" + ce.ip.String() + "\t" + strconv.Itoa(int(ce.expire.Sub(now).Seconds())) + "s\n"))
		return true
	})
	tw.Flush()

	if r.fakeIpPrefix > 0 {
		r.fakeIpMu.Lock()
		sb.WriteString("\nfake ip list:\n\n")
		tw.Write([]byte("[ip]\t[host]\n"))
		for element := r.fakeIpList.Front(); element != nil; element = element.Next() {
			entry := element.Value.(fakeIpEntry)
			ip := entry.fakeIp
			tw.Write([]byte(strconv.Itoa(int(ip>>24)) + "." + strconv.Itoa(int((ip>>16)&0xff)) + "." +
				strconv.Itoa(int(ip>>8)&0xff) + "." + strconv.Itoa(int(ip&0xff)) + "\t" + entry.host + "\n"))
		}
		tw.Flush()

		sb.WriteString("\nhost -> fake ip:\n\n")
		tw.Write([]byte("[host]\t[ip]\n"))
		for host, ip := range r.hostToFakeIp {
			tw.Write([]byte(host + "\t" + strconv.Itoa(int(ip>>24)) + "." + strconv.Itoa(int((ip>>16)&0xff)) + "." +
				strconv.Itoa(int(ip>>8)&0xff) + "." + strconv.Itoa(int(ip&0xff)) + "\n"))
		}
		tw.Flush()
		r.fakeIpMu.Unlock()
	}
	return sb.String()
}

func (r *customResolver) listenLocal() {
	conn, err := net.ListenPacket("udp", r.localAddr)
	if err != nil {
		global.Stderr.Println("[dns-local] failed to listen on " + r.localAddr + ": " + err.Error())
		return
	}
	global.Stdout.Println("[dns-local] listening on " + r.localAddr)
	if r.useFakeIp {
		// temp: use 198.18.0.0/16 as fake ip range
		r.fakeIpPrefix = 198<<24 + 18<<16
		r.fakeIpMask = 16
		r.fakeIpList = list.New()
		r.fakeIpToElement = map[uint32]*list.Element{}
		r.hostToFakeIp = map[string]uint32{}
	}

	go func() {
		reqBuf := global.BufPool.Get(r.bufSize)
		defer global.BufPool.Put(reqBuf)
		respBuf := global.BufPool.Get(udpPacketSize)
		defer global.BufPool.Put(respBuf)
		parser := dnsmessage.Parser{}

		for {
			n, rAddr, err := conn.ReadFrom(reqBuf)
			if err != nil {
				global.Stderr.Println("[dns-local] failed to read request: " + err.Error())
				return
			}

			var resp []byte
			if r.fakeIpPrefix > 0 {
				reqHeader, err := parser.Start(reqBuf[:n])
				if err != nil {
					global.Stderr.Println("[dns-local] failed to parse request: " + err.Error())
					resp = writeServFail(reqBuf)
					goto sendResponse
				}
				if reqHeader.OpCode == 0 {
					reqQuestion, err := parser.Question()
					if err != nil {
						global.Stderr.Println("[dns-local] failed to parse request question: " + err.Error())
						resp = writeServFail(reqBuf)
						goto sendResponse
					}
					if reqQuestion.Type == dnsmessage.TypeA && reqQuestion.Class == dnsmessage.ClassINET {
						fakeIpHostname := reqQuestion.Name.String()[:reqQuestion.Name.Length-1]
						r.fakeIpMu.Lock()
						fip, ok := r.hostToFakeIp[fakeIpHostname]
						if !ok {
							for i := 0; ; i++ {
								r.fakeIpCurr = (r.fakeIpCurr + 1) % (1 << (32 - r.fakeIpMask))
								fip = r.fakeIpPrefix + r.fakeIpCurr
								if _, ok = r.fakeIpToElement[fip]; !ok {
									break
								}
								if i >= 1<<(32-r.fakeIpMask)-1 {
									r.fakeIpMu.Unlock()
									global.Stderr.Println("[dns-local] no available addresses in fake ip pool")
									resp = writeServFail(reqBuf)
									goto sendResponse
								}
							}

							r.hostToFakeIp[fakeIpHostname] = fip
							r.fakeIpToElement[fip] = r.fakeIpList.PushBack(fakeIpEntry{
								fakeIp: fip,
								host:   fakeIpHostname,
							})
							if r.fakeIpList.Len() > fakeIpSize {
								oldEntry := r.fakeIpList.Remove(r.fakeIpList.Front()).(fakeIpEntry)
								delete(r.fakeIpToElement, oldEntry.fakeIp)
								delete(r.hostToFakeIp, oldEntry.host)
							}
						} else {
							r.fakeIpList.MoveToBack(r.fakeIpToElement[fip])
						}
						r.fakeIpMu.Unlock()
						resp, err = ipv4AnswerToWire(reqHeader, reqQuestion, fip, fakeIpTTL, respBuf)
						if err != nil {
							global.Stderr.Println("[dns-local] failed to build response: " + err.Error())
							resp = writeServFail(reqBuf)
						}
						goto sendResponse
					}
				}
			}

			resp, err = r.client.RoundTrip(reqBuf[:n])
			if err != nil {
				global.Stderr.Println("[dns-local] failed to resolve: " + err.Error())
				resp = writeServFail(reqBuf)
			} else {
				resp, err = compressMessage(resp, respBuf)
				if err != nil {
					global.Stderr.Println("[dns-local] failed to build response: " + err.Error())
					resp = writeServFail(reqBuf)
				}
			}

		sendResponse:
			if _, err := conn.WriteTo(resp, rAddr); err != nil {
				global.Stderr.Println("[dns-local] failed to write response: " + err.Error())
			}
		}
	}()
}
