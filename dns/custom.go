package dns

import (
	"encoding/binary"
	"errors"
	"github.com/DeepAQ/mut/global"
	"golang.org/x/net/dns/dnsmessage"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

const (
	maxTTL       = 3600
	fakeIpTTL    = 60
	fakeIpExpire = 5 * time.Minute
)

var (
	errIPv6NotSupported = errors.New("ipv6 not supported")
	errNoResult         = errors.New("no result in the server response")
)

type cacheEntry struct {
	ip     net.IP
	expire time.Time
}

type fakeIpEntry struct {
	host   string
	expire time.Time
}

type customResolver struct {
	bufSize int
	client  Client
	cache   sync.Map //map[string]cacheEntry

	localAddr string
	useFakeIp bool

	fakeIpPrefix uint32
	fakeIpMask   int
	fakeIpMu     sync.Mutex
	fakeIpCurr   uint32
	fakeIpToHost map[uint32]*fakeIpEntry
	hostToFakeIp map[string]uint32
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
				r.cache.Range(func(k, v interface{}) bool {
					ce := v.(cacheEntry)
					if ce.expire.Before(now) {
						r.cache.Delete(k)
					}
					return true
				})

				if r.fakeIpPrefix > 0 {
					r.fakeIpMu.Lock()
					for k, v := range r.fakeIpToHost {
						if v.expire.Before(now) {
							delete(r.fakeIpToHost, k)
							delete(r.hostToFakeIp, v.host)
						}
					}
					r.fakeIpMu.Unlock()
				}
			}
		}
	}()

	if len(r.localAddr) > 0 {
		r.listenLocal()
	}
}

func (r *customResolver) ResolveFakeIP(ip net.IP) string {
	if r.fakeIpPrefix > 0 {
		if ip4 := ip.To4(); ip4 != nil {
			ipInt := binary.BigEndian.Uint32(ip4)
			if ipInt & ^((1<<(32-r.fakeIpMask))-1) == r.fakeIpPrefix {
				r.fakeIpMu.Lock()
				defer r.fakeIpMu.Unlock()
				if v, ok := r.fakeIpToHost[ipInt]; ok {
					v.expire = time.Now().Add(fakeIpExpire)
					return v.host
				}
			}
		}
	}
	return ""
}

func (r *customResolver) Lookup(host string) (net.IP, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			return ip4, nil
		}
		return nil, errIPv6NotSupported
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
		return nil, err
	}
	buf, err = r.client.RoundTrip(buf)
	if err != nil {
		return nil, err
	}
	ips, ttl, err := ipv4ResultFromWire(buf)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, errNoResult
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
	r.cache.Range(func(k, v interface{}) bool {
		ce := v.(cacheEntry)
		tw.Write([]byte(k.(string) + "\t" + ce.ip.String() + "\t" + strconv.Itoa(int(ce.expire.Sub(now).Seconds())) + "s\n"))
		return true
	})
	tw.Flush()

	if r.fakeIpPrefix > 0 {
		sb.WriteString("\nfake ip pool:\n\n")
		tw.Write([]byte("[ip]\t[host]\t[ttl]\n"))
		r.fakeIpMu.Lock()
		for ip, fe := range r.fakeIpToHost {
			tw.Write([]byte(strconv.Itoa(int(ip>>24)) + "." + strconv.Itoa(int((ip>>16)&0xff)) + "." +
				strconv.Itoa(int(ip>>8)&0xff) + "." + strconv.Itoa(int(ip&0xff)) + "\t" + fe.host + "\t" +
				strconv.Itoa(int(fe.expire.Sub(now).Seconds())) + "s\n"))
		}
		r.fakeIpMu.Unlock()
		tw.Flush()
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
		r.fakeIpToHost = map[uint32]*fakeIpEntry{}
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
								if _, ok = r.fakeIpToHost[fip]; !ok {
									break
								}
								if i >= 1<<(32-r.fakeIpMask)-1 {
									global.Stderr.Println("[dns-local] no available addresses in fake ip pool")
									resp = writeServFail(reqBuf)
									goto sendResponse
								}
							}
							r.hostToFakeIp[fakeIpHostname] = fip
							r.fakeIpToHost[fip] = &fakeIpEntry{
								host:   fakeIpHostname,
								expire: time.Now().Add(fakeIpExpire),
							}
						} else {
							r.fakeIpToHost[fip].expire = time.Now().Add(fakeIpExpire)
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
