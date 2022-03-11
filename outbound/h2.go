package outbound

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/transport"
	"golang.org/x/net/http2"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type h2Outbound struct {
	transport transport.TcpOutboundTransport
	host      string
	needsAuth bool
	username  string
	password  string
	aliveTime time.Duration

	h2Transports []*http2.Transport
	tMutex       []sync.Mutex
	tDeadline    []time.Time
}

const (
	Http2DefaultConcurrency = 8
	Http2MaxConcurrency     = 100
	Http2DefaultAliveTime   = 0
	Http2RequestTimeOut     = 5 * time.Second
)

func NewHttp2Outbound(u *url.URL, tp transport.OutboundTransport) (*h2Outbound, error) {
	tcpTransport, err := transport.RequireTcpOutboundTransport(u, tp)
	if err != nil {
		return nil, err
	}

	if tlsTransport, ok := tcpTransport.(transport.TLSTransport); ok {
		tlsTransport.TLSConfig().NextProtos = []string{"h2", "http/1.1"}
	}

	username := u.User.Username()
	password, _ := u.User.Password()
	concurrency, err := strconv.Atoi(u.Query().Get("concurrency"))
	if concurrency <= 0 || err != nil {
		concurrency = Http2DefaultConcurrency
	} else if concurrency > Http2MaxConcurrency {
		concurrency = Http2MaxConcurrency
	}
	aliveTime, err := strconv.Atoi(u.Query().Get("alive"))
	if aliveTime <= 0 || err != nil {
		aliveTime = Http2DefaultAliveTime
	}

	h := &h2Outbound{
		transport: tcpTransport,
		host:      u.Host,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
		aliveTime: time.Duration(aliveTime) * time.Second,

		h2Transports: make([]*http2.Transport, concurrency),
		tMutex:       make([]sync.Mutex, concurrency),
		tDeadline:    make([]time.Time, concurrency),
	}
	return h, nil
}

func (h *h2Outbound) Name() string {
	return "h2"
}

func (h *h2Outbound) RemoteDNS() bool {
	return true
}

func (h *h2Outbound) DialTcp(targetAddr string) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "https://"+h.host, pr)
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, err
	}
	req.Host = targetAddr
	req.Header.Set("User-Agent", "")
	if h.needsAuth {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(h.username+":"+h.password)))
	}

	resp, err := h.getRandomTransport().RoundTrip(req)
	if err != nil {
		req.Body.Close()
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		req.Body.Close()
		pw.Close()
		return nil, errors.New("remote server responded with " + resp.Status)
	}

	return &h2ConnWrapper{
		reqWriter: pw,
		resp:      resp,
	}, nil
}

func (h *h2Outbound) getRandomTransport() *http2.Transport {
	i := rand.Intn(len(h.h2Transports))
	if h.h2Transports[i] == nil || (h.aliveTime > 0 && h.tDeadline[i].Before(time.Now())) {
		h.tMutex[i].Lock()
		defer h.tMutex[i].Unlock()
		if h.h2Transports[i] == nil || (h.aliveTime > 0 && h.tDeadline[i].Before(time.Now())) {
			if h.h2Transports[i] != nil {
				h.h2Transports[i].CloseIdleConnections()
			}
			global.Stdout.Println("[h2-debug] creating new client transport of " + strconv.Itoa(i))
			h.h2Transports[i] = &http2.Transport{
				DialTLS: func(_, _ string, _ *tls.Config) (net.Conn, error) {
					return h.transport.OpenConnection()
				},
				MaxFrameSize:    uint32(global.ConnBufSize),
				IdleConnTimeout: global.TcpStreamTimeout,
			}
			if h.aliveTime > 0 {
				h.tDeadline[i] = time.Now().Add(h.aliveTime)
			}
		}
	}

	return h.h2Transports[i]
}

type h2ConnWrapper struct {
	reqWriter io.WriteCloser
	resp      *http.Response
}

func (h *h2ConnWrapper) Read(p []byte) (n int, err error) {
	return h.resp.Body.Read(p)
}

func (h *h2ConnWrapper) Write(p []byte) (n int, err error) {
	return h.reqWriter.Write(p)
}

func (h *h2ConnWrapper) Close() error {
	h.reqWriter.Close()
	return h.resp.Body.Close()
}

func (h *h2ConnWrapper) LocalAddr() net.Addr {
	return h2Addr{}
}

func (h *h2ConnWrapper) RemoteAddr() net.Addr {
	return h2Addr{}
}

func (h *h2ConnWrapper) SetDeadline(time.Time) error {
	return nil
}

func (h *h2ConnWrapper) SetReadDeadline(time.Time) error {
	return nil
}

func (h *h2ConnWrapper) SetWriteDeadline(time.Time) error {
	return nil
}

type h2Addr struct {
}

func (h h2Addr) Network() string {
	return "tcp"
}

func (h h2Addr) String() string {
	return "h2-stream"
}
