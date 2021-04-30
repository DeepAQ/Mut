package outbound

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/DeepAQ/mut/util"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

var (
	errResponseNotHttp2 = errors.New("server response is not http/2")
)

type h2Outbound struct {
	host      string
	needsAuth bool
	username  string
	password  string
	aliveTime time.Duration
	tlsConfig *tls.Config

	transport []*http.Transport
	tMutex    []sync.Mutex
	tDeadline []time.Time
}

const (
	Http2DefaultConcurrency = 8
	Http2MaxConcurrency     = 100
	Http2DefaultAliveTime   = 0
	Http2RequestTimeOut     = 5 * time.Second
)

func Http2(u *url.URL) (*h2Outbound, error) {
	username := u.User.Username()
	password, _ := u.User.Password()
	serverName := u.Query().Get("host")
	if len(serverName) == 0 {
		serverName, _, _ = net.SplitHostPort(u.Host)
	}
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
		host:      u.Host,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
		tlsConfig: &tls.Config{
			ServerName: serverName,
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS12,
		},
		aliveTime: time.Duration(aliveTime) * time.Second,
		transport: make([]*http.Transport, concurrency),
		tMutex:    make([]sync.Mutex, concurrency),
		tDeadline: make([]time.Time, concurrency),
	}
	return h, nil
}

func (h *h2Outbound) Name() string {
	return "h2"
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
	if h.needsAuth {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(h.username+":"+h.password)))
	}

	timeOut := time.AfterFunc(Http2RequestTimeOut, func() {
		pr.Close()
	})
	resp, err := h.getRandomTransport().RoundTrip(req)
	timeOut.Stop()
	if err != nil {
		req.Body.Close()
		pw.Close()
		return nil, err
	}
	if resp.ProtoMajor != 2 {
		req.Body.Close()
		pw.Close()
		return nil, errResponseNotHttp2
	}
	if resp.StatusCode != http.StatusOK {
		req.Body.Close()
		pw.Close()
		return nil, errors.New("remote server responded with " + resp.Status)
	}

	return &h2ConnWrapper{
		reqWriter: pw,
		req:       req,
		resp:      resp,
	}, nil
}

func (h *h2Outbound) getRandomTransport() *http.Transport {
	i := rand.Intn(len(h.transport))
	if h.transport[i] == nil || (h.aliveTime > 0 && h.tDeadline[i].Before(time.Now())) {
		h.tMutex[i].Lock()
		defer h.tMutex[i].Unlock()
		if h.transport[i] == nil || (h.aliveTime > 0 && h.tDeadline[i].Before(time.Now())) {
			if h.transport[i] != nil {
				h.transport[i].CloseIdleConnections()
			}
			util.Stdout.Println("[h2-debug] creating new client transport of " + strconv.Itoa(i))
			h.transport[i] = &http.Transport{
				TLSClientConfig:     h.tlsConfig,
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        100,
				IdleConnTimeout:     1 * time.Minute,
				TLSHandshakeTimeout: 10 * time.Second,
			}
			if h.aliveTime > 0 {
				h.tDeadline[i] = time.Now().Add(h.aliveTime)
			}
		}
	}

	return h.transport[i]
}

type h2ConnWrapper struct {
	reqWriter io.WriteCloser
	req       *http.Request
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
	h.req.Body.Close()
	return h.resp.Body.Close()
}

func (h *h2ConnWrapper) LocalAddr() net.Addr {
	return h2Addr{}
}

func (h *h2ConnWrapper) RemoteAddr() net.Addr {
	return h2Addr{}
}

func (h *h2ConnWrapper) SetDeadline(t time.Time) error {
	return nil
}

func (h *h2ConnWrapper) SetReadDeadline(t time.Time) error {
	return nil
}

func (h *h2ConnWrapper) SetWriteDeadline(t time.Time) error {
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
