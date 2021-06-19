package inbound

import (
	"crypto/tls"
	"encoding/base64"
	"github.com/DeepAQ/mut/global"
	"github.com/DeepAQ/mut/router"
	"github.com/DeepAQ/mut/transport"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type httpProtocol struct {
	httpsMode bool
	needsAuth bool
	username  string
	password  string
	initOnce  sync.Once
	router    router.Router
	server    *http.Server
	transport *http.Transport
}

func NewHttpProtocol(u *url.URL) *httpProtocol {
	username := u.User.Username()
	password, _ := u.User.Password()
	h := &httpProtocol{
		httpsMode: false,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
	}
	h.server = &http.Server{
		Handler:      h,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	h.transport = &http.Transport{
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxIdleConns:          100,
		IdleConnTimeout:       global.TcpStreamTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err, outName, realAddr := h.router.DialTcp(addr)
			if err != nil {
				return nil, err
			}
			global.Stdout.Println("[http] " + conn.LocalAddr().String() + " <-" + outName + "-> " + realAddr)
			return conn, nil
		},
	}
	return h
}

func (h *httpProtocol) Serve(l net.Listener, r router.Router) error {
	h.initOnce.Do(func() {
		h.router = r
		if tlsTransport, ok := l.(transport.TLSTransport); ok {
			h.httpsMode = true
			h.server.TLSConfig = tlsTransport.TLSConfig()
			http2.ConfigureServer(h.server, &http2.Server{
				MaxReadFrameSize: 16 * 1024,
			})
		}
	})
	return h.server.Serve(l)
}

func (h *httpProtocol) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if h.needsAuth {
		username, password := proxyBasicAuth(req)
		if username != h.username || password != h.password {
			resp.Header().Set("Connection", "close")
			resp.WriteHeader(http.StatusForbidden)
			return
		}
	}

	switch req.Method {
	case http.MethodConnect:
		switch req.ProtoMajor {
		case 1:
			hConn, _, err := resp.(http.Hijacker).Hijack()
			if err != nil {
				resp.Header().Set("Connection", "close")
				resp.WriteHeader(http.StatusInternalServerError)
				return
			}
			if _, err := hConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
				hConn.Close()
				return
			}

			if h.httpsMode {
				h.router.HandleTcpStream("https", hConn, req.RemoteAddr, req.URL.Host)
			} else {
				h.router.HandleTcpStream("http", hConn, req.RemoteAddr, req.URL.Host)
			}

		case 2, 3:
			resp.WriteHeader(http.StatusOK)
			resp.(http.Flusher).Flush()
			h.router.HandleTcpStream("h2", &h2ConnWrapper{
				req:  req,
				resp: resp,
			}, req.RemoteAddr, req.URL.Host)

		default:
			resp.Header().Set("Connection", "close")
			resp.WriteHeader(http.StatusBadRequest)
			return
		}

	default:
		if req.URL.Scheme != "http" {
			if h.httpsMode {
				req.URL.Scheme = "http"
				req.URL.Host = req.Host
			} else {
				resp.WriteHeader(http.StatusForbidden)
				return
			}
		}

		global.Stdout.Println("[http] " + req.RemoteAddr + " -> " + req.URL.String())
		for header := range req.Header {
			if strings.HasPrefix(strings.ToLower(header), "proxy-") {
				req.Header.Del(header)
			}
		}
		result, err := h.transport.RoundTrip(req)
		if err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}
		for k, vs := range result.Header {
			for _, v := range vs {
				resp.Header().Add(k, v)
			}
		}

		resp.WriteHeader(result.StatusCode)
		io.Copy(resp, result.Body)
	}
}

func (h *httpProtocol) serveConn(conn net.Conn, r router.Router) error {
	return h.Serve(&connListener{conn: conn}, r)
}

func proxyBasicAuth(req *http.Request) (username, password string) {
	auth := req.Header.Get("Proxy-Authorization")
	if len(auth) == 0 || !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[6:]))
	if err != nil {
		return
	}
	cs := *(*string)(unsafe.Pointer(&c))
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:]
}

type connListener struct {
	conn     net.Conn
	consumed uint32
}

func (c *connListener) Accept() (net.Conn, error) {
	if atomic.CompareAndSwapUint32(&c.consumed, 0, 1) {
		return c.conn, nil
	} else {
		return nil, net.ErrClosed
	}
}

func (c *connListener) Close() error {
	atomic.StoreUint32(&c.consumed, 1)
	return nil
}

func (c *connListener) Addr() net.Addr {
	return c.conn.LocalAddr()
}

type h2ConnWrapper struct {
	req  *http.Request
	resp http.ResponseWriter
}

func (h *h2ConnWrapper) Read(p []byte) (n int, err error) {
	return h.req.Body.Read(p)
}

func (h *h2ConnWrapper) Write(p []byte) (n int, err error) {
	defer h.resp.(http.Flusher).Flush()
	return h.resp.Write(p)
}

func (h *h2ConnWrapper) Close() error {
	return h.req.Body.Close()
}

func (h *h2ConnWrapper) LocalAddr() net.Addr {
	return h2Addr{}
}

func (h *h2ConnWrapper) RemoteAddr() net.Addr {
	return h2Addr{}
}

func (h *h2ConnWrapper) SetDeadline(_ time.Time) error {
	return nil
}

func (h *h2ConnWrapper) SetReadDeadline(_ time.Time) error {
	return nil
}

func (h *h2ConnWrapper) SetWriteDeadline(_ time.Time) error {
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
