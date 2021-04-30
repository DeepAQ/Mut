package inbound

import (
	"encoding/base64"
	"github.com/DeepAQ/mut/router"
	"github.com/DeepAQ/mut/util"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unsafe"
)

type httpInbound struct {
	httpsMode bool
	needsAuth bool
	username  string
	password  string
	transport *http.Transport
}

func Http(u *url.URL, rt router.Router) (*httpInbound, error) {
	username := u.User.Username()
	password, _ := u.User.Password()
	return &httpInbound{
		httpsMode: false,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
		transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err, outName, realAddr := rt.DialTcp(addr)
				if err != nil {
					return nil, err
				}
				util.Stdout.Println("[http] " + conn.LocalAddr().String() + " <-" + outName + "-> " + realAddr)
				return conn, nil
			},
			DisableKeepAlives:     false,
			DisableCompression:    false,
			MaxIdleConns:          100,
			IdleConnTimeout:       1 * time.Minute,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func (h *httpInbound) Name() string {
	return "http"
}

func (h *httpInbound) ServeConn(conn net.Conn, handleTcpStream StreamHandler) error {
	err := http.Serve(&connListener{conn: conn}, http.HandlerFunc(
		func(resp http.ResponseWriter, req *http.Request) {
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
						handleTcpStream(&TcpStream{
							Conn:       hConn,
							Protocol:   "https",
							ClientAddr: req.RemoteAddr,
							TargetAddr: req.RequestURI,
						})
					} else {
						handleTcpStream(&TcpStream{
							Conn:       hConn,
							Protocol:   "http",
							ClientAddr: req.RemoteAddr,
							TargetAddr: req.RequestURI,
						})
					}

				case 2:
					resp.WriteHeader(http.StatusOK)
					resp.(http.Flusher).Flush()
					handleTcpStream(&TcpStream{
						Conn: &h2ConnWrapper{
							req:  req,
							resp: resp,
						},
						Protocol:   "h2",
						ClientAddr: req.RemoteAddr,
						TargetAddr: req.RequestURI,
					})

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

				util.Stdout.Println("[http] " + req.RemoteAddr + " -> " + req.URL.String())
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
				buf := util.BufPool.Get(4 * 1024)
				io.CopyBuffer(resp, result.Body, buf)
				util.BufPool.Put(buf)
			}
		}))

	if err != nil && err != net.ErrClosed {
		return err
	}
	return nil
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
