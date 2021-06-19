package inbound

import (
	"crypto/tls"
	"github.com/DeepAQ/mut/router"
	"github.com/lucas-clemente/quic-go/http3"
	"net/url"
)

type h3Inbound struct {
	httpProtocol *httpProtocol
	server       *http3.Server
	certFile     string
	keyFile      string
}

func NewH3Inbound(u *url.URL) *h3Inbound {
	h := NewHttpProtocol(u)
	h.httpsMode = true
	h.server.Addr = u.Host
	return &h3Inbound{
		httpProtocol: h,
		server: &http3.Server{
			Server:          h.server,
			EnableDatagrams: false,
		},
		certFile: u.Query().Get("cert"),
		keyFile:  u.Query().Get("key"),
	}
}

func (h *h3Inbound) Name() string {
	return "h3"
}

func (h *h3Inbound) Serve(r router.Router) error {
	if h.server.TLSConfig == nil {
		cert, err := tls.LoadX509KeyPair(h.certFile, h.keyFile)
		if err != nil {
			return err
		}
		h.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	if h.httpProtocol.router == nil {
		h.httpProtocol.router = r
	}
	return h.server.ListenAndServe()
}
