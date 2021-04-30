package inbound

import (
	"crypto/tls"
	"github.com/DeepAQ/mut/router"
	"net"
	"net/url"
)

type httpsInbound struct {
	*httpInbound
	tlsConfig *tls.Config
}

func Https(u *url.URL, rt router.Router) (*httpsInbound, error) {
	cert, err := tls.LoadX509KeyPair(u.Query().Get("cert"), u.Query().Get("key"))
	if err != nil {
		return nil, err
	}

	h, err := Http(u, rt)
	if err != nil {
		return nil, err
	}
	h.httpsMode = true
	return &httpsInbound{
		httpInbound: h,
		tlsConfig: &tls.Config{
			Certificates:             []tls.Certificate{cert},
			NextProtos:               []string{"h2", "http/1.1"},
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		},
	}, nil
}

func (h *httpsInbound) Name() string {
	return "https"
}

func (h *httpsInbound) ServeConn(conn net.Conn, handleTcpStream StreamHandler) error {
	tlsConn := tls.Server(conn, h.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	return h.httpInbound.ServeConn(tlsConn, handleTcpStream)
}
