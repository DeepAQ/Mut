package outbound

import (
	"crypto/tls"
	"net"
	"net/url"
)

type httpsOutbound struct {
	h          *httpOutbound
	serverName string
}

func Https(u *url.URL) (*httpsOutbound, error) {
	serverName := u.Query().Get("host")
	if len(serverName) == 0 {
		serverName, _, _ = net.SplitHostPort(u.Host)
	}
	h, err := Http(u)
	if err != nil {
		return nil, err
	}
	return &httpsOutbound{
		h:          h,
		serverName: serverName,
	}, nil
}

func (h *httpsOutbound) Name() string {
	return "https"
}

func (h *httpsOutbound) DialTcp(targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", h.h.host)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: h.serverName,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return h.h.dialTcpWithConn(tlsConn, targetAddr)
}
