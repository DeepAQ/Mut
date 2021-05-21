package outbound

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/DeepAQ/mut/config"
	"net"
	"net/url"
)

var (
	errCertNotTrusted = errors.New("server certificate is not trusted")
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

	tlsConfig := &tls.Config{
		ServerName: h.serverName,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	if config.TlsCertVerifier != nil {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if !config.TlsCertVerifier(h.serverName, rawCerts) {
				return errCertNotTrusted
			}
			return nil
		}
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return h.h.dialTcpWithConn(tlsConn, targetAddr)
}
