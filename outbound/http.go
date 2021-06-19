package outbound

import (
	"bufio"
	"encoding/base64"
	"errors"
	"github.com/DeepAQ/mut/transport"
	"net"
	"net/http"
	"net/url"
)

type httpOutbound struct {
	transport transport.TcpOutboundTransport
	needsAuth bool
	username  string
	password  string
}

func NewHttpOutbound(u *url.URL, tp transport.OutboundTransport) (*httpOutbound, error) {
	tcpTransport, err := transport.RequireTcpOutboundTransport(u, tp)
	if err != nil {
		return nil, err
	}

	if tlsTransport, ok := tcpTransport.(transport.TLSTransport); ok {
		tlsTransport.TLSConfig().NextProtos = []string{"http/1.1"}
	}

	username := u.User.Username()
	password, _ := u.User.Password()
	return &httpOutbound{
		transport: tcpTransport,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
	}, nil
}

func (h *httpOutbound) Name() string {
	return "http"
}

func (h *httpOutbound) DialTcp(targetAddr string) (net.Conn, error) {
	conn, err := h.transport.OpenConnection()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodConnect, "", nil)
	if err != nil {
		return nil, err
	}
	req.Host = targetAddr
	req.Header.Set("User-Agent", "")
	if h.needsAuth {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(h.username+":"+h.password)))
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReaderSize(conn, 64), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("remote server responded with " + resp.Status)
	}
	return conn, nil
}
