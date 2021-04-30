package outbound

import (
	"bufio"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
)

type httpOutbound struct {
	host      string
	needsAuth bool
	username  string
	password  string
}

func Http(u *url.URL) (*httpOutbound, error) {
	username := u.User.Username()
	password, _ := u.User.Password()
	return &httpOutbound{
		host:      u.Host,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
	}, nil
}

func (h *httpOutbound) Name() string {
	return "http"
}

func (h *httpOutbound) DialTcp(targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", h.host)
	if err != nil {
		return nil, err
	}
	return h.dialTcpWithConn(conn, targetAddr)
}

func (h *httpOutbound) dialTcpWithConn(conn net.Conn, targetAddr string) (net.Conn, error) {
	req, err := http.NewRequest(http.MethodConnect, "", nil)
	if err != nil {
		return nil, err
	}
	req.Host = targetAddr
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
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("remote server responded with " + resp.Status)
	}
	return conn, nil
}
