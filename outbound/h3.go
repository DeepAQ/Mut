package outbound

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/lucas-clemente/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type h3Outbound struct {
	host      string
	needsAuth bool
	username  string
	password  string
	transport *http3.RoundTripper
}

func NewHttp3Outbound(u *url.URL) (*h3Outbound, error) {
	username := u.User.Username()
	password, _ := u.User.Password()
	serverName := u.Query().Get("host")
	if len(serverName) == 0 {
		serverName, _, _ = net.SplitHostPort(u.Host)
	}

	h := &h3Outbound{
		host:      u.Host,
		needsAuth: len(username) > 0 && len(password) > 0,
		username:  username,
		password:  password,
		transport: &http3.RoundTripper{
			DisableCompression: false,
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
			},
		},
	}
	return h, nil
}

func (h *h3Outbound) Name() string {
	return "h3"
}

func (h *h3Outbound) RemoteDNS() bool {
	return true
}

func (h *h3Outbound) DialTcp(targetAddr string) (net.Conn, error) {
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

	timeOut := time.AfterFunc(Http2RequestTimeOut, func() {
		pr.Close()
	})
	resp, err := h.transport.RoundTrip(req)
	timeOut.Stop()
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
