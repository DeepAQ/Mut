package dns

import (
	"bytes"
	"errors"
	"net/http"
	"time"
)

type dohClient struct {
	url    string
	client *http.Client
}

func NewDoHClient(server string, timeout time.Duration) *dohClient {
	return &dohClient{
		url: "https://" + server,
		client: &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        100,
				IdleConnTimeout:     1 * time.Minute,
				TLSHandshakeTimeout: timeout,
			},
			Timeout: timeout,
		},
	}
}

func (d *dohClient) RoundTrip(req []byte) ([]byte, error) {
	hReq, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Accept", "application/dns-message")
	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("User-Agent", "")

	hResp, err := d.client.Do(hReq)
	if err != nil {
		return nil, err
	}
	if hResp.StatusCode != http.StatusOK {
		return nil, errors.New("doh server responded with " + hResp.Status)
	}

	buf := req[:cap(req)]
	n, err := hResp.Body.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
