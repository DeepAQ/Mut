//go:build !linux && !darwin

package inbound

import (
	"errors"
	"net/url"
)

var (
	errTunNotSupported = errors.New("tun inbound is only supported on linux and darwin")
)

func NewTunInbound(_ *url.URL) (Inbound, error) {
	return nil, errTunNotSupported
}
