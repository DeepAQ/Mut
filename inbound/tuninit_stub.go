//go:build !linux && (!darwin || ios)
// +build !linux
// +build !darwin ios

package inbound

import (
	"errors"
	"net/url"
)

var (
	errTunNotSupported = errors.New("tun inbound is only supported on linux and macos")
)

func NewTunInbound(_ *url.URL) (Inbound, error) {
	return nil, errTunNotSupported
}
