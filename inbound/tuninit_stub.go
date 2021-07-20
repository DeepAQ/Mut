// +build !linux
// +build !darwin ios

package inbound

import (
	"errors"
	"net/url"
)

func NewTunInbound(_ *url.URL) (Inbound, error) {
	return nil, errors.New("tun is only supported on linux and darwin")
}
