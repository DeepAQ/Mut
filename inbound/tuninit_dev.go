// +build linux,!cgo darwin,!ios

package inbound

import (
	"net/url"
)

func NewTunInbound(u *url.URL) (*tunInbound, error) {
	return newTunInboundWithDevice(u)
}
