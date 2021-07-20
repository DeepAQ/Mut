// +build linux

package inbound

import (
	"errors"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"net/url"
	"strconv"
)

func newTunInboundWithDevice(u *url.URL) (*tunInbound, error) {
	tag := u.Query().Get("fd")
	fd, err := strconv.Atoi(tag)
	if err != nil {
		tag = u.Host
		fd, err = tun.Open(tag)
		if err != nil {
			return nil, errors.New("failed to open tun device " + tag + ": " + err.Error())
		}
	}

	return newTunInboundWithFD(u, fd, tag)
}

func newTunInboundWithFD(u *url.URL, fd int, tag string) (*tunInbound, error) {
	mtu, _ := strconv.Atoi(u.Query().Get("mtu"))
	if mtu <= 0 {
		mtu = defaultMtu
	}

	l2ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: uint32(mtu),
	})
	if err != nil {
		return nil, errors.New("failed to create l2 endpoint: " + err.Error())
	}
	return newTunInboundWithEndpoint(u, tag, l2ep)
}
