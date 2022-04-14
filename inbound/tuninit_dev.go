//go:build linux || darwin

package inbound

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"net/url"
	"os"
	"strconv"
)

var (
	errNoFdReceived = errors.New("no FDs received from unix socket")
)

func NewTunInbound(u *url.URL) (*tunInbound, error) {
	sockPath := u.Query().Get("fdpath")
	if len(sockPath) > 0 {
		return newTunInboundWithSocketPath(u, sockPath)
	}

	fdStr := u.Query().Get("fd")
	fd, err := strconv.Atoi(fdStr)
	if err == nil {
		return newTunInboundWithFD(u, fd, fdStr)
	}

	return newTunInboundWithDevice(u)
}

func newTunInboundWithSocketPath(u *url.URL, sockPath string) (*tunInbound, error) {
	_ = os.Remove(sockPath)
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}

	conn, err := listener.Accept()
	_ = listener.Close()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	connFile, err := conn.(*net.UnixConn).File()
	if err != nil {
		return nil, err
	}
	defer connFile.Close()

	connFd := connFile.Fd()
	oob := make([]byte, unix.CmsgSpace(4))
	if _, _, _, _, err := unix.Recvmsg(int(connFd), nil, oob, 0); err != nil {
		return nil, err
	}

	ctl, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	if len(ctl) < 1 {
		return nil, errNoFdReceived
	}

	fds, err := unix.ParseUnixRights(&ctl[0])
	if err != nil {
		return nil, err
	}
	if len(fds) < 1 {
		return nil, errNoFdReceived
	}

	return newTunInboundWithFD(u, fds[0], sockPath)
}
